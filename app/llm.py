"""Local LLM brain.

Wraps a small (~1B parameter) GGUF model running fully offline on CPU via
llama.cpp. The model is used to:

  * turn a free-form instruction into a structured test plan,
  * reason about what is missing / broken,
  * write the final diagnostic narrative.

If the model or the inference library is unavailable, every method degrades
to a deterministic rule-based implementation, so the platform always works.
"""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

MODEL_DIR = Path(os.environ.get("MODEL_DIR", Path(__file__).resolve().parent.parent / "models"))
DEFAULT_MODEL = os.environ.get("MODEL_FILE", "Llama-3.2-1B-Instruct-Q4_K_M.gguf")

# Known models, matched by filename substring. The first match that exists on
# disk wins when a caller asks for an alias.
MODEL_REGISTRY = {
    "1b": {"file": "Llama-3.2-1B-Instruct-Q4_K_M.gguf", "label": "Llama 3.2 1B",
           "params": "1B", "n_ctx": 4096},
    "3b": {"file": "Qwen2.5-3B-Instruct-Q4_K_M.gguf", "label": "Qwen 2.5 3B",
           "params": "3B", "n_ctx": 4096},
    "0.5b": {"file": "qwen2.5-0.5b-instruct-q4_k_m.gguf", "label": "Qwen 2.5 0.5B",
             "params": "0.5B", "n_ctx": 4096},
    "1.5b": {"file": "qwen2.5-1.5b-instruct-q4_k_m.gguf", "label": "Qwen 2.5 1.5B",
             "params": "1.5B", "n_ctx": 4096},
}


def available_models() -> list[dict]:
    """List models present on disk, plus which is the active default."""
    out = []
    seen = set()
    for alias, spec in MODEL_REGISTRY.items():
        path = MODEL_DIR / spec["file"]
        if path.exists():
            out.append({"alias": alias, "file": spec["file"], "label": spec["label"],
                        "params": spec["params"], "size_mb": round(path.stat().st_size / 1e6)})
            seen.add(spec["file"])
    for p in sorted(MODEL_DIR.glob("*.gguf")):
        if p.name not in seen:
            out.append({"alias": p.stem, "file": p.name, "label": p.stem,
                        "params": "?", "size_mb": round(p.stat().st_size / 1e6)})
    return out


def _resolve_exact(which: str) -> Path | None:
    """Resolve an explicit model name strictly (alias, filename or substring)."""
    if not which:
        return None
    if which in MODEL_REGISTRY:
        return MODEL_DIR / MODEL_REGISTRY[which]["file"]
    direct = MODEL_DIR / which
    if direct.exists():
        return direct
    for p in MODEL_DIR.glob("*.gguf"):
        if which.lower() in p.name.lower():
            return p
    return None


def _resolve_model(which: str | None) -> Path | None:
    return _resolve_exact(which) or _find_model()


def _find_model() -> Path | None:
    if not MODEL_DIR.exists():
        return None
    preferred = MODEL_DIR / DEFAULT_MODEL
    if preferred.exists():
        return preferred
    for p in sorted(MODEL_DIR.glob("*.gguf")):
        return p
    return None


class LocalLLM:
    """Lazily-loaded, thread-safe wrapper around a local GGUF model."""

    def __init__(self) -> None:
        self._llm = None
        self._lock = threading.Lock()
        self._loaded = False
        self._error: str | None = None
        self._active: str | None = None
        self.model_path = _find_model()
        self.model_name = self.model_path.name if self.model_path else None

    # -- lifecycle ---------------------------------------------------------
    @property
    def available(self) -> bool:
        return self._llm is not None

    def status(self) -> dict[str, Any]:
        return {
            "engine": "llama.cpp (CPU)",
            "model": self.model_name,
            "model_path": str(self.model_path) if self.model_path else None,
            "active": self._active,
            "loaded": self._loaded,
            "available": self.available,
            "error": self._error,
            "installed": available_models(),
        }

    def select(self, which: str) -> bool:
        """Switch to a different installed model, unloading the current one.

        An explicit but unknown name fails rather than silently loading some
        other model, so the UI can report the mistake.
        """
        path = _resolve_exact(which)
        if not path or not path.exists():
            self._error = f"model '{which}' not found"
            return False
        with self._lock:
            if self.model_path == path and self._llm is not None:
                return True
            self._llm = None
            self._loaded = False
            self._error = None
            self.model_path = path
            self.model_name = path.name
            self._active = which
        return self.load()

    def load(self, n_ctx: int = 4096, n_threads: int | None = None) -> bool:
        if self._loaded:
            return self.available
        self._loaded = True
        if not self.model_path:
            self._error = "no GGUF model found in models/"
            return False
        try:
            from llama_cpp import Llama  # type: ignore
        except Exception as exc:  # noqa: BLE001
            self._error = f"llama_cpp not importable: {exc}"
            return False
        try:
            self._llm = Llama(
                model_path=str(self.model_path),
                n_ctx=n_ctx,
                n_threads=n_threads or max(1, (os.cpu_count() or 2) - 1),
                n_batch=256,
                verbose=False,
            )
            self._error = None
            return True
        except Exception as exc:  # noqa: BLE001
            self._error = f"model load failed: {exc}"
            return False

    # -- inference ---------------------------------------------------------
    def chat(self, system: str, user: str, max_tokens: int = 512,
             temperature: float = 0.2, stop: list[str] | None = None) -> str | None:
        """Single-turn chat. Returns None if the model is unavailable."""
        if not self.load():
            return None
        try:
            with self._lock:
                out = self._llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature,
                    top_p=0.9,
                    stop=stop,
                )
            return out["choices"][0]["message"]["content"].strip()
        except Exception as exc:  # noqa: BLE001
            self._error = f"inference failed: {exc}"
            return None

    def json_chat(self, system: str, user: str, max_tokens: int = 400,
                  schema: dict | None = None) -> dict | None:
        """Chat constrained to emit a JSON object.

        Uses llama.cpp grammar-constrained decoding when available (much more
        reliable on small models), falling back to tolerant parsing.
        """
        if not self.load():
            return None
        kwargs: dict = {"max_tokens": max_tokens, "temperature": 0.0}
        if schema is not None:
            kwargs["response_format"] = {
                "type": "json_object",
                "schema": schema,
            }
        try:
            with self._lock:
                out = self._llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    top_p=0.9,
                    **kwargs,
                )
            raw = out["choices"][0]["message"]["content"].strip()
        except Exception:  # noqa: BLE001
            # Some builds lack schema support; retry without it.
            raw = self.chat(system, user, max_tokens=max_tokens, temperature=0.1)
        if not raw:
            return None
        data = _extract_json(raw)
        return data if isinstance(data, dict) else None


def _repair_json(text: str, drop_partial: bool = False) -> str | None:
    """Close a truncated JSON object so it can be parsed.

    Small models sometimes loop or stop mid-array; salvage the complete part.
    Set drop_partial to also discard an incomplete trailing token.
    """
    start = text.find("{")
    if start == -1:
        return None
    s = text[start:]
    if drop_partial:
        s = re.sub(r",\s*[^,\[\]{}]*$", "", s)
    # Balance brackets/braces, respecting simple string state.
    out, stack, in_str, esc = [], [], False, False
    for ch in s:
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
        elif ch in "[{":
            stack.append(ch)
            out.append(ch)
        elif ch in "]}":
            if stack:
                stack.pop()
            out.append(ch)
        else:
            out.append(ch)
    if in_str:
        out.append('"')
    while stack:
        out.append("}" if stack.pop() == "{" else "]")
    return "".join(out)


def _extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    candidates = [text, _slice_object(text),
                  _repair_json(text), _repair_json(text, drop_partial=True)]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except Exception:  # noqa: BLE001
            continue
    return None


def _slice_object(text: str) -> str | None:
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return text[start:end + 1]
    return None


# Process-wide singleton.
LLM = LocalLLM()
