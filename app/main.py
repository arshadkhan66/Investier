"""Investier FastAPI server."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .agent import AGENT
from .llm import LLM
from .runner import run_test

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="Investier",
    version=__version__,
    description="Universal automated testing platform with a local ~1B parameter "
                "LLM brain.",
)


class TestRequest(BaseModel):
    target: str = Field(..., description="URL, host, or API endpoint to test")
    instruction: str = Field("", description="Natural-language testing instruction")
    options: dict = Field(default_factory=dict)
    use_llm: bool = Field(True, description="Use the local model for planning/narrative")


class ModelSelect(BaseModel):
    name: str = Field(..., description="Model alias (e.g. '1b', '3b') or filename")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": __version__, "model": LLM.status()}


@app.get("/api/model")
async def model():
    return LLM.status()


@app.get("/api/models")
async def models():
    from .llm import available_models
    return {"installed": available_models(), "active": LLM.model_name}


@app.post("/api/model/load")
async def model_load():
    ok = LLM.load()
    return {"loaded": ok, "status": LLM.status()}


@app.post("/api/model/select")
async def model_select(req: ModelSelect):
    ok = LLM.select(req.name)
    if not ok:
        raise HTTPException(status_code=404,
                            detail=f"Model '{req.name}' could not be loaded.")
    return {"loaded": ok, "status": LLM.status()}


@app.post("/api/plan")
async def plan(req: TestRequest):
    from .runner import normalize_target
    target = normalize_target(req.target)
    if not target:
        raise HTTPException(status_code=400, detail="A target is required.")
    return {"target": target, "plan": AGENT.plan(req.instruction, target)}


@app.post("/api/test")
async def test(req: TestRequest):
    if not req.target.strip():
        raise HTTPException(status_code=400, detail="A target URL or host is required.")
    try:
        report = await run_test(req.target, req.instruction, req.options, req.use_llm)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Test run failed: {exc}") from exc
    return JSONResponse(report)


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
