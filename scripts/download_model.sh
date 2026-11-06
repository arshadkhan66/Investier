#!/usr/bin/env bash
# Download a local model for the AI brain.
#
# Usage:
#   ./scripts/download_model.sh          # default: Llama-3.2-1B (~0.8 GB)
#   ./scripts/download_model.sh 3b       # Qwen2.5-3B   (~2.1 GB, better accuracy)
#   ./scripts/download_model.sh 1.5b     # Qwen2.5-1.5B (~1.0 GB)
#   ./scripts/download_model.sh 0.5b     # Qwen2.5-0.5B (~0.4 GB)
set -e
cd "$(dirname "$0")/.."
mkdir -p models

SIZE="${1:-1b}"

case "$SIZE" in
  1b|llama)
    REPO="bartowski/Llama-3.2-1B-Instruct-GGUF"
    FILE="Llama-3.2-1B-Instruct-Q4_K_M.gguf" ;;
  3b)
    REPO="Qwen/Qwen2.5-3B-Instruct-GGUF"
    SRC="qwen2.5-3b-instruct-q4_k_m.gguf"
    FILE="Qwen2.5-3B-Instruct-Q4_K_M.gguf" ;;
  1.5b)
    REPO="Qwen/Qwen2.5-1.5B-Instruct-GGUF"
    SRC="qwen2.5-1.5b-instruct-q4_k_m.gguf"
    FILE="qwen2.5-1.5b-instruct-q4_k_m.gguf" ;;
  0.5b)
    REPO="Qwen/Qwen2.5-0.5B-Instruct-GGUF"
    SRC="qwen2.5-0.5b-instruct-q4_k_m.gguf"
    FILE="qwen2.5-0.5b-instruct-q4_k_m.gguf" ;;
  *)
    REPO="${MODEL_REPO:?unknown size; set MODEL_REPO and MODEL_FILE}"
    SRC="${MODEL_FILE:?set MODEL_FILE}"
    FILE="$SRC" ;;
esac
SRC="${SRC:-$FILE}"

DEST="models/$FILE"
if [ -f "$DEST" ]; then
  echo "Model already present: $DEST"
  exit 0
fi

echo "Downloading $REPO/$SRC ..."
curl -L --fail --progress-bar -o "$DEST" \
  "https://huggingface.co/$REPO/resolve/main/$SRC"
echo "Saved to $DEST"

