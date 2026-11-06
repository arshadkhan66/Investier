#!/usr/bin/env bash
# Download the local model used by the AI brain.
# Default: Llama-3.2-1B-Instruct, Q4_K_M quantisation (~0.8 GB, CPU friendly).
set -e
cd "$(dirname "$0")/.."
mkdir -p models
MODEL_REPO="${MODEL_REPO:-bartowski/Llama-3.2-1B-Instruct-GGUF}"
MODEL_FILE="${MODEL_FILE:-Llama-3.2-1B-Instruct-Q4_K_M.gguf}"
DEST="models/$MODEL_FILE"

if [ -f "$DEST" ]; then
  echo "Model already present: $DEST"
  exit 0
fi

echo "Downloading $MODEL_REPO/$MODEL_FILE ..."
curl -L --fail -o "$DEST" \
  "https://huggingface.co/$MODEL_REPO/resolve/main/$MODEL_FILE"
echo "Saved to $DEST"
