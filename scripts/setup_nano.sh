#!/usr/bin/env bash
# First-time setup on a fresh HP ZGX Nano. Idempotent -- safe to re-run.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== sanity checks =="
uname -m            # expect aarch64
nvidia-smi -L
zrt status

echo "== python venv =="
python3 -m venv .venv
source .venv/bin/activate
make setup

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env -- fill in HF_TOKEN / JEV_API_KEY / ANTHROPIC_API_KEY as needed."
fi

echo "== check-model datasets + training =="
make data
make train-check
make test

echo "== pulling the two Nano LLMs (large: ~51GB + ~24GB) =="
zrt pull hf:nvidia/Qwen3-Next-80B-A3B-Instruct-NVFP4
zrt pull hf:google/gemma-4-12B-it

cat <<'EOF'

Setup complete. Next steps (see README.md "ZGX Nano setup" for the exact
commands and known gotchas):

  1. Serve both LLMs (first run ~20 min: CUDA kernels compile once):
       scripts/serve_models.sh

  2. In separate tmux sessions:
       make serve-check       # :8010
       make serve-demo        # :8200
       make serve-dashboard   # :8100 (dashboard + API)

  3. Open the dashboard: tunnel from your laptop with
       ssh -L 8100:127.0.0.1:8100 <user>@<tailscale-ip>
     then visit http://127.0.0.1:8100
EOF
