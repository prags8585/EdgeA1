#!/usr/bin/env bash
# Serve the writer and verifier side by side through ZRT (one proxy, :8080).
# Every flag below fixed a real crash or conflict on the Nano (HANDOFF.md 5.4, 6.4):
#   --max-model-len=8192  : default was the checkpoint's 262k context -> KV-cache OOM
#   MAX_JOBS=4            : FlashInfer JIT-compiles CUDA kernels on first run; ~20
#                           parallel nvcc jobs got OOM-killed next to the loaded model
#   --gpu-memory-fraction : auto-sizing gave the writer 79 GB and left the verifier too
#                           little host RAM (CPU and GPU share the same 121 GB)
# First start of the writer takes ~15-20 min (kernel compile, cached afterwards);
# later starts ~6 min.
set -euo pipefail

# `zrt services` can report "Ready" before the proxy actually routes to the model
# (observed: an eval got 404s from a "Ready" writer), so readiness means a real
# completion succeeding through the proxy.
wait_ready() {
  local label=$1
  echo "waiting for $label ..."
  until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 http://127.0.0.1:8080/v1/chat/completions \
      -H 'Content-Type: application/json' \
      -d "{\"model\":\"$label\",\"messages\":[{\"role\":\"user\",\"content\":\"OK\"}],\"max_tokens\":2}")" = "200" ]; do
    if ! pgrep -f "vllm serve.*served-model-name $label" >/dev/null; then
      sleep 15
      pgrep -f "vllm serve.*served-model-name $label" >/dev/null || { echo "$label died; see /opt/hp/zrt/run/vllm-$label.log"; exit 1; }
    fi
    sleep 10
  done
  echo "$label ready"
}

# ZRT's proxy can deregister a fresh service if it starts right after a stop,
# so make sure nothing is left over first.
if zrt services --json 2>/dev/null | grep -q '"label"'; then
  echo "models already registered -- run 'zrt stop --all' first and wait for 'zrt services' to be empty"
  exit 1
fi

MAX_JOBS=4 zrt serve hf:nvidia/Qwen3-Next-80B-A3B-Instruct-NVFP4 --label writer \
  --gpu-memory-fraction 0.45 --extra '--max-model-len=8192'
wait_ready writer

MAX_JOBS=4 zrt serve hf:google/gemma-4-12B-it --label verifier \
  --gpu-memory-fraction 0.25 --extra '--max-model-len=8192'
wait_ready verifier

zrt services
