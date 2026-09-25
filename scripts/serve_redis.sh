#!/usr/bin/env bash
# Start the patch store: Redis on 127.0.0.1:6379, password from .env, data persisted
# under data/redis (append-only file). Built from source without sudo:
#   curl -fsSL https://download.redis.io/redis-stable.tar.gz | tar xz && cd redis-stable
#   make -j8 BUILD_WITH_MODULES=no && make BUILD_WITH_MODULES=no PREFIX=$HOME/opt/redis install
set -euo pipefail
cd "$(dirname "$0")/.."
REDIS_BIN="${REDIS_BIN:-$HOME/opt/redis/bin/redis-server}"
if ! grep -q '^REDIS_URL=' .env 2>/dev/null; then
  echo "REDIS_URL=redis://:$(openssl rand -hex 24)@127.0.0.1:6379/0" >> .env
fi
PASS="$(grep '^REDIS_URL=' .env | sed -E 's#^REDIS_URL=redis://:([^@]*)@.*#\1#')"
mkdir -p data/redis
exec "$REDIS_BIN" --bind 127.0.0.1 --port 6379 --protected-mode yes --requirepass "$PASS" \
  --dir "$PWD/data/redis" --appendonly yes --appendfsync everysec --save 60 1
