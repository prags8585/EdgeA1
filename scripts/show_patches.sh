#!/usr/bin/env bash
# Show the patches stored in Redis.
#   scripts/show_patches.sh            live patches, with their Python code
#   scripts/show_patches.sh all        the 15 newest attempts, any status
#   scripts/show_patches.sh watch      print each status change as it happens
set -euo pipefail
cd "$(dirname "$0")/.."
REDISCLI_AUTH="$(grep '^REDIS_URL=' .env | sed -E 's#^REDIS_URL=redis://:([^@]*)@.*#\1#')"
export REDISCLI_AUTH
R="${REDIS_CLI:-$HOME/opt/redis/bin/redis-cli}"

echo "patches stored: $($R ZCARD chameleon:patches:all)   live now: $($R ZCARD chameleon:patches:active)"
echo

case "${1:-live}" in
  all)
    printf '%-18s %-18s %-9s %s\n' STATUS ATTACK FIELD PATTERN
    for id in $($R ZREVRANGE chameleon:patches:all 0 14); do
      $R --raw HMGET "chameleon:patch:$id" status attack_type field pattern |
        paste -sd$'\t' | awk -F'\t' '{ printf "%-18s %-18s %-9s %.70s\n", $1, $2, $3, $4 }'
    done
    ;;
  watch)
    echo "waiting for patch updates (send an attack from the dashboard; Ctrl+C to stop)..."
    $R SUBSCRIBE chameleon:patches
    ;;
  *)
    ids=$($R ZRANGE chameleon:patches:active 0 -1)
    [ -z "$ids" ] && { echo "no live patches yet: send an attack from the dashboard and wait 1-3 minutes"; exit 0; }
    for id in $ids; do
      echo "================================================================"
      $R --raw HMGET "chameleon:patch:$id" attack_type field learned_from app_files |
        paste -sd$'\t' | awk -F'\t' '{ printf "%s on field \"%s\"\nlearned from: %s\nwritten into: chameleon/apps/%s\n", $1, $2, $3, $4 }'
      echo "tests: $($R LRANGE "chameleon:patch:$id:events" 0 -1 | python3 -c '
import sys, json
print("  ".join(e["stage"] + "=" + e["result"] for e in map(json.loads, sys.stdin)))')"
      echo "----------------------------------------------------------------"
      $R --raw HGET "chameleon:patch:$id" python_code
    done
    ;;
esac
