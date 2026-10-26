#!/usr/bin/env bash
# End-to-end smoke test of the Docker Compose deployment.
#   scripts/smoke-test.sh            # builds, starts, runs both variants of a fixture through the API, tears down
#   KEEP=1 scripts/smoke-test.sh     # leave the stack running
# Requires: docker compose, curl, python3.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=$(command -v python3 || command -v python)
created_env=0
if [ ! -f .env ]; then "$PY" scripts/make_env.py; created_env=1; fi
# shellcheck disable=SC1091
set -a; . ./.env; set +a
BASE="http://127.0.0.1:8787/api/v1"
AUTH=(-H "Authorization: Bearer ${SENTINEL_API_TOKEN}" -H "X-Sentinel-Client: smoke" -H "Content-Type: application/json" -H "Origin: http://127.0.0.1:8787")

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then docker compose down -v --remove-orphans >/dev/null 2>&1 || true; [ "$created_env" = 1 ] && rm -f .env; fi
}
trap cleanup EXIT

docker compose up --build -d
echo "waiting for the API..."
for _ in $(seq 1 60); do
  curl -fsS "$BASE/health" >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS "$BASE/health" >/dev/null

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/test-runs")
[ "$code" = 401 ] || { echo "FAIL: unauthenticated request returned $code, expected 401"; exit 1; }

run_variant() { # <variant> <expected failed count>
  local variant=$1 want=$2 resp rid st failed
  resp=$(curl -fsS -X POST "$BASE/test-runs" "${AUTH[@]}" -d "{\"fixture\":\"multi-tenant-saas\",\"variant\":\"$variant\"}")
  rid=$("$PY" -c 'import json,sys; print(json.load(sys.stdin)["data"]["run_id"])' <<<"$resp")
  for _ in $(seq 1 90); do
    st=$(curl -fsS "$BASE/test-runs/$rid" "${AUTH[@]}" | "$PY" -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d["status"], d.get("coverage",{}).get("failed",""))')
    case "$st" in completed*) break ;; failed*|cancelled*) echo "FAIL: run $variant ended as $st"; exit 1 ;; esac
    sleep 2
  done
  failed=${st#completed }
  [ "$failed" = "$want" ] || { echo "FAIL: $variant expected $want failed cases, got '$failed'"; exit 1; }
  echo "ok: $variant -> $failed failed case(s), as documented"
  curl -fsS "$BASE/reports/$rid?format=sarif" "${AUTH[@]}" -o "/tmp/smoke-$variant.sarif"
}
run_variant vulnerable 8
run_variant secure 0
echo "smoke test passed"
