#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 BASELINE_PROJECT CANDIDATE_PROJECT [source|compiled]" >&2
  exit 2
fi

BASELINE_PROJECT="$(cd "$1" && pwd)"
CANDIDATE_PROJECT="$(cd "$2" && pwd)"
BUILD_MODE="${3:-compiled}"
MODE="${MODE:-express-pooled}"
WORKERS="${WORKERS:-8}"
RUNS="${RUNS:-7}"
WARMUPS="${WARMUPS:-2}"
RUN_WARMUP_REQUESTS="${RUN_WARMUP_REQUESTS:-20000}"
NEW_CONN_COOLDOWN="${NEW_CONN_COOLDOWN:-30}"
PORT="${PORT:-18990}"
NEXT_PORT="$PORT"
OUT_DIR="${OUT_DIR:-/tmp/igropyr-bench-$(date +%Y%m%d-%H%M%S)}"
SCENARIOS="${SCENARIOS:-primary new-50 new-500 keepalive-500 new-1000}"
MAX_CV="${MAX_CV:-5}"
MIN_RPS_GAIN="${MIN_RPS_GAIN:-8}"
MIN_ALLOC_DROP="${MIN_ALLOC_DROP:-20}"
MAX_REGRESSION="${MAX_REGRESSION:-5}"
SKIP_GATE="${SKIP_GATE:-0}"

if [[ "$(basename "$BASELINE_PROJECT")" != "igropyr" ||
      "$(basename "$CANDIDATE_PROJECT")" != "igropyr" ]]; then
  echo "both project directories must be named igropyr (R6RS library path)" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
CSV="$OUT_DIR/results.csv"
echo "variant,scenario,requested,completed,rps,mean_ms,p95_ms,rss_kb,bytes,collections,cpu_ms,real_ms,gc_cpu_ms,gc_real_ms,gc_bytes" > "$CSV"

SERVER_PID=""

stop_server() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
}
trap stop_server EXIT INT TERM

build_project() {
  local project="$1"
  local parent
  parent="$(dirname "$project")"
  if [[ "$BUILD_MODE" == "compiled" ]]; then
    (
      cd "$parent"
      chez --libdirs "$parent" --script "$project/build.ss"
    ) > "$OUT_DIR/build-$(basename "$parent").log" 2>&1
  elif [[ "$BUILD_MODE" != "source" ]]; then
    echo "unknown build mode: $BUILD_MODE" >&2
    exit 2
  fi
}

start_server() {
  local project="$1"
  local label="$2"
  local parent exts
  parent="$(dirname "$project")"
  if [[ "$BUILD_MODE" == "compiled" ]]; then
    exts=".so:.sc"
  else
    exts=".sc"
  fi
  (
    cd "$parent"
    exec env CHEZSCHEMELIBDIRS="$parent" CHEZSCHEMELIBEXTS="$exts" \
      chez --script "$project/bench/server.sc" "$MODE" "$PORT" "$WORKERS"
  ) > "$OUT_DIR/server-$label.log" 2>&1 &
  SERVER_PID=$!

  local i
  for i in $(seq 1 100); do
    if curl -fsS --max-time 1 "http://127.0.0.1:$PORT/__bench/result" >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "server $label exited before becoming ready" >&2
      cat "$OUT_DIR/server-$label.log" >&2
      exit 1
    fi
    sleep 0.05
  done
  echo "server $label did not become ready" >&2
  exit 1
}

scenario_args() {
  case "$1" in
    primary) echo "-k -n 300000 -c 500" ;;
    new-50) echo "-n 10000 -c 50" ;;
    new-500) echo "-n 50000 -c 500" ;;
    keepalive-500) echo "-k -n 100000 -c 500" ;;
    new-1000) echo "-n 100000 -c 1000" ;;
    *) echo "unknown scenario: $1" >&2; exit 2 ;;
  esac
}

run_one() {
  local variant="$1"
  local project="$2"
  local scenario="$3"
  local run="$4"
  local args requested completed output metrics failed rps mean p95 rss bytes collections cpu real gc_cpu gc_real gc_bytes

  args="$(scenario_args "$scenario")"
  requested="$(awk '{for(i=1;i<=NF;i++) if($i=="-n") print $(i+1)}' <<< "$args")"
  if (( NEXT_PORT > 65535 )); then
    echo "benchmark port range exhausted" >&2
    exit 1
  fi
  PORT="$NEXT_PORT"
  NEXT_PORT=$((NEXT_PORT + 1))
  start_server "$project" "$variant-$scenario-$run"
  # Each measured run uses a fresh Chez process. Warm that exact process so
  # script/JIT, heap and libuv startup variance is outside the reset metrics.
  if (( RUN_WARMUP_REQUESTS > 0 )); then
    ab -q -k -n "$RUN_WARMUP_REQUESTS" -c 200 \
      "http://127.0.0.1:$PORT/" >/dev/null
  fi
  curl -fsS --max-time 2 "http://127.0.0.1:$PORT/__bench/reset" >/dev/null
  output="$OUT_DIR/ab-$variant-$scenario-$run.txt"
  # shellcheck disable=SC2086
  ab -q $args "http://127.0.0.1:$PORT/" > "$output"
  metrics="$(curl -fsS --max-time 2 "http://127.0.0.1:$PORT/__bench/result")"
  rss="$(ps -o rss= -p "$SERVER_PID" | tr -d ' ')"

  failed="$(awk -F: '/Failed requests/{gsub(/[[:space:]]/,"",$2); print $2}' "$output")"
  if [[ "$failed" != "0" ]]; then
    echo "$variant $scenario run $run had $failed failed requests" >&2
    exit 1
  fi
  rps="$(awk -F: '/Requests per second/{gsub(/\[.*/,"",$2); gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' "$output")"
  mean="$(awk -F: '/Time per request/{seen++; if(seen==1){gsub(/\[.*/,"",$2); gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}}' "$output")"
  p95="$(awk '/^[[:space:]]*95%/{print $2}' "$output")"
  completed="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="requests") print a[2]}}' <<< "$metrics")"
  bytes="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="bytes") print a[2]}}' <<< "$metrics")"
  collections="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="collections") print a[2]}}' <<< "$metrics")"
  cpu="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="cpu_ms") print a[2]}}' <<< "$metrics")"
  real="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="real_ms") print a[2]}}' <<< "$metrics")"
  gc_cpu="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="gc_cpu_ms") print a[2]}}' <<< "$metrics")"
  gc_real="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="gc_real_ms") print a[2]}}' <<< "$metrics")"
  gc_bytes="$(awk '{for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="gc_bytes") print a[2]}}' <<< "$metrics")"

  if [[ "$completed" != "$requested" ]]; then
    echo "$variant $scenario run $run completed $completed of $requested requests" >&2
    exit 1
  fi

  echo "$variant,$scenario,$requested,$completed,$rps,$mean,$p95,$rss,$bytes,$collections,$cpu,$real,$gc_cpu,$gc_real,$gc_bytes" >> "$CSV"
  stop_server
}

warmup() {
  local variant="$1" project="$2" i
  for i in $(seq 1 "$WARMUPS"); do
    start_server "$project" "$variant-warmup-$i"
    ab -q -k -n 50000 -c 200 "http://127.0.0.1:$PORT/" >/dev/null
    stop_server
  done
}

echo "results: $OUT_DIR"
build_project "$BASELINE_PROJECT"
build_project "$CANDIDATE_PROJECT"
warmup baseline "$BASELINE_PROJECT"
warmup candidate "$CANDIDATE_PROJECT"

for scenario in $SCENARIOS; do
  for run in $(seq 1 "$RUNS"); do
    if (( run % 2 == 1 )); then
      run_one baseline "$BASELINE_PROJECT" "$scenario" "$run"
      run_one candidate "$CANDIDATE_PROJECT" "$scenario" "$run"
    else
      run_one candidate "$CANDIDATE_PROJECT" "$scenario" "$run"
      run_one baseline "$BASELINE_PROJECT" "$scenario" "$run"
    fi
    if [[ "$scenario" != "primary" && "$scenario" != "keepalive-500" &&
          "$run" -lt "$RUNS" ]] && (( NEW_CONN_COOLDOWN > 0 )); then
      sleep "$NEW_CONN_COOLDOWN"
    fi
  done
done

awk -f "$CANDIDATE_PROJECT/bench/summarize.awk" "$CSV" | tee "$OUT_DIR/summary.csv"
if [[ "$SKIP_GATE" != "1" ]]; then
  awk -v max_cv="$MAX_CV" \
      -v min_rps_gain="$MIN_RPS_GAIN" \
      -v min_alloc_drop="$MIN_ALLOC_DROP" \
      -v max_regression="$MAX_REGRESSION" \
      -f "$CANDIDATE_PROJECT/bench/check-gates.awk" \
      "$OUT_DIR/summary.csv"
fi
