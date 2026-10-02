#!/usr/bin/env bash
#
# Bring the whole test harness up, run every suite, tear it down again.
#
# The suites need five listeners on five ports, and getting one of them wrong
# produces a failure three layers from its cause. This script owns all of them:
# it refuses to start when a port is already busy (saying what is on it), waits
# for each listener to actually bind rather than sleeping and hoping, and kills
# everything it started on the way out — including on Ctrl-C or a failure.
#
#   test/run_all.sh            run everything
#   test/run_all.sh --clean    kill leftover harness processes first
#   test/run_all.sh --keep     leave the listeners running afterwards
#
set -uo pipefail

cd "$(dirname "$0")/.."

PLC_PORT=5020
ROGUE_PORT=5030
BENCH_PORT=5502
RESP_PORT=5510
POLICY_PORTS=(5520 5521)   # these come from test/policy-test.json

# Where to build and run the binary. Override when the working tree is on a
# filesystem mounted noexec, which some containers and network shares are.
CG_BIN=${CG_BIN:-./conduitgate}

CLEAN=0
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --clean) CLEAN=1 ;;
    --keep)  KEEP=1 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

LOGDIR=$(mktemp -d)
PIDS=()
FAILED=()

cleanup() {
  if [ "$KEEP" = 1 ] && [ "${#PIDS[@]}" -gt 0 ]; then
    echo
    echo "listeners left running (--keep); logs in $LOGDIR"
    return
  fi
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

wait_port() { # port, seconds
  local waited=0
  while ! port_busy "$1"; do
    sleep 0.2
    waited=$((waited + 1))
    if [ "$waited" -gt $(( ${2:-15} * 5 )) ]; then
      return 1
    fi
  done
  return 0
}

start() { # name, logfile, command...
  local name=$1 log=$2; shift 2
  "$@" >"$LOGDIR/$log" 2>&1 &
  PIDS+=($!)
  note "started $name (log: $LOGDIR/$log)"
}

run_suite() { # label, command...
  local label=$1; shift
  say "$label"
  if "$@"; then
    return 0
  fi
  FAILED+=("$label")
  return 1
}

# ---------------------------------------------------------------------------
say "Pre-flight"

if [ "$CLEAN" = 1 ]; then
  pkill -f 'test/plcsim.py' 2>/dev/null
  pkill -f 'test/rogue_device.py' 2>/dev/null
  pkill -x conduitgate 2>/dev/null
  sleep 1
  note "killed leftover harness processes"
fi

busy=0
for port in "$PLC_PORT" "$ROGUE_PORT" "$BENCH_PORT" "$RESP_PORT" "${POLICY_PORTS[@]}"; do
  if port_busy "$port"; then
    busy=1
    # Name what is there rather than just reporting the collision.
    note "port $port is already in use:"
    python3 test/identity.py "$port" 2>/dev/null | sed 's/^/    /'
  fi
done
if [ "$busy" = 1 ]; then
  echo
  echo "Refusing to start on top of something else. Re-run with --clean to kill"
  echo "leftover harness processes, or free the ports yourself."
  exit 1
fi
note "all six ports free"

# ---------------------------------------------------------------------------
say "Build"
if ! go build -o "$CG_BIN" ./cmd/conduitgate; then
  echo "build failed"
  exit 1
fi
note "built $CG_BIN"

# ---------------------------------------------------------------------------
say "Start listeners"

start "plcsim"          plcsim.log  python3 test/plcsim.py "$PLC_PORT"
wait_port "$PLC_PORT" || { echo "plcsim did not bind"; cat "$LOGDIR/plcsim.log"; exit 1; }

start "rogue device"    rogue.log   python3 test/rogue_device.py "$ROGUE_PORT"
wait_port "$ROGUE_PORT" || { echo "rogue did not bind"; cat "$LOGDIR/rogue.log"; exit 1; }

start "bench proxy"     bench.log   "$CG_BIN" -listen "127.0.0.1:$BENCH_PORT" -target "127.0.0.1:$PLC_PORT"
wait_port "$BENCH_PORT" || { echo "bench proxy did not bind"; cat "$LOGDIR/bench.log"; exit 1; }

start "response proxy"  resp.log    "$CG_BIN" -listen "127.0.0.1:$RESP_PORT" -target "127.0.0.1:$ROGUE_PORT"
wait_port "$RESP_PORT" || { echo "response proxy did not bind"; cat "$LOGDIR/resp.log"; exit 1; }

start "policy proxy"    policy.log  "$CG_BIN" -policy test/policy-test.json
for port in "${POLICY_PORTS[@]}"; do
  wait_port "$port" || { echo "policy proxy did not bind $port"; cat "$LOGDIR/policy.log"; exit 1; }
done

# ---------------------------------------------------------------------------
run_suite "Unit tests"            go test ./... -cover
run_suite "Classification and evasion" python3 test/enforcement_test.py
run_suite "Response path"         env CG_PROXY_PORT="$RESP_PORT" python3 test/response_test.py
run_suite "Policy scoping"        python3 test/policy_test.py

# ---------------------------------------------------------------------------
say "Summary"
if [ "${#FAILED[@]}" -eq 0 ]; then
  note "all suites passed"
  exit 0
fi

note "failed: ${FAILED[*]}"
note "proxy logs are in $LOGDIR — the denial reason codes say why"
exit 1
