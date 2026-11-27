#!/bin/sh
# ARTEX supervisor start script (Linux / macOS / Docker ENTRYPOINT)
#
# Usage:
#   ./start.sh                       run in the foreground (Ctrl-C to stop)
#   nohup ./start.sh >artex.log 2>&1 &   run persistently in the background
#   ./start.sh -addr :9000           extra arguments are passed through to artex as-is
#
# It does exactly one thing: run artex and, once the process exits, decide by exit code whether to relaunch it.
#
#   0      user stopped normally  -> exit the loop
#   other  crash               -> rerun after backoff (1→2→4... up to 60 seconds)
set -u

cd "$(dirname "$0")" || exit 1

BIN=./artex
[ -x "$BIN" ] || { echo "[artex] executable $BIN not found" >&2; exit 1; }

MAX_DELAY=60

# Offline egress firewall (docker-compose.offline.yml, docs/offline-toolbox.md §6.4).
# Applied once, as root, before artex starts; the rules stay in the container's
# network namespace across restarts of the child below. A failure stops the start
# (fail closed) unless ARTEX_OFFLINE_FIREWALL_ALLOW_DEGRADED is set, in which case
# the server starts and reports the degraded state (GET /api/health, UI banner).
is_true() {
	case "$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z')" in
		1 | true | on | yes) return 0 ;;
	esac
	return 1
}
is_false() {
	case "$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z')" in
		0 | false | off | no) return 0 ;;
	esac
	return 1
}
FW_STATUS="${ARTEX_EGRESS_FIREWALL_STATUS:-/run/artex/egress-firewall}"
rm -f "$FW_STATUS" 2>/dev/null || true
if is_true "${ARTEX_OFFLINE_FIREWALL:-}"; then
	if is_false "${ARTEX_OFFLINE:-}"; then
		# Online mode must reach arbitrary targets; the firewall would break that.
		echo "[artex] ARTEX_OFFLINE_FIREWALL is set but offline mode is off (ARTEX_OFFLINE=${ARTEX_OFFLINE}); the egress firewall is not applied" >&2
	elif ! sh ./offline-firewall.sh; then
		if is_true "${ARTEX_OFFLINE_FIREWALL_ALLOW_DEGRADED:-}"; then
			echo "[artex] WARNING: egress firewall NOT applied; starting degraded (ARTEX_OFFLINE_FIREWALL_ALLOW_DEGRADED)" >&2
		else
			echo "[artex] egress firewall could not be applied; refusing to start. Fix the cause above, or set ARTEX_OFFLINE_FIREWALL_ALLOW_DEGRADED=1 to start without it." >&2
			exit 1
		fi
	fi
fi

child=0
stopping=0

# Forward stop signals to artex itself.
#
# Under Docker this is required: docker stop sends SIGTERM only to PID 1 (this script),
# never to the child. Without forwarding, artex never sees the signal and cannot shut down gracefully; after 10 seconds it gets
# hard-killed by SIGKILL and any running task is cut off mid-flight.
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
}
trap forward INT TERM

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# A signal interrupts wait and makes it return >128. At that point the child is still shutting down gracefully;
	# wait must be called once more to get its real exit code.
	wait "$child"
	code=$?
	if [ "$code" -gt 128 ]; then
		wait "$child"
		code=$?
	fi
	child=0

	if [ "$stopping" -eq 1 ]; then
		echo "[artex] stopped"
		exit 0
	fi

	case "$code" in
		0)
			echo "[artex] exited normally"
			exit 0
			;;
		*)
			echo "[artex] abnormal exit (code=$code), restarting in ${delay}s" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done
