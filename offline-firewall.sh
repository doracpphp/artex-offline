#!/bin/sh
# offline-firewall.sh — egress firewall of the offline compose overlay
# (docker-compose.offline.yml, docs/offline-toolbox.md §6.4).
#
# start.sh runs it as root, before artex starts, when ARTEX_OFFLINE_FIREWALL is
# on. The rules live in the container's own network namespace, so they cover
# every process in it: the server and the agents' shells alike. Agent processes
# run as an unprivileged uid with no-new-privileges and hold no capabilities,
# so they cannot change the rules.
#
# Allowed out: loopback (Docker's DNS included), replies to inbound connections
# (the published UI/proxy ports), RFC1918 / ULA private ranges — the same set
# as offline.IsLocalIP — and ARTEX_OFFLINE_ALLOW_CIDRS. Everything else is
# rejected, link-local (cloud metadata) included. Rejected, not dropped, so a
# blocked tool fails at once instead of hanging until its timeout.
#
# Note: names are still resolved by Docker's DNS on the host, so the firewall
# stops connections, not DNS lookups of public names.
#
# The outcome is written to $ARTEX_EGRESS_FIREWALL_STATUS (default
# /run/artex/egress-firewall): "enforced", or "failed: <reason>". The server
# reports it in GET /api/health. Exit status 0 = enforced.
set -u

STATUS="${ARTEX_EGRESS_FIREWALL_STATUS:-/run/artex/egress-firewall}"
CHAIN=ARTEX-EGRESS

status() {
	mkdir -p "$(dirname "$STATUS")" && printf '%s\n' "$1" >"$STATUS"
}

fail() {
	echo "[offline-firewall] $1" >&2
	status "failed: $1"
	exit 1
}

command -v iptables >/dev/null 2>&1 || fail "iptables is not installed in the image"

V4_LOCAL="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
V6_LOCAL="::1/128 fc00::/7"
EXTRA_V4=""
EXTRA_V6=""
for c in $(printf '%s' "${ARTEX_OFFLINE_ALLOW_CIDRS:-}" | tr ',' ' '); do
	case "$c" in
		-*) fail "invalid entry in ARTEX_OFFLINE_ALLOW_CIDRS: $c" ;;
		*:*) EXTRA_V6="$EXTRA_V6 $c" ;;
		*) EXTRA_V4="$EXTRA_V4 $c" ;;
	esac
done

# apply TOOL ALLOWED REJECT_WITH: (re)build the chain and hook it first in OUTPUT.
apply() {
	t="$1"
	allowed="$2"
	"$t" -w -N "$CHAIN" 2>/dev/null || "$t" -w -F "$CHAIN" || return 1
	"$t" -w -A "$CHAIN" -o lo -j RETURN || return 1
	"$t" -w -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
	for c in $allowed; do
		"$t" -w -A "$CHAIN" -d "$c" -j RETURN || return 1
	done
	if [ "$t" = ip6tables ]; then
		# Neighbour discovery and router advertisements use link-local ICMPv6.
		"$t" -w -A "$CHAIN" -p ipv6-icmp -j RETURN || return 1
	fi
	"$t" -w -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset || return 1
	"$t" -w -A "$CHAIN" -j REJECT --reject-with "$3" || return 1
	"$t" -w -C OUTPUT -j "$CHAIN" 2>/dev/null || "$t" -w -I OUTPUT 1 -j "$CHAIN" || return 1
}

# shellcheck disable=SC2086 # word splitting of the range lists is intended
apply iptables "$V4_LOCAL $EXTRA_V4" icmp-admin-prohibited ||
	fail "could not apply the IPv4 rules (is NET_ADMIN granted? see docker-compose.offline.yml; is every ARTEX_OFFLINE_ALLOW_CIDRS entry a valid IPv4 CIDR?)"

# shellcheck disable=SC2086
if ! apply ip6tables "$V6_LOCAL $EXTRA_V6" icmp6-adm-prohibited 2>/dev/null; then
	# Without IPv6 rules the container is still closed if it has no global IPv6
	# address (Docker's default): there is no IPv6 route out.
	if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
		fail "could not apply the IPv6 rules while the container has a global IPv6 address"
	fi
	echo "[offline-firewall] IPv6 rules not applied; the container has no global IPv6 address" >&2
fi

status "enforced"
echo "[offline-firewall] egress limited to loopback, private ranges${ARTEX_OFFLINE_ALLOW_CIDRS:+ and $ARTEX_OFFLINE_ALLOW_CIDRS}"
