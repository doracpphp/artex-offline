#!/bin/sh
# offline-firewall.sh — egress firewall of offline mode (docs/offline-toolbox.md
# §6.4). docker-compose.yml enables it by default (ARTEX_OFFLINE_FIREWALL=1).
#
# start.sh runs it as root, before artex starts, while offline mode is on. The
# rules live in the container's own network namespace, so they cover every
# process in it: the server and the agents' shells alike. start.sh then drops
# NET_ADMIN from the bounding set before starting artex, so nothing it starts can
# change the rules; agent processes also run as an unprivileged uid with
# no-new-privileges.
#
# Allowed out: loopback (Docker's DNS included), replies to inbound connections
# (the published UI/proxy ports), RFC1918 / ULA private ranges — the same set
# as offline.AllowedAddr — and ARTEX_OFFLINE_ALLOW_CIDRS (IP/CIDR literals
# only). Cloud metadata endpoints are rejected first, whatever the ranges.
# Everything else is rejected, link-local included. Rejected, not dropped, so a
# blocked tool fails at once instead of hanging until its timeout.
#
# Limits (documented, not hidden): this guarantees no DIRECT route to the
# internet from this container. It does not stop (1) DNS lookups of public
# names, which Docker's resolver forwards from the host, (2) a relay on an
# allowed range that forwards onward (a LAN proxy, a service on the host), or
# (3) other containers, which have their own network namespaces.
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
# Cloud metadata endpoints, rejected before any allow rule (mirrors
# offline.metadataAddrs): fd00:ec2::254 lies inside fc00::/7.
V4_METADATA="169.254.169.254 100.100.100.200"
V6_METADATA="fd00:ec2::254"
EXTRA_V4=""
EXTRA_V6=""
for c in $(printf '%s' "${ARTEX_OFFLINE_ALLOW_CIDRS:-}" | tr ',' ' '); do
	# IP/CIDR literals only. iptables -d would resolve a hostname, which the Go
	# gates (that parse CIDRs) never would — keep both layers on the same rule.
	case "$c" in
		*[!0-9a-fA-F:./]* | "" | -* | */*/*) fail "invalid entry in ARTEX_OFFLINE_ALLOW_CIDRS (IP or CIDR literals only): $c" ;;
		*:*) EXTRA_V6="$EXTRA_V6 $c" ;;
		*[!0-9./]*) fail "invalid IPv4 entry in ARTEX_OFFLINE_ALLOW_CIDRS (IP or CIDR literals only): $c" ;;
		*) EXTRA_V4="$EXTRA_V4 $c" ;;
	esac
done

# apply TOOL ALLOWED REJECT_WITH METADATA: (re)build the chain and hook it first
# in OUTPUT.
apply() {
	t="$1"
	allowed="$2"
	"$t" -w -N "$CHAIN" 2>/dev/null || "$t" -w -F "$CHAIN" || return 1
	"$t" -w -A "$CHAIN" -o lo -j RETURN || return 1
	"$t" -w -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
	for m in $4; do
		"$t" -w -A "$CHAIN" -d "$m" -j REJECT --reject-with "$3" || return 1
	done
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
apply iptables "$V4_LOCAL $EXTRA_V4" icmp-admin-prohibited "$V4_METADATA" ||
	fail "could not apply the IPv4 rules (is NET_ADMIN granted? see cap_add in docker-compose.yml; is every ARTEX_OFFLINE_ALLOW_CIDRS entry a valid IPv4 CIDR?)"

# shellcheck disable=SC2086
if ! apply ip6tables "$V6_LOCAL $EXTRA_V6" icmp6-adm-prohibited "$V6_METADATA" 2>/dev/null; then
	# Without IPv6 rules the container is still closed if it has no global IPv6
	# address (Docker's default): there is no IPv6 route out.
	if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
		fail "could not apply the IPv6 rules while the container has a global IPv6 address"
	fi
	echo "[offline-firewall] IPv6 rules not applied; the container has no global IPv6 address" >&2
fi

status "enforced"
echo "[offline-firewall] egress limited to loopback, private ranges${ARTEX_OFFLINE_ALLOW_CIDRS:+ and $ARTEX_OFFLINE_ALLOW_CIDRS}"
