package intercept

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/doracpphp/artex-offline/offline"
)

// OfflineEgressBlocked: offline mode refused an agent-initiated connection to
// an address that is not local (loopback, RFC1918 / ULA) or inside
// ARTEX_OFFLINE_ALLOW_CIDRS. It applies on every agent path — gate off, no
// scope, the SOCKS5 / transparent relays, and a gated scope, where the scope
// can only narrow this rule, never widen it (docs/offline-knowledge-search.md
// §4.5). The same rule is what the egress firewall enforces.
const OfflineEgressBlocked = "OFFLINE_EGRESS_BLOCKED"

type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// offlineDial dials addr through base unchanged while offline mode is off. When
// it is on, it resolves the host, keeps the addresses offline mode permits and
// dials those, never the name, so that a second answer cannot point the
// connection elsewhere. With none left the connection is refused with
// OfflineEgressBlocked.
func offlineDial(ctx context.Context, network, addr string, base dialFunc) (net.Conn, error) {
	if !offline.Enabled() {
		return base(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, &dialError{code: OfflineEgressBlocked, target: addr, reason: "offline mode: the address of the connection could not be read (" + err.Error() + ")"}
	}
	addrs, err := offline.AllowedAddrs(ctx, host)
	if err != nil {
		return nil, offlineRefusal(addr, err)
	}
	ips := make([]string, len(addrs))
	for i, a := range addrs {
		ips[i] = a.String()
	}
	return dialEach(ctx, base, network, ips, port)
}

// offlineFilter keeps the addresses of a checked target that offline mode
// permits. It returns ips unchanged while offline mode is off, and a refusal
// when none is permitted.
func offlineFilter(target string, ips []string) ([]string, error) {
	if !offline.Enabled() {
		return ips, nil
	}
	var kept, refused []string
	for _, raw := range ips {
		if a, err := netip.ParseAddr(raw); err == nil && offline.AllowedAddr(a) {
			kept = append(kept, raw)
		} else {
			refused = append(refused, raw)
		}
	}
	if len(kept) == 0 {
		reason := "no address"
		if len(refused) > 0 {
			reason = strings.Join(refused, ", ")
		}
		return nil, offlineRefusal(target, &offline.EgressError{Target: target, Reason: reason + " is not a local address"})
	}
	return kept, nil
}

// offlineUDP checks the destination a UDP resolver chose. It passes the result
// through while offline mode is off or when resolution already failed.
func offlineUDP(target string, a *net.UDPAddr, err error) (*net.UDPAddr, error) {
	if err != nil || !offline.Enabled() {
		return a, err
	}
	if !offline.Allowed(a.IP) {
		return nil, offlineRefusal(target, &offline.EgressError{Target: target, Reason: a.IP.String() + " is not a local address"})
	}
	return a, nil
}

// offlineRefusal turns an offline refusal into the dialError the model reads,
// keeping the hint that tells it to use the installed tools instead.
func offlineRefusal(target string, err error) error {
	reason := err.Error()
	if eg, ok := errors.AsType[*offline.EgressError](err); ok {
		reason = eg.Reason
	}
	return &dialError{code: OfflineEgressBlocked, target: target,
		reason: fmt.Sprintf("offline mode: %s. %s", reason, strings.TrimSuffix(offline.Hint, "."))}
}

// dialEach connects to ips in order with port; the first that accepts wins. An
// address of the wrong family for tcp4 or tcp6 is skipped. When every attempt
// fails, the last error is returned.
func dialEach(ctx context.Context, dial dialFunc, network string, ips []string, port string) (net.Conn, error) {
	var last error = &net.AddrError{Err: "no suitable address found", Addr: strings.Join(ips, ", ")}
	for _, ip := range ips {
		a, err := netip.ParseAddr(ip)
		if err != nil || network == "tcp4" && !a.Is4() || network == "tcp6" && !a.Is6() {
			continue
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}
