package offline

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// AllowCIDRsEnv names extra address ranges that offline mode treats as local,
// comma- or space-separated (an IP without a prefix length is one host). It is
// for closed networks that use public address ranges internally: without it
// such a lab target, LLM host or mail relay would be refused like the internet.
const AllowCIDRsEnv = "ARTEX_OFFLINE_ALLOW_CIDRS"

// DenyInstallsEnv controls the offline refusal of package installs in agent
// shells. It is on whenever offline mode is on; only an explicit falsy value
// turns it off, e.g. when a local package mirror serves the installs.
const DenyInstallsEnv = "ARTEX_DENY_INSTALLS"

// Hint is appended to every offline refusal an agent sees, so that the model
// stops looking for another route out and uses what is installed instead.
const Hint = "There is no external network in offline mode: do not try to download or install tools or data by another route. Run list_tools to see the installed tools."

// AllowCIDRs parses AllowCIDRsEnv. It returns the valid prefixes and, apart,
// every entry that is not a valid CIDR or IP, so that the server can report
// them at startup instead of silently ignoring a typo.
func AllowCIDRs() (prefixes []netip.Prefix, invalid []string) {
	raw := os.Getenv(AllowCIDRsEnv)
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(f); err == nil {
			a = a.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		invalid = append(invalid, f)
	}
	return prefixes, invalid
}

// metadataAddrs are cloud instance-metadata endpoints. Some sit inside ranges
// offline mode otherwise treats as local (fd00:ec2::254 is ULA, i.e.
// IsPrivate) or that an operator might allow-list (100.100.100.200 lies in
// CGNAT space), so they are refused before any other rule. This mirrors
// intercept.metadataAddrs, which the target gate refuses for the same reason.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS / GCP / Azure / OCI IMDS (IPv4)
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
}

// IsMetadataAddr reports whether a is a cloud instance-metadata endpoint.
func IsMetadataAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, m := range metadataAddrs {
		if a == m {
			return true
		}
	}
	return false
}

// AllowedAddr reports whether offline mode permits a connection to a: a local
// address (loopback, RFC1918 / ULA) or one inside an operator-declared
// AllowCIDRsEnv range — never a cloud metadata endpoint, whatever the range.
func AllowedAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || IsMetadataAddr(a) {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() {
		return true
	}
	prefixes, _ := AllowCIDRs()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Allowed is AllowedAddr for a net.IP.
func Allowed(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	return ok && AllowedAddr(a)
}

// DenyInstalls reports whether package installs in agent shells are refused:
// offline mode is on and DenyInstallsEnv is not explicitly falsy.
func DenyInstalls() bool {
	if !Enabled() {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(DenyInstallsEnv))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// EgressError is an offline refusal of an agent-initiated connection. Its text
// carries Hint, because it reaches the model as a tool result.
type EgressError struct {
	Target string // host or host:port as the caller named it
	Reason string
}

func (e *EgressError) Error() string {
	return fmt.Sprintf("offline mode: the connection to %s was refused: %s. %s", e.Target, e.Reason, Hint)
}

// Resolver resolves the names the offline gates check. Tests replace it.
var Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
} = net.DefaultResolver

// AllowedAddrs returns the addresses of host that offline mode permits, in the
// resolver's order, for the caller to dial instead of the name: dialing the
// checked addresses leaves no room for a second, different answer (DNS
// rebinding). An IP literal is checked as is. It returns an *EgressError when
// the name cannot be resolved or none of its addresses is permitted. With
// offline mode off it returns (nil, nil): the caller dials as before.
func AllowedAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	if !Enabled() {
		return nil, nil
	}
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		if !AllowedAddr(a) {
			return nil, &EgressError{Target: host, Reason: fmt.Sprintf("%s is not a local address", a.Unmap())}
		}
		return []netip.Addr{a.Unmap()}, nil
	}
	if h == "" {
		return nil, &EgressError{Target: host, Reason: "no host"}
	}
	addrs, err := Resolver.LookupNetIP(ctx, "ip", h)
	if err != nil {
		return nil, &EgressError{Target: host, Reason: "the name could not be resolved (" + err.Error() + ")"}
	}
	var out, refused []netip.Addr
	for _, a := range addrs {
		if AllowedAddr(a) {
			out = append(out, a.Unmap())
		} else {
			refused = append(refused, a.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, &EgressError{Target: host, Reason: fmt.Sprintf("%s resolves to %s, which is not a local address", h, joinAddrs(refused))}
	}
	return out, nil
}

// RequireAllAllowed is the strict form of AllowedAddrs for a caller that cannot
// dial the checked addresses itself (it hands the NAME to code that resolves
// again, e.g. the recording proxy's go-mitmproxy dialer): it refuses the host
// when ANY of its addresses is not permitted, so a name with a mixed local and
// public answer cannot be used to reach the public one. Returns nil when
// offline mode is off.
func RequireAllAllowed(ctx context.Context, host string) error {
	if !Enabled() {
		return nil
	}
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		if !AllowedAddr(a) {
			return &EgressError{Target: host, Reason: fmt.Sprintf("%s is not a local address", a.Unmap())}
		}
		return nil
	}
	if h == "" {
		return &EgressError{Target: host, Reason: "no host"}
	}
	addrs, err := Resolver.LookupNetIP(ctx, "ip", h)
	if err != nil {
		return &EgressError{Target: host, Reason: "the name could not be resolved (" + err.Error() + ")"}
	}
	var refused []netip.Addr
	for _, a := range addrs {
		if !AllowedAddr(a) {
			refused = append(refused, a.Unmap())
		}
	}
	if len(addrs) == 0 || len(refused) > 0 {
		return &EgressError{Target: host, Reason: fmt.Sprintf("%s resolves to %s, which is not a local address", h, joinAddrs(refused))}
	}
	return nil
}

func joinAddrs(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	if len(s) == 0 {
		return "no address"
	}
	return strings.Join(s, ", ")
}
