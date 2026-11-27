// Package offline implements ARTEX's offline / local-LLM-only enforcement.
//
// ARTEX was designed for online use: the LLM backend could point at a cloud API
// (api.anthropic.com, api.openai.com), the backend could poll GitHub for a
// newer release, and notification channels could push to external IM / mail
// services. In an offline environment none of that is wanted: the only LLM is a
// LOCAL inference server (Ollama, or an OpenAI/Anthropic-compatible local
// gateway such as Strata) and NOTHING may reach a third-party service on the
// public internet.
//
// Offline mode is ON by default. Set ARTEX_OFFLINE=0 (or false/off/no) to turn
// it off and restore the original online behavior.
//
// What "local" means here (Enabled() == true):
//   - The LLM endpoint host must resolve to a local address — loopback, an
//     RFC1918 / ULA private network, or the Docker host alias. This is a
//     HOST-based rule, not a provider-format rule, so Ollama, Strata and any
//     other local gateway all work while only public cloud endpoints are
//     refused.
//   - All platform-owned outbound HTTP(S)/SMTP (LLM calls, notifications, the
//     update check) is confined to local addresses; a dial to a public address
//     is refused at connection time, which also defeats DNS-rebinding and
//     cross-host redirects.
//
// Target traffic (the scoped victim of a penetration test) does NOT go through
// this package and is unaffected — in an offline environment the target is
// itself a local/LAN host.
//
// This package depends only on the standard library so that leaf packages such
// as notify can import it without taking on heavier dependencies.
package offline

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// Env is the environment variable that controls offline mode.
const Env = "ARTEX_OFFLINE"

// Enabled reports whether offline / local-LLM-only mode is active.
//
// It is ON by default: an unset, empty or unrecognized value means ON. Only an
// explicit falsy value ("0", "false", "off", "no", any case) turns it OFF. This
// mirrors agent.isFalsy so the whole codebase reads env booleans the same way.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(Env))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// IsLocalIP reports whether ip is a local address that offline mode permits:
// loopback or an RFC1918 / ULA private network.
//
// Link-local (169.254.0.0/16, fe80::/10) is deliberately NOT treated as local:
// it is where the cloud metadata endpoint (169.254.169.254) lives, and nothing
// legitimate in an offline deployment — a local LLM, a LAN mail relay, the
// Docker host gateway — sits there. Keeping it out preserves the SSRF
// protection that would otherwise be lost when the notify guard is inverted.
func IsLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) must be folded back to IPv4 before the
	// check, otherwise it bypasses it.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if a, ok := netip.AddrFromSlice(ip); ok && IsMetadataAddr(a) {
		return false // fd00:ec2::254 is ULA (IsPrivate) but is a metadata endpoint
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// IsLocalHost reports whether host (a bare host, no port) is one offline mode
// treats as local. An IP literal is checked with IsLocalIP; the names
// "localhost", "*.localhost" and "host.docker.internal" are accepted by name
// (the Docker host alias resolves to a private gateway address at dial time, so
// the dial guard still confirms it).
func IsLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// Strip IPv6 brackets if present ("[::1]").
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if ip := net.ParseIP(host); ip != nil {
		return Allowed(ip)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if host == "host.docker.internal" {
		return true
	}
	return false
}

// GuardDial is a net.Dialer.Control hook. When offline mode is on it refuses a
// connection to any non-local address; when off it is a no-op so the original
// online behavior is unchanged.
//
// Control runs after name resolution with the concrete host:port about to be
// dialed, so this is the final enforcement point: a public hostname that
// resolved to a public IP is refused here even if an earlier name-based check
// was bypassed by DNS rebinding or a redirect.
func GuardDial(_, address string, _ syscall.RawConn) error {
	if !Enabled() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("offline mode: cannot parse dial target %q", host)
	}
	if !Allowed(ip) {
		return fmt.Errorf("offline mode: refusing to connect to non-local address %s (set %s=0 to allow external connections, or add the range to %s)", ip, Env, AllowCIDRsEnv)
	}
	return nil
}

// CheckURLLocal is CheckEndpointLocal for a non-LLM endpoint (an MCP server,
// an archive store): kind names it in the error. It returns nil when offline
// mode is off.
func CheckURLLocal(kind, rawURL string) error {
	if !Enabled() {
		return nil
	}
	host := hostOf(strings.TrimSpace(rawURL))
	if host == "" {
		return fmt.Errorf("offline mode: cannot parse the %s endpoint %q", kind, rawURL)
	}
	if !hostResolvesLocal(host) {
		return fmt.Errorf("offline mode: the %s endpoint host %q is not local; use a local endpoint, add its range to %s, or set %s=0", kind, host, AllowCIDRsEnv, Env)
	}
	return nil
}

// configLookupTimeout bounds the name lookup of a configuration-time check.
const configLookupTimeout = 3 * time.Second

// hostResolvesLocal is the configuration-time test of an endpoint host: a host
// IsLocalHost accepts by itself, or a name (a compose service such as
// "ollama", a LAN name) whose every address offline mode permits. A name that
// does not resolve is not local. The dial guard still checks the address of
// each connection; this only rejects a cloud endpoint early with a clear error.
func hostResolvesLocal(host string) bool {
	if IsLocalHost(host) {
		return true
	}
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if net.ParseIP(h) != nil || h == "" {
		return false // an IP literal IsLocalHost refused
	}
	ctx, cancel := context.WithTimeout(context.Background(), configLookupTimeout)
	defer cancel()
	addrs, err := Resolver.LookupNetIP(ctx, "ip", h)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !AllowedAddr(a) {
			return false
		}
	}
	return true
}

// CheckEndpointLocal validates, at configuration time, that rawURL points at a
// local host. It returns nil when offline mode is off. The error is phrased for
// an operator who has configured a cloud LLM endpoint.
func CheckEndpointLocal(rawURL string) error {
	if !Enabled() {
		return nil
	}
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return fmt.Errorf("offline mode: a local LLM endpoint is required (e.g. Ollama http://127.0.0.1:11434 or a local Strata gateway); a cloud provider's default endpoint is not allowed")
	}
	host := hostOf(raw)
	if host == "" {
		return fmt.Errorf("offline mode: cannot parse LLM endpoint %q", raw)
	}
	if !hostResolvesLocal(host) {
		return fmt.Errorf("offline mode: LLM endpoint host %q is not local; use a local LLM (Ollama/Strata), add its range to %s, or set %s=0", host, AllowCIDRsEnv, Env)
	}
	return nil
}

// hostOf extracts the host from an endpoint that may be a full URL
// ("http://127.0.0.1:11434/v1"), a bare authority ("127.0.0.1:11434"), or a
// bare host ("localhost"). Returns "" when no host can be determined.
func hostOf(raw string) string {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
		return ""
	}
	// No scheme: treat it as an authority or bare host.
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	return raw
}
