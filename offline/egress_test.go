package offline

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// fakeResolver answers from a fixed table; any other name fails like NXDOMAIN.
type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, len(ips))
	for i, s := range ips {
		out[i] = netip.MustParseAddr(s)
	}
	return out, nil
}

// TestMain keeps every test of the package off the real resolver: a name that
// is not in the table fails as if it did not exist.
func TestMain(m *testing.M) {
	Resolver = fakeResolver{
		"localhost":           {"127.0.0.1", "::1"},
		"ollama":              {"172.18.0.5"},
		"mcp.lab":             {"10.1.2.3"},
		"api.example":         {"93.184.216.34"},
		"split.example":       {"10.0.0.9", "93.184.216.34"},
		"lab-public.internal": {"203.0.113.7"},
	}
	os.Exit(m.Run())
}

func TestAllowCIDRs(t *testing.T) {
	t.Setenv(AllowCIDRsEnv, "203.0.113.0/24, 198.51.100.7 2001:db8::/32,not-a-cidr\t10.0.0.300")
	got, bad := AllowCIDRs()
	want := []string{"203.0.113.0/24", "198.51.100.7/32", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, p, want[i])
		}
	}
	if len(bad) != 2 || bad[0] != "not-a-cidr" || bad[1] != "10.0.0.300" {
		t.Errorf("invalid = %v, want [not-a-cidr 10.0.0.300]", bad)
	}
}

func TestAllowedAddrHonorsAllowList(t *testing.T) {
	t.Setenv(AllowCIDRsEnv, "")
	pub := netip.MustParseAddr("203.0.113.7")
	if AllowedAddr(pub) {
		t.Fatal("a public address must not be allowed without an allow-list entry")
	}
	if AllowedAddr(netip.MustParseAddr("169.254.169.254")) {
		t.Fatal("link-local (cloud metadata) must not be allowed")
	}
	if !AllowedAddr(netip.MustParseAddr("::ffff:192.168.1.2")) {
		t.Fatal("an IPv4-mapped private address must be allowed")
	}
	t.Setenv(AllowCIDRsEnv, "203.0.113.0/24")
	if !AllowedAddr(pub) {
		t.Fatal("an address inside an allow-list range must be allowed")
	}
	if AllowedAddr(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("an address outside the allow-list must stay refused")
	}
}

func TestAllowedAddrs(t *testing.T) {
	t.Setenv(Env, "1")
	t.Setenv(AllowCIDRsEnv, "")
	ctx := context.Background()

	addrs, err := AllowedAddrs(ctx, "ollama")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "172.18.0.5" {
		t.Fatalf("ollama: got %v, %v", addrs, err)
	}
	// A name with a public and a private answer: only the private one is dialled.
	addrs, err = AllowedAddrs(ctx, "split.example")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "10.0.0.9" {
		t.Fatalf("split.example: got %v, %v", addrs, err)
	}
	if addrs, err = AllowedAddrs(ctx, "[::1]"); err != nil || len(addrs) != 1 {
		t.Fatalf("[::1]: got %v, %v", addrs, err)
	}

	for _, host := range []string{"api.example", "8.8.8.8", "unknown.example", ""} {
		_, err := AllowedAddrs(ctx, host)
		if _, ok := errors.AsType[*EgressError](err); !ok {
			t.Fatalf("%q: want *EgressError, got %v", host, err)
		}
		if !strings.Contains(err.Error(), "list_tools") {
			t.Errorf("%q: the refusal must carry the hint, got %q", host, err)
		}
	}

	t.Setenv(AllowCIDRsEnv, "203.0.113.0/24")
	if _, err := AllowedAddrs(ctx, "lab-public.internal"); err != nil {
		t.Fatalf("an allow-listed public range must pass: %v", err)
	}

	t.Setenv(Env, "0")
	if addrs, err := AllowedAddrs(ctx, "api.example"); addrs != nil || err != nil {
		t.Fatalf("offline off: want (nil, nil), got %v, %v", addrs, err)
	}
}

func TestDenyInstalls(t *testing.T) {
	t.Setenv(Env, "1")
	t.Setenv(DenyInstallsEnv, "")
	if !DenyInstalls() {
		t.Fatal("installs must be refused by default in offline mode")
	}
	t.Setenv(DenyInstallsEnv, "off")
	if DenyInstalls() {
		t.Fatal("ARTEX_DENY_INSTALLS=off must turn the refusal off")
	}
	t.Setenv(DenyInstallsEnv, "1")
	t.Setenv(Env, "0")
	if DenyInstalls() {
		t.Fatal("the refusal must be off when offline mode is off")
	}
}

func TestGuardDialAllowList(t *testing.T) {
	t.Setenv(Env, "1")
	t.Setenv(AllowCIDRsEnv, "203.0.113.0/24")
	if err := GuardDial("tcp", "203.0.113.9:443", nil); err != nil {
		t.Fatalf("allow-listed address must pass: %v", err)
	}
	if err := GuardDial("tcp", "198.51.100.1:443", nil); err == nil {
		t.Fatal("an address outside the allow-list must be refused")
	}
}

func TestEndpointChecksResolveNames(t *testing.T) {
	t.Setenv(Env, "1")
	t.Setenv(AllowCIDRsEnv, "")
	// A compose service name or LAN name that resolves to private addresses is local.
	if err := CheckEndpointLocal("http://ollama:11434/v1"); err != nil {
		t.Errorf("a service name resolving to a private address must be allowed: %v", err)
	}
	if err := CheckURLLocal("MCP server", "http://mcp.lab:8931/mcp"); err != nil {
		t.Errorf("a LAN MCP server must be allowed: %v", err)
	}
	// Any public answer refuses the name.
	for _, u := range []string{"https://api.example/v1", "https://split.example", "https://unknown.example"} {
		if err := CheckURLLocal("MCP server", u); err == nil {
			t.Errorf("%s must be refused", u)
		}
	}
	if err := CheckURLLocal("MCP server", "::not a url"); err == nil {
		t.Error("an unparsable endpoint must be refused")
	}
	t.Setenv(Env, "0")
	if err := CheckURLLocal("MCP server", "https://api.example"); err != nil {
		t.Errorf("offline off: everything allowed, got %v", err)
	}
}
