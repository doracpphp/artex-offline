package intercept

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/offline"
)

// offlineNames is a resolver for the offline tests: a fixed table, and NXDOMAIN
// for any other name.
type offlineNames map[string][]string

func (f offlineNames) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
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

// offlineFixture turns offline mode on, swaps the offline resolver and the
// package base dialer for test doubles, and restores them afterwards.
func offlineFixture(t *testing.T) *dialRecorder {
	t.Helper()
	t.Setenv(offline.Env, "1")
	t.Setenv(offline.AllowCIDRsEnv, "")
	prevResolver, prevBase := offline.Resolver, baseDial
	offline.Resolver = offlineNames{
		"lab.local":     {"127.0.0.1"},
		"split.example": {"203.0.113.10", "127.0.0.1"},
		"cdn.example":   {"203.0.113.20"},
	}
	rec := newDialRecorder()
	baseDial = rec.dial
	t.Cleanup(func() { offline.Resolver, baseDial = prevResolver, prevBase })
	return rec
}

func wantOfflineBlock(t *testing.T, err error) {
	t.Helper()
	code, ok := IsTargetBlocked(err)
	if !ok || code != OfflineEgressBlocked {
		t.Fatalf("want %s, got %v", OfflineEgressBlocked, err)
	}
	if !strings.Contains(err.Error(), "list_tools") {
		t.Errorf("the refusal must tell the model to use the installed tools: %q", err)
	}
}

func TestPinnedDialerOfflineUnscoped(t *testing.T) {
	rec := offlineFixture(t)
	_, _, port := pinnedServer(t, "ok")
	dial := PinnedDialer("WebFetch", false)

	// A public address is refused before any connection is attempted.
	_, err := dial(context.Background(), "tcp", "203.0.113.5:443")
	wantOfflineBlock(t, err)
	_, err = dial(context.Background(), "tcp", "cdn.example:443")
	wantOfflineBlock(t, err)
	if calls := rec.calls(); len(calls) != 0 {
		t.Fatalf("a refused connection must not be dialled, got %v", calls)
	}

	// A name with a public and a local answer is dialled at the local address only.
	conn, err := dial(context.Background(), "tcp", "split.example:"+port)
	if err != nil {
		t.Fatalf("split.example: %v", err)
	}
	conn.Close()
	if calls := rec.calls(); !slices.Equal(calls, []string{"127.0.0.1:" + port}) {
		t.Fatalf("dialled %v, want only the local address", calls)
	}
}

func TestPinnedDialerOfflineGateOff(t *testing.T) {
	offlineFixture(t)
	rec := newDialRecorder()
	ic := &Interceptor{dial: rec.dial}
	_, _, port := pinnedServer(t, "ok")
	ctx := WithTargetScope(context.Background(), TargetScope{TaskID: "1", Enabled: func() bool { return false }, Interceptor: ic})
	dial := PinnedDialer("enrich", true)

	_, err := dial(ctx, "tcp", "203.0.113.5:80")
	wantOfflineBlock(t, err)
	conn, err := dial(ctx, "tcp", "lab.local:"+port)
	if err != nil {
		t.Fatalf("a local target must still be reachable with the gate off: %v", err)
	}
	conn.Close()
	if calls := rec.calls(); !slices.Equal(calls, []string{"127.0.0.1:" + port}) {
		t.Fatalf("dialled %v through the interceptor's base dialer, want [127.0.0.1:%s]", calls, port)
	}
}

func TestPinnedDialerOfflineOffUnchanged(t *testing.T) {
	rec := offlineFixture(t)
	t.Setenv(offline.Env, "0")
	_, _ = PinnedDialer("WebFetch", false)(context.Background(), "tcp", "203.0.113.5:443")
	if calls := rec.calls(); !slices.Equal(calls, []string{"203.0.113.5:443"}) {
		t.Fatalf("with offline mode off the address must be dialled as given, got %v", calls)
	}
}

func TestDialSOCKS5OfflineWithoutStore(t *testing.T) {
	offlineFixture(t)
	rec := newDialRecorder()
	ic := &Interceptor{dial: rec.dial}
	_, err := ic.DialSOCKS5(context.Background(), "tcp", "cdn.example:443")
	wantOfflineBlock(t, err)
	_, _, port := pinnedServer(t, "ok")
	conn, err := ic.DialSOCKS5(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("local relay: %v", err)
	}
	conn.Close()

	var nilIC *Interceptor
	_, err = nilIC.DialSOCKS5(context.Background(), "tcp", "203.0.113.5:443")
	wantOfflineBlock(t, err)
}

func TestOfflineFilter(t *testing.T) {
	offlineFixture(t)
	got, err := offlineFilter("split.example:443", []string{"203.0.113.10", "10.0.0.4", "fd00::1"})
	if err != nil || !slices.Equal(got, []string{"10.0.0.4", "fd00::1"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	_, err = offlineFilter("cdn.example:443", []string{"203.0.113.20", "169.254.169.254"})
	wantOfflineBlock(t, err)

	t.Setenv(offline.AllowCIDRsEnv, "203.0.113.0/24")
	if got, err := offlineFilter("cdn.example:443", []string{"203.0.113.20"}); err != nil || len(got) != 1 {
		t.Fatalf("an allow-listed range must pass: %v, %v", got, err)
	}
	t.Setenv(offline.Env, "0")
	if got, err := offlineFilter("x", []string{"8.8.8.8"}); err != nil || len(got) != 1 {
		t.Fatalf("offline off must pass everything: %v, %v", got, err)
	}
}

func TestOfflineUDP(t *testing.T) {
	offlineFixture(t)
	if _, err := offlineUDP("8.8.8.8:53", &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}, nil); err == nil {
		t.Fatal("a public UDP destination must be refused")
	} else {
		wantOfflineBlock(t, err)
	}
	if a, err := offlineUDP("10.0.0.53:53", &net.UDPAddr{IP: net.ParseIP("10.0.0.53"), Port: 53}, nil); err != nil || a == nil {
		t.Fatalf("a private UDP destination must pass: %v", err)
	}
	a, err := PinnedUDP4Resolver("socks5-udp", false)(context.Background(), "8.8.4.4:53")
	if err == nil {
		t.Fatalf("an unscoped public UDP destination must be refused, got %v", a)
	}
	wantOfflineBlock(t, err)
}
