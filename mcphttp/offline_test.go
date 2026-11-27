package mcphttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/offline"
)

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

// TestOfflineRefusesRemoteMCP: in offline mode a non-local MCP endpoint is
// refused before any request, for both transports.
func TestOfflineRefusesRemoteMCP(t *testing.T) {
	t.Setenv(offline.Env, "1")
	prev := offline.Resolver
	offline.Resolver = offlineNames{"mcp.vendor.example": {"203.0.113.40"}}
	t.Cleanup(func() { offline.Resolver = prev })

	for _, u := range []string{"https://mcp.vendor.example/mcp", "http://203.0.113.40:8080/mcp"} {
		if _, err := New(context.Background(), "remote", u, nil, false, 5); err == nil || !strings.Contains(err.Error(), "offline mode") {
			t.Errorf("New(%s): want an offline refusal, got %v", u, err)
		}
		if _, err := NewSSE(context.Background(), "remote", u, nil, true); err == nil || !strings.Contains(err.Error(), "offline mode") {
			t.Errorf("NewSSE(%s): want an offline refusal, got %v", u, err)
		}
	}
}

// TestOfflineTransport: the offline transport ignores the environment proxy
// and refuses a public address at dial time, while a local server is reached.
func TestOfflineTransport(t *testing.T) {
	t.Setenv(offline.Env, "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()

	tr, ok := transport(false).(*http.Transport)
	if !ok || tr.Proxy != nil || tr.DialContext == nil {
		t.Fatalf("offline transport must dial itself without a proxy, got %#v", transport(false))
	}
	c := &http.Client{Transport: tr}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("local server: %v", err)
	}
	resp.Body.Close()
	if _, err := tr.DialContext(context.Background(), "tcp", "203.0.113.40:443"); err == nil || !strings.Contains(err.Error(), "offline mode") {
		t.Fatalf("a public address must be refused at dial time, got %v", err)
	}
	if it, ok := transport(true).(*http.Transport); !ok || it.TLSClientConfig == nil || !it.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure must still skip TLS verification in offline mode")
	}

	t.Setenv(offline.Env, "0")
	if transport(false) != nil {
		t.Fatal("offline off and secure: the default transport must be kept")
	}
}
