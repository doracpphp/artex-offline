package traffic

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/doracpphp/artex-offline/offline"
)

// offlineResolver answers from a fixed table; any other name is NXDOMAIN.
type offlineResolver map[string][]string

func (f offlineResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
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

func offlineOn(t *testing.T) {
	t.Helper()
	t.Setenv(offline.Env, "1")
	t.Setenv(offline.AllowCIDRsEnv, "")
	prev := offline.Resolver
	offline.Resolver = offlineResolver{
		"localhost":      {"127.0.0.1"},
		"pypi.example":   {"203.0.113.30"},
		"github.example": {"203.0.113.31"},
	}
	t.Cleanup(func() { offline.Resolver = prev })
}

// TestProxyOfflineRefusesPublic runs the real recording proxy: in offline mode
// a request to a public destination gets the readable 403 (and never reaches
// the network), while a local destination is forwarded as before.
func TestProxyOfflineRefusesPublic(t *testing.T) {
	offlineOn(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "local ok")
	}))
	defer local.Close()
	tr, _, proxyURL := startProxy(t)
	client := proxyClient(t, tr, proxyURL)

	for _, u := range []string{"http://pypi.example/simple/requests/", "http://203.0.113.5/x", "http://unknown.example/"} {
		resp, err := client.Get(u)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Artex-Offline") != "blocked" {
			t.Fatalf("%s: status %d, want the offline 403", u, resp.StatusCode)
		}
		if !strings.Contains(string(body), "offline mode") || !strings.Contains(string(body), "list_tools") {
			t.Fatalf("%s: body %q must explain the refusal and point to list_tools", u, body)
		}
	}

	resp, err := client.Get(local.URL)
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "local ok" {
		t.Fatalf("local: status %d body %q, want it forwarded", resp.StatusCode, body)
	}
}

// TestUpstreamForOffline covers the dial-time gate every upstream connection
// passes, CONNECT tunnels included: the CONNECT itself carries no readable
// body, so this is where a tunnel to a public host is refused.
func TestUpstreamForOffline(t *testing.T) {
	offlineOn(t)
	tr, _ := openTraffic(t)
	connect := func(authority string) *http.Request {
		return &http.Request{Method: http.MethodConnect, Host: authority, URL: &url.URL{Host: authority}}
	}
	for _, a := range []string{"203.0.113.5:443", "github.example:443", "[2001:db8::1]:443"} {
		if _, err := tr.upstreamFor(connect(a)); err == nil {
			t.Errorf("CONNECT %s must be refused in offline mode", a)
		}
	}
	for _, a := range []string{"127.0.0.1:8443", "localhost:443", "10.0.0.7:443"} {
		if up, err := tr.upstreamFor(connect(a)); err != nil || up != nil {
			t.Errorf("CONNECT %s: want a direct dial, got %v, %v", a, up, err)
		}
	}
	// A plain request names its destination in the absolute URL.
	req := &http.Request{Method: http.MethodGet, Host: "pypi.example", URL: &url.URL{Scheme: "http", Host: "pypi.example"}}
	if _, err := tr.upstreamFor(req); err == nil {
		t.Error("a plain request to a public host must be refused")
	}
	t.Setenv(offline.Env, "0")
	if _, err := tr.upstreamFor(connect("203.0.113.5:443")); err != nil {
		t.Errorf("offline off: %v", err)
	}
}

func TestOfflineCheck(t *testing.T) {
	offlineOn(t)
	if err := offlineCheck("localhost:8080", nil); err != nil {
		t.Fatalf("local destination: %v", err)
	}
	if err := offlineCheck("pypi.example:443", nil); err == nil {
		t.Fatal("a public destination must be refused")
	}
	// A local destination through a public upstream proxy is refused too: the
	// proxy would carry the connection out.
	up, _ := ValidateProxyURL("http://127.0.0.1:3128")
	if err := offlineCheck("localhost", up); err != nil {
		t.Fatalf("local destination through a local proxy: %v", err)
	}
	t.Setenv(offline.Env, "0")
	if err := offlineCheck("pypi.example:443", nil); err != nil {
		t.Fatalf("offline off: %v", err)
	}
}

func TestValidateProxyURLOffline(t *testing.T) {
	offlineOn(t)
	for _, raw := range []string{"http://127.0.0.1:3128", "socks5://user:pw@localhost:1080"} {
		if _, err := ValidateProxyURL(raw); err != nil {
			t.Errorf("%s: a local proxy must be accepted: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://203.0.113.9:3128", "socks5://pypi.example:1080"} {
		if _, err := ValidateProxyURL(raw); err == nil {
			t.Errorf("%s: a non-local proxy must be refused in offline mode", raw)
		}
	}
	t.Setenv(offline.Env, "0")
	if _, err := ValidateProxyURL("http://203.0.113.9:3128"); err != nil {
		t.Errorf("offline off: %v", err)
	}
}
