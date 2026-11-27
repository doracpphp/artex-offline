package traffic

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/doracpphp/artex-offline/offline"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// Offline gate of the recording proxy. Agent shells get HTTP(S)_PROXY /
// ALL_PROXY pointing here, so tools that honor those variables (pip, git, curl,
// npm, go, ...) reach the network through this proxy. In offline mode it
// forwards only to local destinations (offline.AllowedAddrs), through a local
// upstream proxy if one is set. It is a turn-saving layer with a clear message,
// not a boundary: a tool that ignores the proxy variables connects directly,
// which only network isolation stops (docs/offline-toolbox.md §6.4).

// offlineLookupTimeout bounds the name lookup of one offline check.
const offlineLookupTimeout = 5 * time.Second

// offlineCheck returns the refusal for forwarding to host (a bare host or
// host:port) through upstream (nil = direct), or nil when offline mode is off
// or the destination is local.
//
// go-mitmproxy dials the NAME itself after this check, so the check is strict:
// every address the name resolves to must be local (offline.RequireAllAllowed);
// a mixed local/public answer is refused rather than filtered. An upstream proxy
// is refused outright in offline mode (traffic.ValidateProxyURL never lets one
// be set, and this guards a stale value too). A rebinding between this lookup
// and go-mitmproxy's own is the residual risk of a check-then-dial layer; the
// egress firewall is the boundary (docs/offline-toolbox.md §6.4).
func offlineCheck(host string, upstream *url.URL) error {
	if !offline.Enabled() {
		return nil
	}
	if upstream != nil {
		return &offline.EgressError{Target: upstream.Host, Reason: "an upstream egress proxy is not allowed in offline mode"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), offlineLookupTimeout)
	defer cancel()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return offline.RequireAllAllowed(ctx, host)
}

// upstreamFor is go-mitmproxy's upstream selector: the global egress proxy, or
// nil for a direct dial. go-mitmproxy calls it before every upstream
// connection, so an error here refuses the connection before it is opened.
func (t *Traffic) upstreamFor(req *http.Request) (*url.URL, error) {
	up := t.upstream.Load()
	if err := offlineCheck(requestHost(req), up); err != nil {
		return nil, err
	}
	return up, nil
}

// requestHost is the destination host of a proxied request: the URL host of an
// absolute-form or intercepted request, else the Host header (CONNECT).
func requestHost(req *http.Request) string {
	if req.URL != nil && req.URL.Host != "" {
		return req.URL.Host
	}
	return req.Host
}

// offlineResponse is the answer a client gets for a request offline mode does
// not forward: a 403 whose body carries the refusal and its hint, so that a
// model reading curl's or pip's output learns why and what to do instead.
func offlineResponse(err error) *mproxy.Response {
	h := make(http.Header)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Artex-Offline", "blocked")
	body := "[ARTEX platform control] " + strings.TrimSpace(err.Error()) + "\n"
	return &mproxy.Response{StatusCode: http.StatusForbidden, Header: h, Body: []byte(body)}
}
