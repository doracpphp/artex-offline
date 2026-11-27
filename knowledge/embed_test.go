package knowledge

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/offline"
)

// embedServer is a fake embedding server for both wire formats, returning a
// deterministic 4-dim vector per input so tests can assert ordering.
func embedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/embed", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Model string   `json:"model"`
			Input []string `json:"input"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		vecs := make([][]float32, len(in.Input))
		for i, s := range in.Input {
			vecs[i] = toyVector(s)
		}
		json.NewEncoder(w).Encode(map[string]any{"embeddings": vecs})
	})
	mux.HandleFunc("/v1/embeddings", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Model string   `json:"model"`
			Input []string `json:"input"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		type d struct {
			Index     int       `json:"index"`
			Embedding []float32 `json:"embedding"`
		}
		var data []d
		// Return out of order to exercise index placement.
		for i := len(in.Input) - 1; i >= 0; i-- {
			data = append(data, d{Index: i, Embedding: toyVector(in.Input[i])})
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// toyVector maps text to a small deterministic unit-ish vector.
func toyVector(s string) []float32 {
	var v [4]float32
	for i, r := range s {
		v[i%4] += float32((int(r) % 17)) / 17
	}
	n := float32(math.Sqrt(float64(v[0]*v[0] + v[1]*v[1] + v[2]*v[2] + v[3]*v[3])))
	if n == 0 {
		n = 1
	}
	return []float32{v[0] / n, v[1] / n, v[2] / n, v[3] / n}
}

func TestEmbeddersBothFormats(t *testing.T) {
	t.Setenv(offline.Env, "0")
	srv := embedServer(t)
	for _, provider := range []string{"ollama", "openai"} {
		e, err := NewEmbedder(EmbedConfig{Provider: provider, Model: "test-model", Endpoint: srv.URL})
		if err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		if e.Model() != "test-model" {
			t.Errorf("%s model: %q", provider, e.Model())
		}
		vecs, err := e.Embed(context.Background(), []string{"alpha", "beta", "gamma"})
		if err != nil {
			t.Fatalf("%s embed: %v", provider, err)
		}
		if len(vecs) != 3 || len(vecs[0]) != 4 {
			t.Fatalf("%s shape: %d x %d", provider, len(vecs), len(vecs[0]))
		}
		// Order preserved: input[0] "alpha" maps to toyVector("alpha").
		if vecs[0][0] != toyVector("alpha")[0] {
			t.Errorf("%s: first vector does not match the first input", provider)
		}
		if vecs[1][1] != toyVector("beta")[1] {
			t.Errorf("%s: order not preserved", provider)
		}
	}
}

// testResolver answers from a fixed name→IP table for the offline check.
type testResolver map[string][]string

func (f testResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
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

func TestEmbedderOfflineRejectsCloud(t *testing.T) {
	t.Setenv(offline.Env, "1")
	prev := offline.Resolver
	offline.Resolver = testResolver{"api.openai.com": {"1.2.3.4"}, "localhost": {"127.0.0.1"}}
	t.Cleanup(func() { offline.Resolver = prev })
	if _, err := NewEmbedder(EmbedConfig{Provider: "openai", Model: "m", Endpoint: "https://api.openai.com"}); err == nil {
		t.Fatal("offline mode must reject a cloud embedding endpoint")
	}
	if _, err := NewEmbedder(EmbedConfig{Provider: "ollama", Model: "m", Endpoint: "http://localhost:11434"}); err != nil {
		t.Errorf("a local embedding endpoint must be allowed offline: %v", err)
	}
}

func TestLoadEmbedConfig(t *testing.T) {
	t.Setenv(EmbedModelEnv, "")
	t.Setenv(EmbedEndpointEnv, "")
	if _, ok := LoadEmbedConfig(); ok {
		t.Fatal("no model/endpoint → not configured")
	}
	t.Setenv(EmbedModelEnv, "nomic-embed-text")
	t.Setenv(EmbedEndpointEnv, "http://127.0.0.1:11434")
	cfg, ok := LoadEmbedConfig()
	if !ok || cfg.Provider != "ollama" || cfg.Model != "nomic-embed-text" {
		t.Fatalf("config: %+v ok=%v", cfg, ok)
	}
}

func TestFormatVector(t *testing.T) {
	got := formatVector([]float32{1, 0.5, -0.25})
	if got != "[1,0.5,-0.25]" {
		t.Fatalf("formatVector = %q", got)
	}
}

func TestFuseRRF(t *testing.T) {
	// Chunk 7 ranks high in both lists → should win; chunk 9 only in vector.
	lex := []chunkRow{{chunkID: 7}, {chunkID: 8}, {chunkID: 5}}
	vec := []chunkRow{{chunkID: 7}, {chunkID: 9}, {chunkID: 8}}
	out := fuseRRF(lex, vec, 3)
	if len(out) != 3 || out[0].chunkID != 7 {
		t.Fatalf("RRF top should be the chunk ranked high in both: %+v", out)
	}
	ids := map[int64]bool{}
	for _, r := range out {
		ids[r.chunkID] = true
	}
	if !ids[8] { // 8 appears in both lists (ranks 2 and 3) → beats singletons 5 and 9
		t.Errorf("chunk 8 (in both lists) should rank in the top 3: %+v", out)
	}
}

func TestEmbedServerErrorPropagates(t *testing.T) {
	t.Setenv(offline.Env, "0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("model not found"))
	}))
	defer srv.Close()
	e, _ := NewEmbedder(EmbedConfig{Provider: "ollama", Model: "m", Endpoint: srv.URL})
	_, err := e.Embed(context.Background(), []string{"x"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("server error should propagate: %v", err)
	}
}
