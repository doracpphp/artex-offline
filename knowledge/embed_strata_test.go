package knowledge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/doracpphp/artex-offline/offline"
)

// TestOpenAIEmbedderURLForms confirms the OpenAI-format embedder (used for a
// Strata or any OpenAI-compatible local gateway) posts to /v1/embeddings whether
// the configured endpoint includes the /v1 suffix or not.
func TestOpenAIEmbedderURLForms(t *testing.T) {
	t.Setenv(offline.Env, "0")
	var gotPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"index": 0, "embedding": []float32{1, 0}}}})
	}))
	defer srv.Close()
	for _, base := range []string{srv.URL, srv.URL + "/v1", srv.URL + "/v1/"} {
		e, err := NewEmbedder(EmbedConfig{Provider: "openai", Model: "m", Endpoint: base})
		if err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		if _, err := e.Embed(context.Background(), []string{"x"}); err != nil {
			t.Fatalf("%s: embed: %v", base, err)
		}
		if gotPath.Load() != "/v1/embeddings" {
			t.Errorf("base %q posted to %v, want /v1/embeddings", base, gotPath.Load())
		}
	}
}
