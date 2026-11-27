package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/offline"
)

// Embedding backs the vector half of hybrid search (docs §4.2, Phase 2). A local
// embedding server (Ollama, or an OpenAI-compatible gateway) turns chunk text and
// a query into vectors; pgvector stores and searches them (vector.go). The
// endpoint must be local — offline mode forbids a cloud embedding service just as
// it does a cloud LLM — and every call dials through offline.GuardDial.

// Embedding configuration env vars (docs §6). Unset endpoint/model = no embedder,
// so search stays lexical-only.
const (
	// EmbedProviderEnv selects the wire format: "ollama" (default) or "openai".
	EmbedProviderEnv = "ARTEX_KNOWLEDGE_EMBED_PROVIDER"
	// EmbedModelEnv is the embedding model name (e.g. nomic-embed-text, bge-m3).
	EmbedModelEnv = "ARTEX_KNOWLEDGE_EMBED_MODEL"
	// EmbedEndpointEnv is the server base URL (e.g. http://host.docker.internal:11434).
	EmbedEndpointEnv = "ARTEX_KNOWLEDGE_EMBED_ENDPOINT"
)

// Embedder turns text into vectors. Implementations are safe for concurrent use.
type Embedder interface {
	// Model is the embedding model name, recorded alongside each vector so a model
	// change is detectable.
	Model() string
	// Embed returns one vector per input text, in order. All vectors from one
	// model share a dimension.
	Embed(ctx context.Context, texts []string) ([][]float32, error)
}

// EmbedConfig is the resolved embedding configuration.
type EmbedConfig struct {
	Provider string // "ollama" | "openai"
	Model    string
	Endpoint string
}

// LoadEmbedConfig reads the embedding configuration from the environment. ok is
// false when no model/endpoint is set, meaning "lexical search only".
func LoadEmbedConfig() (EmbedConfig, bool) {
	c := EmbedConfig{
		Provider: strings.ToLower(strings.TrimSpace(os.Getenv(EmbedProviderEnv))),
		Model:    strings.TrimSpace(os.Getenv(EmbedModelEnv)),
		Endpoint: strings.TrimSpace(os.Getenv(EmbedEndpointEnv)),
	}
	if c.Provider == "" {
		c.Provider = "ollama"
	}
	if c.Model == "" || c.Endpoint == "" {
		return c, false
	}
	return c, true
}

// NewEmbedderFromEnv builds the configured embedder, or (nil, nil) when none is
// configured. In offline mode the endpoint must be local, like an LLM endpoint.
func NewEmbedderFromEnv() (Embedder, error) {
	cfg, ok := LoadEmbedConfig()
	if !ok {
		return nil, nil
	}
	return NewEmbedder(cfg)
}

// NewEmbedder builds an embedder for cfg, validating the endpoint is local when
// offline mode is on.
func NewEmbedder(cfg EmbedConfig) (Embedder, error) {
	if err := offline.CheckURLLocal("embedding", cfg.Endpoint); err != nil {
		return nil, err
	}
	base := strings.TrimRight(cfg.Endpoint, "/")
	hc := &http.Client{
		Timeout:   2 * time.Minute,
		Transport: embedTransport(),
	}
	switch cfg.Provider {
	case "ollama", "":
		return &ollamaEmbedder{model: cfg.Model, base: base, hc: hc}, nil
	case "openai":
		return &openaiEmbedder{model: cfg.Model, base: base, hc: hc}, nil
	default:
		return nil, fmt.Errorf("unknown embedding provider %q (use ollama or openai)", cfg.Provider)
	}
}

// embedTransport returns the HTTP transport for embedding calls: in offline mode
// it pins every dial to a local address (offline.GuardDial) and ignores the
// environment proxy, which would otherwise carry the call out; otherwise the
// default transport.
func embedTransport() http.RoundTripper {
	if !offline.Enabled() {
		return nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: offline.GuardDial}).DialContext
	return tr
}

// ollamaEmbedder calls Ollama's native embeddings endpoint (/api/embed), which
// accepts a batch of inputs and returns one vector each.
type ollamaEmbedder struct {
	model string
	base  string
	hc    *http.Client
}

func (e *ollamaEmbedder) Model() string { return e.model }

func (e *ollamaEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	body, _ := json.Marshal(map[string]any{"model": e.model, "input": texts})
	endpoint := e.base + "/api/embed"
	var out struct {
		Embeddings [][]float32 `json:"embeddings"`
		Error      string      `json:"error"`
	}
	if err := postJSON(ctx, e.hc, endpoint, body, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return nil, fmt.Errorf("ollama embed: %s", out.Error)
	}
	if len(out.Embeddings) != len(texts) {
		return nil, fmt.Errorf("ollama returned %d embeddings for %d inputs", len(out.Embeddings), len(texts))
	}
	return out.Embeddings, nil
}

// openaiEmbedder calls an OpenAI-compatible /v1/embeddings endpoint.
type openaiEmbedder struct {
	model string
	base  string
	hc    *http.Client
}

func (e *openaiEmbedder) Model() string { return e.model }

func (e *openaiEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	body, _ := json.Marshal(map[string]any{"model": e.model, "input": texts})
	endpoint := strings.TrimSuffix(e.base, "/v1") + "/v1/embeddings"
	var out struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := postJSON(ctx, e.hc, endpoint, body, &out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("openai embed: %s", out.Error.Message)
	}
	if len(out.Data) != len(texts) {
		return nil, fmt.Errorf("openai returned %d embeddings for %d inputs", len(out.Data), len(texts))
	}
	// data may be out of order; place by index.
	vecs := make([][]float32, len(texts))
	for _, d := range out.Data {
		if d.Index < 0 || d.Index >= len(vecs) {
			return nil, fmt.Errorf("openai embedding index %d out of range", d.Index)
		}
		vecs[d.Index] = d.Embedding
	}
	for i, v := range vecs {
		if v == nil {
			return nil, fmt.Errorf("openai did not return an embedding for input %d", i)
		}
	}
	return vecs, nil
}

func postJSON(ctx context.Context, hc *http.Client, endpoint string, body []byte, out any) error {
	if _, err := url.Parse(endpoint); err != nil {
		return fmt.Errorf("embedding endpoint %q: %w", endpoint, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("embedding request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("embedding server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode embedding response: %w", err)
	}
	return nil
}
