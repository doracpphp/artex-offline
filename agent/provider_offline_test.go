package agent

import "testing"

func TestValidateOfflineRejectsCloudAllowsLocal(t *testing.T) {
	t.Setenv("ARTEX_OFFLINE", "1")

	local := []Config{
		ConfigFrom("ollama", "", "", "", ""),                          // defaults to 127.0.0.1:11434
		ConfigFrom("ollama", "", "http://127.0.0.1:11434", "", ""),    //
		ConfigFrom("openai", "", "http://127.0.0.1:1234/v1", "k", ""), // Strata-style local OpenAI gateway
		ConfigFrom("anthropic", "", "http://localhost:8080", "k", ""), // Strata-style local Anthropic gateway
		ConfigFrom("openai", "", "http://host.docker.internal:11434", "k", ""),
	}
	for i, c := range local {
		if err := c.ValidateOffline(); err != nil {
			t.Errorf("local config %d (%s) must pass offline validation: %v", i, c.Provider(), err)
		}
	}

	cloud := []Config{
		ConfigFrom("anthropic", "", "", "k", ""), // empty -> api.anthropic.com
		ConfigFrom("openai", "", "", "k", ""),    // empty -> api.openai.com
		ConfigFrom("anthropic", "", "https://api.anthropic.com", "k", ""),
		ConfigFrom("openai", "", "https://api.openai.com/v1", "k", ""),
		ConfigFrom("openai", "", "https://gateway.example.com/v1", "k", ""),
	}
	for i, c := range cloud {
		if err := c.ValidateOffline(); err == nil {
			t.Errorf("cloud config %d (%s / %q) must be refused offline", i, c.Provider(), c.BaseURL)
		}
	}
}

func TestValidateOfflineNoOpWhenDisabled(t *testing.T) {
	t.Setenv("ARTEX_OFFLINE", "0")
	for _, c := range []Config{
		ConfigFrom("anthropic", "", "", "k", ""),
		ConfigFrom("openai", "", "https://api.openai.com/v1", "k", ""),
	} {
		if err := c.ValidateOffline(); err != nil {
			t.Errorf("with offline off, %s must pass: %v", c.Provider(), err)
		}
	}
}

func TestQuotaAwareHTTPClientOfflineProxyGuard(t *testing.T) {
	t.Setenv("ARTEX_OFFLINE", "1")
	// A non-local proxy would let LLM traffic escape the dial guard.
	if _, err := quotaAwareHTTPClient("http://proxy.example.com:8080", "", ""); err == nil {
		t.Error("offline mode must refuse a non-local LLM proxy")
	}
	// A local proxy is allowed.
	if _, err := quotaAwareHTTPClient("http://127.0.0.1:8080", "", ""); err != nil {
		t.Errorf("offline mode must allow a local LLM proxy: %v", err)
	}
	// No proxy is allowed and installs the offline dial guard without error.
	if _, err := quotaAwareHTTPClient("", "", ""); err != nil {
		t.Errorf("offline mode with no proxy must build a client: %v", err)
	}

	t.Setenv("ARTEX_OFFLINE", "0")
	if _, err := quotaAwareHTTPClient("http://proxy.example.com:8080", "", ""); err != nil {
		t.Errorf("with offline off, a public proxy must be allowed: %v", err)
	}
}
