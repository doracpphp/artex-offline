package offline

import (
	"net"
	"strings"
	"testing"
)

func TestEnabledDefaultsOn(t *testing.T) {
	t.Setenv(Env, "")
	if !Enabled() {
		t.Fatal("offline mode must default ON when unset/empty")
	}
	for _, v := range []string{"0", "false", "off", "no", "OFF", "False", " no "} {
		t.Setenv(Env, v)
		if Enabled() {
			t.Fatalf("offline mode must be OFF for %q", v)
		}
	}
	for _, v := range []string{"1", "true", "on", "yes", "anything"} {
		t.Setenv(Env, v)
		if !Enabled() {
			t.Fatalf("offline mode must be ON for %q", v)
		}
	}
}

func TestIsLocalIP(t *testing.T) {
	local := []string{
		"127.0.0.1", "::1", "::ffff:127.0.0.1",
		"10.0.0.5", "172.16.3.4", "192.168.1.1", "192.168.65.2", // RFC1918 (incl. docker host gw)
		"fd00::1", // ULA
	}
	for _, s := range local {
		if !IsLocalIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be local", s)
		}
	}
	nonLocal := []string{
		"8.8.8.8", "1.1.1.1", "160.79.104.10", // public
		"169.254.169.254",        // cloud metadata (link-local) must NOT be local
		"169.254.0.1", "fe80::1", // link-local
		"2606:4700:4700::1111", // public v6
	}
	for _, s := range nonLocal {
		if IsLocalIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be non-local", s)
		}
	}
	if IsLocalIP(nil) {
		t.Error("nil IP must not be local")
	}
}

func TestIsLocalHost(t *testing.T) {
	ok := []string{"localhost", "LOCALHOST", "foo.localhost", "host.docker.internal", "127.0.0.1", "[::1]", "192.168.0.10"}
	for _, h := range ok {
		if !IsLocalHost(h) {
			t.Errorf("expected %q to be local host", h)
		}
	}
	bad := []string{"", "api.anthropic.com", "api.openai.com", "example.com", "8.8.8.8", "169.254.169.254", "localhost.evil.com"}
	for _, h := range bad {
		if IsLocalHost(h) {
			t.Errorf("expected %q to be non-local host", h)
		}
	}
}

func TestGuardDial(t *testing.T) {
	t.Setenv(Env, "1")
	if err := GuardDial("tcp", "127.0.0.1:11434", nil); err != nil {
		t.Errorf("local dial must pass: %v", err)
	}
	if err := GuardDial("tcp", "192.168.65.2:3000", nil); err != nil {
		t.Errorf("private dial must pass: %v", err)
	}
	if err := GuardDial("tcp", "8.8.8.8:443", nil); err == nil {
		t.Error("public dial must be refused in offline mode")
	}
	if err := GuardDial("tcp", "169.254.169.254:80", nil); err == nil {
		t.Error("metadata dial must be refused in offline mode")
	}
	// Off: everything passes.
	t.Setenv(Env, "0")
	if err := GuardDial("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("with offline off, public dial must pass: %v", err)
	}
}

func TestCheckEndpointLocal(t *testing.T) {
	t.Setenv(Env, "1")
	good := []string{
		"http://127.0.0.1:11434/v1",
		"http://localhost:11434",
		"http://host.docker.internal:11434/v1",
		"http://192.168.1.50:8080",
		"127.0.0.1:11434",
	}
	for _, u := range good {
		if err := CheckEndpointLocal(u); err != nil {
			t.Errorf("expected %q to be allowed: %v", u, err)
		}
	}
	bad := []string{
		"", // empty -> cloud default, refused
		"https://api.anthropic.com",
		"https://api.openai.com/v1",
		"https://gateway.example.com/v1",
	}
	for _, u := range bad {
		if err := CheckEndpointLocal(u); err == nil {
			t.Errorf("expected %q to be refused", u)
		}
	}
	// Off: everything allowed.
	t.Setenv(Env, "0")
	if err := CheckEndpointLocal("https://api.anthropic.com"); err != nil {
		t.Errorf("with offline off, cloud endpoint must be allowed: %v", err)
	}
	if err := CheckEndpointLocal(""); err != nil {
		t.Errorf("with offline off, empty endpoint must be allowed: %v", err)
	}
}

func TestCheckEndpointErrorMentionsOffline(t *testing.T) {
	t.Setenv(Env, "1")
	err := CheckEndpointLocal("https://api.openai.com")
	if err == nil || !strings.Contains(err.Error(), "offline mode") {
		t.Fatalf("error should mention offline mode, got %v", err)
	}
}
