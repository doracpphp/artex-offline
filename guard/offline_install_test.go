package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/hook"
	"github.com/doracpphp/artex-offline/offline"
)

func TestOfflineInstallBlock(t *testing.T) {
	t.Setenv(offline.Env, "1")
	t.Setenv(offline.DenyInstallsEnv, "")
	blocked := []string{
		"pip install requests",
		"pip3.11 install -U impacket",
		"python3 -m pip install pwntools",
		"/usr/bin/pip install x",
		"uv pip install httpx",
		"pipx install netexec",
		"cd /tmp && npm install -g wappalyzer",
		"npx some-scanner --target x",
		"go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		"go get github.com/foo/bar",
		"gem install wpscan",
		"cargo install feroxbuster",
		"apt-get -y install gobuster",
		"apt install seclists",
		"sudo yum install nmap",
		"apk add --no-cache socat",
	}
	for _, c := range blocked {
		if !offlineInstallBlock(c) {
			t.Errorf("%q must be refused in offline mode", c)
		}
	}
	allowed := []string{
		"",
		"nmap -sV 10.0.0.5",
		"go install ./cmd/tool",
		"go build ./...",
		"pip list",
		"pip install --no-index --find-links /opt/wheels impacket",
		"npm install --offline",
		"curl http://10.0.0.5/install.php",
		"echo 'apt is not available'",
	}
	for _, c := range allowed {
		if offlineInstallBlock(c) {
			t.Errorf("%q must not be refused", c)
		}
	}

	t.Setenv(offline.DenyInstallsEnv, "0")
	if offlineInstallBlock("pip install requests") {
		t.Error("ARTEX_DENY_INSTALLS=0 must turn the refusal off")
	}
	t.Setenv(offline.DenyInstallsEnv, "")
	t.Setenv(offline.Env, "0")
	if offlineInstallBlock("pip install requests") {
		t.Error("the refusal must be off when offline mode is off")
	}
}

// TestOfflineInstallGuard runs the refusal through both guards' PreToolUse
// hook: the full guard (worker) and the target-only guard (planner, main agent),
// with and without an interceptor.
func TestOfflineInstallGuard(t *testing.T) {
	t.Setenv(offline.Env, "1")
	input, _ := json.Marshal(map[string]string{"command": "pip install requests"})
	for name, g := range map[string]*Guard{"full": New(), "target-only": NewTargetOnly(nil)} {
		res := g.preToolUse(context.Background(), hook.Event{ToolName: "Bash", Input: input})
		if res.Decision != "block" {
			t.Fatalf("%s guard: want a block, got %+v", name, res)
		}
		if !strings.Contains(res.Message, "offline mode") || !strings.Contains(res.Message, "list_tools") {
			t.Errorf("%s guard: the message must explain and point to list_tools: %q", name, res.Message)
		}
	}
	send, _ := json.Marshal(map[string]string{"text": "apt-get install -y gobuster\n"})
	if res := New().preToolUse(context.Background(), hook.Event{ToolName: "shell_send", Input: send}); res.Decision != "block" {
		t.Errorf("an install typed into an interactive shell must be refused, got %+v", res)
	}
	ok, _ := json.Marshal(map[string]string{"command": "nmap -sV 127.0.0.1"})
	if res := New().preToolUse(context.Background(), hook.Event{ToolName: "Bash", Input: ok}); res.Decision == "block" {
		t.Errorf("an ordinary command must pass, got %+v", res)
	}
}
