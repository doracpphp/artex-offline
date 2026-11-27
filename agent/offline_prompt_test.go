package agent

import (
	"strings"
	"testing"
)

// The knowledge line names tools only the planner and the worker have; the main
// agent and chat must not be told to call them.
func TestOfflineBlockKnowledgeLineOnlyForKnowledgeRoles(t *testing.T) {
	t.Setenv("ARTEX_OFFLINE", "1")
	prevP, prevA := knowledgeProvider, knowledgeAvailable
	t.Cleanup(func() { knowledgeProvider, knowledgeAvailable = prevP, prevA })
	SetKnowledgeProvider(func() KnowledgeStore { return &fakeKnowledge{} }, func() bool { return true })

	if got := offlineBlock(true); !strings.Contains(got, "search_exploits") || !strings.Contains(got, "Offline mode") {
		t.Errorf("planner/worker block must carry the offline rules and the knowledge line: %q", got)
	}
	if got := offlineBlock(false); strings.Contains(got, "search_exploits") || !strings.Contains(got, "Offline mode") {
		t.Errorf("main agent/chat block must carry the offline rules only: %q", got)
	}
	// No active pack: no knowledge line for anyone.
	SetKnowledgeProvider(func() KnowledgeStore { return &fakeKnowledge{} }, func() bool { return false })
	if got := offlineBlock(true); strings.Contains(got, "search_exploits") {
		t.Errorf("without an active pack the knowledge line must be absent: %q", got)
	}
	// Online with no pack: nothing at all.
	t.Setenv("ARTEX_OFFLINE", "0")
	if got := offlineBlock(true); got != "" {
		t.Errorf("online without a pack: want no block, got %q", got)
	}
}
