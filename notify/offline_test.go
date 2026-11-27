package notify

import (
	"os"
	"testing"
)

// In offline mode the delivery dial guard inverts: local destinations are
// allowed (a LAN relay / local webhook) while any public IM or mail service is
// refused. Link-local, including the cloud metadata endpoint, stays blocked.
func TestBlockInternalDialOfflineInversion(t *testing.T) {
	// The suite TestMain sets ARTEX_NOTIFY_ALLOW_LOCAL=1; clear it so the test
	// relies only on the offline policy, then restore it.
	prevAllow := os.Getenv(AllowLocalTargetsEnv)
	t.Cleanup(func() { _ = os.Setenv(AllowLocalTargetsEnv, prevAllow) })
	_ = os.Setenv(AllowLocalTargetsEnv, "")

	t.Setenv("ARTEX_OFFLINE", "1")

	localOK := []string{"127.0.0.1:25", "192.168.1.10:443", "10.0.0.5:80"}
	for _, a := range localOK {
		if err := blockInternalDial("tcp", a, nil); err != nil {
			t.Errorf("offline: local delivery %s must be allowed: %v", a, err)
		}
	}
	publicBlocked := []string{"8.8.8.8:443", "160.79.104.10:443", "169.254.169.254:80"}
	for _, a := range publicBlocked {
		if err := blockInternalDial("tcp", a, nil); err == nil {
			t.Errorf("offline: public/metadata delivery %s must be refused", a)
		}
	}
}

func TestBlockInternalDialOnlineUnchanged(t *testing.T) {
	t.Setenv("ARTEX_OFFLINE", "0")
	prevAllow := os.Getenv(AllowLocalTargetsEnv)
	t.Cleanup(func() { _ = os.Setenv(AllowLocalTargetsEnv, prevAllow) })

	// Online default (escape hatch closed): loopback blocked, public allowed.
	_ = os.Setenv(AllowLocalTargetsEnv, "")
	if err := blockInternalDial("tcp", "127.0.0.1:25", nil); err == nil {
		t.Error("online default must block loopback delivery")
	}
	if err := blockInternalDial("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("online default must allow public delivery: %v", err)
	}
}
