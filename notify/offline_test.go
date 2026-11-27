package notify

import (
	"os"
	"testing"
)

// In offline mode the delivery dial guard adds a restriction: LAN destinations
// (a relay / local webhook) are allowed while any public IM or mail service is
// refused. Link-local and metadata (incl. IPv6 IMDS) stay blocked, and loopback
// still needs the ARTEX_NOTIFY_ALLOW_LOCAL opt-in — offline mode must not
// loosen the existing SSRF protection.
func TestBlockInternalDialOfflineAddsRestriction(t *testing.T) {
	// The suite TestMain sets ARTEX_NOTIFY_ALLOW_LOCAL=1; clear it so the test
	// relies only on the offline policy, then restore it.
	prevAllow := os.Getenv(AllowLocalTargetsEnv)
	t.Cleanup(func() { _ = os.Setenv(AllowLocalTargetsEnv, prevAllow) })
	_ = os.Setenv(AllowLocalTargetsEnv, "")

	t.Setenv("ARTEX_OFFLINE", "1")

	for _, a := range []string{"192.168.1.10:443", "10.0.0.5:80"} {
		if err := blockInternalDial("tcp", a, nil); err != nil {
			t.Errorf("offline: LAN delivery %s must be allowed: %v", a, err)
		}
	}
	for _, a := range []string{"8.8.8.8:443", "160.79.104.10:443", "169.254.169.254:80", "[fd00:ec2::254]:80", "127.0.0.1:25"} {
		if err := blockInternalDial("tcp", a, nil); err == nil {
			t.Errorf("offline: delivery to %s must be refused (public, metadata, or loopback without opt-in)", a)
		}
	}
	// The loopback opt-in still works in offline mode.
	_ = os.Setenv(AllowLocalTargetsEnv, "1")
	if err := blockInternalDial("tcp", "127.0.0.1:25", nil); err != nil {
		t.Errorf("offline: loopback with the opt-in must be allowed: %v", err)
	}
	if err := blockInternalDial("tcp", "8.8.8.8:443", nil); err == nil {
		t.Error("offline: the loopback opt-in must not re-open public delivery")
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
