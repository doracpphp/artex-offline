package archivestore

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Offline mode defaults ON in production; this suite configures cloud
	// endpoints, so default it OFF here. Offline tests opt back in with
	// t.Setenv("ARTEX_OFFLINE", "1").
	os.Setenv("ARTEX_OFFLINE", "0")
	os.Exit(m.Run())
}
