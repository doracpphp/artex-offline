package intercept

import (
	"os"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestMain(m *testing.M) {
	// Offline mode defaults ON in production; this suite dials public test
	// addresses through the ungated dialers, so default it OFF here. Offline
	// tests opt back in with t.Setenv("ARTEX_OFFLINE", "1").
	os.Setenv("ARTEX_OFFLINE", "0")
	// Own database per package (#80), as in db, agent, server and evidence.
	db.SuffixTestDatabase("intercept")
	// A short poll keeps the cross-instance tests fast; production uses 2 s.
	targetPollInterval = 50 * time.Millisecond
	os.Exit(m.Run())
}
