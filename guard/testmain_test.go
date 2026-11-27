package guard

import (
	"os"
	"testing"

	"github.com/doracpphp/artex-offline/db"
)

func TestMain(m *testing.M) {
	// Offline mode defaults ON in production; this suite runs install commands
	// through the guard, so default it OFF here. Offline tests opt back in with
	// t.Setenv("ARTEX_OFFLINE", "1").
	os.Setenv("ARTEX_OFFLINE", "0")
	// Own database per package (#80), as in db, agent, server, evidence and intercept.
	db.SuffixTestDatabase("guard")
	os.Exit(m.Run())
}
