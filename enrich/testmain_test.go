package enrich

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestMain(m *testing.M) {
	// Offline mode defaults ON in production; this suite probes test
	// addresses through the ungated dialer, so default it OFF here.
	os.Setenv("ARTEX_OFFLINE", "0")
	db.SuffixTestDatabase("enrich")
	os.Exit(m.Run())
}
