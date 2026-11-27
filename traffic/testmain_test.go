package traffic

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Offline mode defaults ON in production; this suite relays to public test
	// addresses and upstream proxies, so default it OFF here. Offline tests opt
	// back in with t.Setenv("ARTEX_OFFLINE", "1").
	os.Setenv("ARTEX_OFFLINE", "0")
	os.Exit(m.Run())
}
