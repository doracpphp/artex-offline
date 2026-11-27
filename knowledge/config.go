package knowledge

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Configuration (docs §6). Deployment switches are environment variables, like
// the rest of ARTEX; the search index and pack files live under the data
// directory.
const (
	// EnabledEnv turns knowledge search off when explicitly falsy. On by default:
	// when a pack is imported the tools work; with no pack they simply return
	// nothing. Same parsing as ARTEX_OFFLINE.
	EnabledEnv = "ARTEX_KNOWLEDGE"
	// DirEnv overrides the directory that holds imported packs (default
	// <dataDir>/knowledge).
	DirEnv = "ARTEX_KNOWLEDGE_DIR"
	// MaxChunksEnv caps the chunks a single search returns (default 8).
	MaxChunksEnv = "ARTEX_KNOWLEDGE_MAX_CHUNKS"
	// MaxChunkBytesEnv caps the bytes of a chunk read/returned (default 4096).
	MaxChunkBytesEnv = "ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES"
)

// Config is the resolved knowledge configuration for a run.
type Config struct {
	Enabled       bool
	Dir           string // absolute; packs extract to <Dir>/<pack-id>/
	MaxChunks     int
	MaxChunkBytes int
}

// LoadConfig resolves the configuration from the environment. dataDir is the
// server's data directory, used for the default pack location.
func LoadConfig(dataDir string) Config {
	c := Config{
		Enabled:       enabledDefaultOn(os.Getenv(EnabledEnv)),
		Dir:           strings.TrimSpace(os.Getenv(DirEnv)),
		MaxChunks:     envInt(MaxChunksEnv, 8, 1, 50),
		MaxChunkBytes: envInt(MaxChunkBytesEnv, 4096, 256, 1<<20),
	}
	if c.Dir == "" {
		c.Dir = filepath.Join(dataDir, "knowledge")
	}
	if abs, err := filepath.Abs(c.Dir); err == nil {
		c.Dir = abs
	}
	return c
}

// PacksDir holds the imported packs' files: <PacksDir>/<pack_id>/<version dir>/,
// one version directory per import (import.go). It is apart from <Dir>/inbox, so
// no pack id can collide with the inbox.
func (c Config) PacksDir() string { return filepath.Join(c.Dir, "packs") }

// packFilesDir resolves a kb_packs.dir value (<pack_id>/<version dir>) to its
// absolute directory under PacksDir. The value comes from the database, so it
// is re-validated rather than trusted: exactly two safe segments, neither
// starting with a dot (which also rules out "." and ".." and staging dirs).
func (c Config) packFilesDir(rel string) (string, error) {
	clean, err := SafePath(rel)
	if err != nil {
		return "", fmt.Errorf("pack directory %q: %w", rel, err)
	}
	segs := strings.Split(clean, "/")
	if len(segs) != 2 || strings.HasPrefix(segs[0], ".") || strings.HasPrefix(segs[1], ".") {
		return "", fmt.Errorf("pack directory %q is not <pack_id>/<version>", rel)
	}
	return filepath.Join(c.PacksDir(), segs[0], segs[1]), nil
}

func enabledDefaultOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

func envInt(name string, def, min, max int) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || n < min || n > max {
		return def
	}
	return n
}
