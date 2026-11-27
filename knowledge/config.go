package knowledge

import (
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

// StagingDir is where a pack extracts before it is activated, so a failed import
// leaves the active pack untouched (docs §4.1).
func (c Config) StagingDir() string { return filepath.Join(c.Dir, ".staging") }

// PackDir is the directory an activated pack's files live under.
func (c Config) PackDir(packID string) string { return filepath.Join(c.Dir, packID) }

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
