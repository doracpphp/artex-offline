package knowledge

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// PackInput describes a pack to build: its identity and the data files to
// include, each a path on disk mapped to the slash path it takes inside the pack.
type PackInput struct {
	PackID  string
	Version string
	KeyID   string
	Sources []Source
	// Files maps an in-pack slash path (e.g. "exploitdb/files_exploits.csv") to
	// the source file on disk.
	Files map[string]string
	// BaseVersion and Deletions make a delta pack (DeltaInput builds them).
	BaseVersion string
	Deletions   []string
	// Embeddings declares precomputed vector files, each also one of Files
	// (BuildEmbeddingFile writes them).
	Embeddings []EmbeddingSet
}

// BuildPack writes a signed knowledge pack to out. It hashes and sizes every
// input file, builds and signs the manifest with priv, and writes the tar.gz:
// manifest.json and manifest.sig first, then the data files in sorted path order
// so a pack is reproducible. priv's public half must correspond to the key the
// importer trusts under KeyID.
func BuildPack(out io.Writer, in PackInput, priv ed25519.PrivateKey) error {
	paths := make([]string, 0, len(in.Files))
	for p := range in.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	files := make([]FileEntry, 0, len(paths))
	for _, p := range paths {
		clean, err := SafePath(p)
		if err != nil {
			return fmt.Errorf("pack path %q: %w", p, err)
		}
		size, sum, err := hashFile(in.Files[p])
		if err != nil {
			return err
		}
		files = append(files, FileEntry{Path: clean, Size: size, SHA256: sum})
	}

	m := &Manifest{
		Format:  FormatVersion,
		Kind:    KindKnowledge,
		PackID:  in.PackID,
		Version: in.Version,
		BuiltAt: time.Now().UTC(),
		KeyID:   in.KeyID,
		Sources: in.Sources,
		Files:   files,

		BaseVersion: in.BaseVersion,
		Deletions:   in.Deletions,
		Embeddings:  in.Embeddings,
	}
	if err := m.Validate(); err != nil {
		return err
	}
	manifestBytes, err := m.Marshal()
	if err != nil {
		return err
	}
	sig := SignManifest(priv, manifestBytes)

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	now := m.BuiltAt
	if err := writeTarFile(tw, ManifestName, manifestBytes, now); err != nil {
		return err
	}
	if err := writeTarFile(tw, SigName, sig, now); err != nil {
		return err
	}
	for i, p := range paths {
		if err := copyTarFile(tw, files[i].Path, in.Files[p], files[i].Size, now); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// BuildPackFile is BuildPack to a path, created or truncated.
func BuildPackFile(path string, in PackInput, priv ed25519.PrivateKey) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := BuildPack(f, in, priv); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func writeTarFile(tw *tar.Writer, name string, data []byte, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: mod, Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func copyTarFile(tw *tar.Writer, name, src string, size int64, mod time.Time) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: size, ModTime: mod, Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	n, err := io.Copy(tw, f)
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("file %q changed size during packing (%d != %d)", src, n, size)
	}
	return nil
}

// GenerateKey returns a new ed25519 key pair for signing packs.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}
