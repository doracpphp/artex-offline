package knowledge

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractLimits bound a pack extraction, defending against decompression bombs
// and a pack larger than the disk. Zero fields take the defaults.
type ExtractLimits struct {
	MaxTotalBytes int64 // ceiling on the sum of extracted file sizes (default 8 GiB)
	MaxFiles      int   // ceiling on the number of files (default 200000)
}

func (l ExtractLimits) withDefaults() ExtractLimits {
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = 8 << 30
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = 200000
	}
	return l
}

// ReadManifest reads just manifest.json and manifest.sig from a pack stream and
// returns the raw manifest bytes and the signature, without verifying or parsing.
// The caller verifies (VerifyManifest) and parses (ParseManifest). The data
// files, which in a real pack dwarf these two, are not read.
func ReadManifest(r io.Reader) (manifestBytes, sig []byte, err error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, fmt.Errorf("open pack gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	const maxMeta = 64 << 20 // a manifest or signature over 64 MiB is not real
	for manifestBytes == nil || sig == nil {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read pack: %w", err)
		}
		name := filepath.ToSlash(h.Name)
		switch name {
		case ManifestName:
			if manifestBytes, err = readAtMost(tr, maxMeta); err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", ManifestName, err)
			}
		case SigName:
			if sig, err = readAtMost(tr, maxMeta); err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", SigName, err)
			}
		}
	}
	if manifestBytes == nil {
		return nil, nil, fmt.Errorf("pack has no %s", ManifestName)
	}
	if sig == nil {
		return nil, nil, fmt.Errorf("pack has no %s", SigName)
	}
	return manifestBytes, sig, nil
}

// Extract writes a pack's data files under destDir, having been given the
// already-verified manifest. It streams the archive a second time: for every
// regular-file entry it checks the path is listed in the manifest and safe, that
// its running size and SHA-256 match the manifest, and refuses anything else —
// symlinks, hard links, devices, unlisted files, a path outside destDir. It also
// enforces the limits. On success every manifest file has been written; a file
// the manifest lists but the archive omits is an error. The two metadata entries
// are skipped. destDir must already exist and should be empty.
func Extract(r io.Reader, m *Manifest, destDir string, limits ExtractLimits) error {
	limits = limits.withDefaults()
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	want := m.fileByPath()
	written := make(map[string]bool, len(want))
	var totalBytes int64
	var fileCount int

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open pack gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read pack: %w", err)
		}
		name := filepath.ToSlash(h.Name)
		if name == ManifestName || name == SigName {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue // directories are created as needed from file paths
		case tar.TypeReg, 0: // 0 is the historical regular-file flag (TypeRegA)
			// handled below
		default:
			return fmt.Errorf("pack entry %q has an unsupported type (only regular files and directories are allowed)", h.Name)
		}
		clean, err := SafePath(name)
		if err != nil {
			return fmt.Errorf("pack entry %q: %w", h.Name, err)
		}
		entry, ok := want[clean]
		if !ok {
			return fmt.Errorf("pack entry %q is not listed in the manifest", clean)
		}
		if written[clean] {
			return fmt.Errorf("pack entry %q appears twice", clean)
		}
		if h.Size != entry.Size {
			return fmt.Errorf("pack entry %q is %d bytes, manifest says %d", clean, h.Size, entry.Size)
		}
		fileCount++
		if fileCount > limits.MaxFiles {
			return fmt.Errorf("pack has more than %d files", limits.MaxFiles)
		}
		totalBytes += entry.Size
		if totalBytes > limits.MaxTotalBytes {
			return fmt.Errorf("pack exceeds the %d-byte extraction limit", limits.MaxTotalBytes)
		}
		if err := writeVerified(tr, absDest, clean, entry); err != nil {
			return err
		}
		written[clean] = true
	}
	if len(written) != len(want) {
		for p := range want {
			if !written[p] {
				return fmt.Errorf("pack is missing file %q listed in the manifest", p)
			}
		}
	}
	return nil
}

// writeVerified copies one entry to destDir/clean, checking its SHA-256 against
// the manifest as it goes and never writing more than its declared size. The
// parent directories are created inside destDir; the final path is re-checked to
// be within destDir in case the OS resolved something unexpected.
func writeVerified(r io.Reader, absDest, clean string, entry FileEntry) (err error) {
	target := filepath.Join(absDest, filepath.FromSlash(clean))
	if !withinDir(absDest, target) {
		return fmt.Errorf("pack entry %q resolves outside the destination", clean)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create %q: %w", clean, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	hsh := sha256.New()
	// Copy exactly entry.Size bytes: LimitReader guards against a tar header that
	// lies long, and we separately require the full count to guard against short.
	n, err := io.Copy(io.MultiWriter(f, hsh), io.LimitReader(r, entry.Size))
	if err != nil {
		return fmt.Errorf("write %q: %w", clean, err)
	}
	if n != entry.Size {
		return fmt.Errorf("pack entry %q ended after %d of %d bytes", clean, n, entry.Size)
	}
	if got := hex.EncodeToString(hsh.Sum(nil)); got != entry.SHA256 {
		return fmt.Errorf("pack entry %q hash mismatch: manifest %s, got %s", clean, entry.SHA256, got)
	}
	return nil
}

// withinDir reports whether target is dir itself or lies under it, after
// cleaning. Both are expected absolute.
func withinDir(dir, target string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel == "." || (!strings.HasPrefix(rel, "../") && rel != "..")
}

// VerifyPackFile reads the manifest and signature from a pack file and verifies
// the signature against the trusted keys BEFORE the manifest is parsed
// (VerifyRaw), returning the verified, validated manifest. It reads only the two
// metadata entries, not the data files, so it is cheap to call before deciding
// to import. keys is the trusted key set (production: TrustedKeys; tests pass a
// throwaway key).
func VerifyPackFile(path string, keys map[string]ed25519.PublicKey) (*VerifiedManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	manifestBytes, sig, err := ReadManifest(f)
	if err != nil {
		return nil, err
	}
	return VerifyRaw(keys, manifestBytes, sig)
}

// ExtractPackFile extracts a pack file's data files under destDir, given its
// already-verified manifest. It opens the file a second time (the first pass,
// VerifyPackFile, read only the metadata).
func ExtractPackFile(path string, m *Manifest, destDir string, limits ExtractLimits) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Extract(f, m, destDir, limits)
}

// readAtMost reads up to max bytes, erroring if the source has more.
func readAtMost(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than the %d-byte limit", max)
	}
	return b, nil
}
