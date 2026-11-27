package knowledge

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Delta packs (docs §4.1). A delta carries base_version, the added and changed
// files, and the deletions. It applies only on top of the active pack of the
// same id at exactly base_version. The importer builds the new version's
// directory from the base directory (hard links, so unchanged files cost no
// copy) plus the delta's files, and indexes the merged set like a full pack, so
// search sees exactly what a full pack of the new version would give.
//
// Every version directory keeps the manifest it was indexed from as
// manifest.json: the signed bytes for a full pack, the merged manifest for a
// delta. kb_packs.manifest_sha256 is the SHA-256 of that file, so a later delta
// can trust the base manifest it reads back from disk.

// storedManifestName is the manifest kept in each version directory. It cannot
// collide with a data file: Validate refuses manifest.json as a file path.
const storedManifestName = ManifestName

// maxStoredManifestBytes caps the stored manifest read back for a delta, like
// ReadManifest caps the one in a pack.
const maxStoredManifestBytes = 64 << 20

// readStoredManifest reads <dir>/manifest.json and checks it against wantSHA,
// the hash recorded in kb_packs when that version was activated.
func readStoredManifest(dir, wantSHA string) (*Manifest, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(storedManifestName)
	if err != nil {
		return nil, fmt.Errorf("the base version has no stored manifest (imported before delta support?): re-import a full pack first: %w", err)
	}
	defer f.Close()
	b, err := readAtMost(f, maxStoredManifestBytes)
	if err != nil {
		return nil, err
	}
	if got := sha256Hex(b); got != wantSHA {
		return nil, fmt.Errorf("the base version's stored manifest does not match its recorded hash (%s != %s); re-import a full pack", got, wantSHA)
	}
	m, err := ParseManifest(b)
	if err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("stored base manifest: %w", err)
	}
	return m, nil
}

// applyDelta completes staging — which holds the delta's own files, already
// verified by extraction — with the base version's unchanged files, and
// returns the merged manifest of the new version. Base files are hard-linked
// (copied where links are not supported); each is checked to be a regular file
// of the size its manifest records.
func applyDelta(baseDir string, base, delta *Manifest, staging string) (*Manifest, error) {
	baseFiles := base.fileByPath()
	deltaFiles := delta.fileByPath()
	deleted := make(map[string]bool, len(delta.Deletions))
	for _, d := range delta.Deletions {
		if _, ok := baseFiles[d]; !ok {
			return nil, fmt.Errorf("delta deletes %q, which is not in base version %s", d, base.Version)
		}
		deleted[d] = true
	}

	merged := &Manifest{
		Format: FormatVersion, Kind: KindKnowledge,
		PackID: delta.PackID, Version: delta.Version, BuiltAt: delta.BuiltAt, KeyID: delta.KeyID,
		Sources: delta.Sources,
	}
	if len(merged.Sources) == 0 {
		merged.Sources = base.Sources
	}
	for p, f := range baseFiles {
		if deleted[p] {
			continue
		}
		if _, replaced := deltaFiles[p]; replaced {
			continue
		}
		if err := linkOrCopy(filepath.Join(baseDir, filepath.FromSlash(p)), filepath.Join(staging, filepath.FromSlash(p)), f.Size); err != nil {
			return nil, fmt.Errorf("carry %s over from base version %s: %w", p, base.Version, err)
		}
		merged.Files = append(merged.Files, f)
	}
	merged.Files = append(merged.Files, delta.Files...)
	sort.Slice(merged.Files, func(i, j int) bool { return merged.Files[i].Path < merged.Files[j].Path })

	// Embedding sets: the base's sets whose file survives unchanged, then the
	// delta's (a delta set for the same path replaces the base one).
	kept := map[string]bool{}
	for _, f := range merged.Files {
		kept[f.Path] = true
	}
	for _, e := range base.Embeddings {
		if _, replaced := deltaFiles[e.Path]; !replaced && kept[e.Path] {
			merged.Embeddings = append(merged.Embeddings, e)
		}
	}
	merged.Embeddings = append(merged.Embeddings, delta.Embeddings...)
	if err := merged.Validate(); err != nil {
		return nil, fmt.Errorf("merged manifest: %w", err)
	}
	return merged, nil
}

// linkOrCopy makes dst the same content as src, a regular file of size bytes:
// a hard link when the filesystem allows it, else a copy. dst must not exist.
func linkOrCopy(src, dst string, size int64) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	if fi.Size() != size {
		return fmt.Errorf("%s is %d bytes, its manifest says %d", src, fi.Size(), size)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// DeltaInput turns a full build input into a delta against base: it keeps only
// the files whose size or SHA-256 differ from base (or are new), lists the base
// files that are gone as deletions, and sets BaseVersion. Embedding files of
// the base are never deleted: they still hold vectors for unchanged chunks.
func DeltaInput(in PackInput, base *Manifest) (PackInput, error) {
	if base.PackID != in.PackID {
		return PackInput{}, fmt.Errorf("base pack id %s differs from %s", base.PackID, in.PackID)
	}
	if base.BaseVersion != "" {
		return PackInput{}, fmt.Errorf("the base must be a full pack, not a delta (build deltas against the last full pack, or against the manifest the importer stored)")
	}
	if CompareVersions(in.Version, base.Version) <= 0 {
		return PackInput{}, fmt.Errorf("version %s must be newer than the base %s", in.Version, base.Version)
	}
	baseFiles := base.fileByPath()
	out := in
	out.BaseVersion = base.Version
	out.Files = map[string]string{}
	for p, src := range in.Files {
		size, sum, err := hashFile(src)
		if err != nil {
			return PackInput{}, err
		}
		if b, ok := baseFiles[p]; ok && b.Size == size && b.SHA256 == sum {
			continue
		}
		out.Files[p] = src
	}
	for p := range baseFiles {
		if _, still := in.Files[p]; still || strings.HasPrefix(p, embeddingsPrefix) {
			continue
		}
		out.Deletions = append(out.Deletions, p)
	}
	sort.Strings(out.Deletions)
	return out, nil
}

// PackManifest reads and parses the manifest of a pack file without verifying
// its signature — for the builder, which reads its own previous pack to build a
// delta. The importer never uses it (VerifyPackFile verifies first).
func PackManifest(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, _, err := ReadManifest(f)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(b)
	if err != nil {
		return nil, err
	}
	return m, m.Validate()
}
