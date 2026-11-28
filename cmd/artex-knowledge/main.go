// Command artex-knowledge builds and signs offline knowledge packs for ARTEX
// (docs/offline-knowledge-search.md). It runs in an ONLINE environment — a CI
// job or a workstation — where the source datasets are collected; the offline
// side only imports the signed pack. The offline environment never runs this.
//
// Usage:
//
//	artex-knowledge keygen [-out key]
//	    Generate an ed25519 signing key. Writes <out>.key (private, base64) and
//	    prints the base64 public key to paste into knowledge/keys.go (embeddedKeys)
//	    or to set as ARTEX_KNOWLEDGE_PUBKEY on the offline side.
//
//	artex-knowledge build -key key.key -key-id artex-knowledge-1 \
//	    -pack-id artex-core -version 2026.11.27 -out pack.tar.gz \
//	    [-exploitdb DIR] [-nvd DIR] [-docs DIR] [-templates DIR -templates-version TAG] [-attack DIR -attack-version TAG] \
//	    [-embed-model M -embed-endpoint URL [-embed-provider ollama|openai] [-chunk-bytes N]] \
//	    [-base PREVIOUS-FULL.tar.gz [-delta-out DELTA.tar.gz]]
//	    Assemble the given sources into a signed pack. Each source flag points at
//	    a local directory; its files are placed under the matching pack prefix.
//	    -embed-* precomputes the chunk vectors and ships them in the pack (the
//	    importer uses them when its embedding model and chunk size match).
//	    -base reuses the previous full pack's vectors for unchanged chunks, and
//	    -delta-out additionally writes a delta pack against it: only the changed
//	    files, the deletions, and the new vectors. Keep every full pack: the next
//	    delta is built against it.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/doracpphp/artex-offline/knowledge"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "build":
		err = build(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `artex-knowledge — build and sign ARTEX offline knowledge packs

  artex-knowledge keygen [-out key]
  artex-knowledge build -key key.key -key-id ID -pack-id ID -version V -out pack.tar.gz \
      [-exploitdb DIR] [-nvd DIR] [-docs DIR] [-templates DIR -templates-version TAG] [-attack DIR -attack-version TAG] \
      [-embed-model M -embed-endpoint URL [-embed-provider ollama|openai] [-chunk-bytes N]] \
      [-base PREVIOUS-FULL.tar.gz [-delta-out DELTA.tar.gz]]
`)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "artex-knowledge", "output base name; writes <out>.key (private)")
	fs.Parse(args)

	pub, priv, err := knowledge.GenerateKey()
	if err != nil {
		return err
	}
	keyFile := *out + ".key"
	if _, err := os.Stat(keyFile); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a signing key", keyFile)
	}
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("private key written to %s (keep it secret, 0600)\n", keyFile)
	fmt.Printf("public key (base64): %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("\nTrust it on the offline side by either:\n")
	fmt.Printf("  - adding it to embeddedKeys in knowledge/keys.go, keyed by your -key-id, or\n")
	fmt.Printf("  - setting ARTEX_KNOWLEDGE_PUBKEY to the base64 above (and ARTEX_KNOWLEDGE_KEY_ID to the key id)\n")
	return nil
}

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	keyFile := fs.String("key", "", "private signing key file (from keygen)")
	keyID := fs.String("key-id", "", "key id recorded in the manifest; must match a trusted key")
	packID := fs.String("pack-id", "artex-core", "pack id (stable across versions)")
	version := fs.String("version", "", "pack version (e.g. 2026.11.27); orders packs of one id")
	out := fs.String("out", "", "output pack path (.tar.gz): the full pack")
	exploitdb := fs.String("exploitdb", "", "ExploitDB mirror dir (files_exploits.csv + exploits/)")
	nvd := fs.String("nvd", "", "dir of NVD 2.0 JSON snapshot files")
	docs := fs.String("docs", "", "dir of technique docs (markdown)")
	templates := fs.String("templates", "", "nuclei-templates checkout (its layout is kept, as in the image)")
	templatesVersion := fs.String("templates-version", "", "release tag of the -templates checkout (e.g. v10.5.1); the importer compares it with the image's")
	attack := fs.String("attack", "", "dir of MITRE ATT&CK STIX bundles (enterprise-attack.json, ics-attack.json, mobile-attack.json)")
	attackVersion := fs.String("attack-version", "", "ATT&CK release recorded in the manifest (e.g. v16.1)")
	base := fs.String("base", "", "previous FULL pack of the same id: reuse its vectors, and with -delta-out build a delta against it")
	deltaOut := fs.String("delta-out", "", "also write a delta pack against -base to this path")
	embedModel := fs.String("embed-model", "", "embedding model to precompute chunk vectors with (e.g. nomic-embed-text); empty = no vectors")
	embedEndpoint := fs.String("embed-endpoint", "", "embedding endpoint (e.g. http://127.0.0.1:11434)")
	embedProvider := fs.String("embed-provider", "ollama", "embedding API: ollama (/api/embed) or openai (/v1/embeddings)")
	embedDigest := fs.String("embed-digest", "", "optional model digest to record with the vectors")
	chunkBytes := fs.Int("chunk-bytes", 4096, "chunk size the vectors are computed for; must equal the importer's ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES")
	fs.Parse(args)

	if *keyFile == "" || *keyID == "" || *version == "" || *out == "" {
		return fmt.Errorf("-key, -key-id, -version and -out are required")
	}
	if *deltaOut != "" && *base == "" {
		return fmt.Errorf("-delta-out needs -base (the previous full pack)")
	}
	priv, err := loadPrivKey(*keyFile)
	if err != nil {
		return err
	}
	in := knowledge.PackInput{
		PackID: *packID, Version: *version, KeyID: *keyID,
		Files: map[string]string{},
	}
	add := func(prefix, dir string, pred func(string) bool, src knowledge.Source) error {
		if dir == "" {
			return nil
		}
		n, err := collect(in.Files, prefix, dir, pred)
		if err != nil {
			return err
		}
		if n > 0 {
			in.Sources = append(in.Sources, src)
		}
		fmt.Printf("  %-10s %5d files from %s\n", prefix, n, dir)
		return nil
	}
	// ExploitDB: only the index and the exploit files it points at (exploits/...),
	// not the mirror's scripts, shellcodes or git metadata.
	if err := add("exploitdb", *exploitdb, exploitDBFile, knowledge.Source{Name: "exploitdb", License: "GPL-2.0 (mixed)"}); err != nil {
		return err
	}
	if err := add("nvd", *nvd, hasExt(".json"), knowledge.Source{Name: "nvd", Version: "NVD 2.0", License: "NVD terms of use"}); err != nil {
		return err
	}
	if err := add("docs", *docs, hasExt(".md", ".markdown", ".txt", ".rst", ".adoc"), knowledge.Source{Name: "docs"}); err != nil {
		return err
	}
	if *templates != "" && *templatesVersion == "" {
		fmt.Println("  note: -templates-version is not set; the importer will warn that the templates version is unknown")
	}
	if err := add("attack", *attack, hasExt(".json"), knowledge.Source{Name: "mitre-attack", Version: *attackVersion, License: "Apache-2.0 / MITRE ATT&CK terms"}); err != nil {
		return err
	}
	if err := add("templates", *templates, hasExt(".yaml", ".yml"), knowledge.Source{Name: "nuclei-templates", Version: *templatesVersion, License: "MIT"}); err != nil {
		return err
	}
	if len(in.Files) == 0 {
		return fmt.Errorf("no source files found; pass at least one of -exploitdb/-nvd/-docs/-templates/-attack")
	}

	// The previous full pack, when given, must be ours: the delta and the reused
	// vectors are only as good as the base they are computed against.
	var baseManifest *knowledge.Manifest
	if *base != "" {
		if baseManifest, err = loadOwnPack(*base, priv); err != nil {
			return err
		}
	}

	// Precomputed vectors: one file for the full pack, and the new vectors only
	// for the delta.
	var vecPath, fullVec, deltaVec string
	var fullSet, deltaSet knowledge.EmbeddingSet
	if *embedModel != "" {
		emb, err := knowledge.NewEmbedder(knowledge.EmbedConfig{Provider: *embedProvider, Model: *embedModel, Endpoint: *embedEndpoint})
		if err != nil {
			return fmt.Errorf("embedding model: %w", err)
		}
		tmp, err := os.MkdirTemp(filepath.Dir(*out), ".artex-vectors-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		fullVec = filepath.Join(tmp, "full.akv")
		if *deltaOut != "" {
			deltaVec = filepath.Join(tmp, "delta.akv")
		}
		fmt.Printf("embedding chunks with %s (chunk size %d)...\n", *embedModel, *chunkBytes)
		fullSet, deltaSet, err = knowledge.BuildEmbeddings(context.Background(), knowledge.EmbedBuild{
			Files: in.Files, ChunkBytes: *chunkBytes, Embedder: emb, Digest: *embedDigest,
			BasePack: *base, FullOut: fullVec, DeltaOut: deltaVec,
			Progress: func(done int) { fmt.Printf("\r  %d vectors", done) },
		})
		fmt.Println()
		if err != nil {
			return err
		}
		vecPath = knowledge.EmbeddingFileName(*embedModel, *version)
		fmt.Printf("  vectors   %5d (dimension %d)\n", fullSet.Count, fullSet.Dimension)
	}

	full := in
	full.Files = copyFiles(in.Files)
	if fullSet.Count > 0 {
		fullSet.Path = vecPath
		full.Files[vecPath] = fullVec
		full.Embeddings = []knowledge.EmbeddingSet{fullSet}
	}
	if err := writePack(*out, full, priv); err != nil {
		return err
	}

	if *deltaOut != "" {
		din := in
		din.Files = copyFiles(in.Files)
		if deltaSet.Count > 0 {
			deltaSet.Path = vecPath
			din.Files[vecPath] = deltaVec
			din.Embeddings = []knowledge.EmbeddingSet{deltaSet}
		}
		delta, err := knowledge.DeltaInput(din, baseManifest)
		if err != nil {
			return fmt.Errorf("delta against %s: %w", *base, err)
		}
		fmt.Printf("delta against %s %s: %d added or changed files, %d deletions\n",
			baseManifest.PackID, baseManifest.Version, len(delta.Files), len(delta.Deletions))
		if err := writePack(*deltaOut, delta, priv); err != nil {
			return err
		}
	}
	return nil
}

// loadOwnPack reads a previous pack's manifest and checks it was signed by the
// key we sign with.
func loadOwnPack(path string, priv ed25519.PrivateKey) (*knowledge.Manifest, error) {
	m, err := knowledge.PackManifest(path)
	if err != nil {
		return nil, fmt.Errorf("base pack %s: %w", path, err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := knowledge.VerifyPackFile(path, map[string]ed25519.PublicKey{m.KeyID: pub}); err != nil {
		return nil, fmt.Errorf("base pack %s is not signed by this key: %w", path, err)
	}
	if m.BaseVersion != "" {
		return nil, fmt.Errorf("base pack %s is a delta; pass the previous FULL pack", path)
	}
	return m, nil
}

func writePack(path string, in knowledge.PackInput, priv ed25519.PrivateKey) error {
	fmt.Printf("building %s %s (%d files)...\n", in.PackID, in.Version, len(in.Files))
	if err := knowledge.BuildPackFile(path, in, priv); err != nil {
		return err
	}
	fi, _ := os.Stat(path)
	fmt.Printf("wrote %s", path)
	if fi != nil {
		fmt.Printf(" (%d bytes)", fi.Size())
	}
	fmt.Println()
	return nil
}

func copyFiles(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// collect walks dir and adds each matching regular file to files under
// prefix/<relpath>. pred gets the slash path relative to dir. Hidden entries
// (.git, .github, editor files) and anything that is not a regular file (a
// symlink, a device) are skipped: a pack carries data, not a checkout.
func collect(files map[string]string, prefix, dir string, pred func(string) bool) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !pred(rel) {
			return nil
		}
		packPath := prefix + "/" + rel
		if _, err := knowledge.SafePath(packPath); err != nil {
			return fmt.Errorf("file %q maps to unsafe pack path: %w", path, err)
		}
		files[packPath] = path
		n++
		return nil
	})
	return n, err
}

func loadPrivKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key is %d bytes, want an ed25519 private key of %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// exploitDBFile selects the ExploitDB index and the exploit files under
// exploits/, which the index's file column names relative to the mirror root.
func exploitDBFile(rel string) bool {
	return rel == "files_exploits.csv" || strings.HasPrefix(rel, "exploits/")
}

func hasExt(exts ...string) func(string) bool {
	return func(p string) bool {
		e := strings.ToLower(filepath.Ext(p))
		for _, want := range exts {
			if e == want {
				return true
			}
		}
		return false
	}
}
