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
//	    [-exploitdb DIR] [-nvd DIR] [-docs DIR] [-templates DIR]
//	    Assemble the given sources into a signed pack. Each source flag points at
//	    a local directory; its files are placed under the matching pack prefix.
package main

import (
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
      [-exploitdb DIR] [-nvd DIR] [-docs DIR] [-templates DIR]
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
	out := fs.String("out", "", "output pack path (.tar.gz)")
	exploitdb := fs.String("exploitdb", "", "ExploitDB mirror dir (files_exploits.csv + exploits/)")
	nvd := fs.String("nvd", "", "dir of NVD 2.0 JSON snapshot files")
	docs := fs.String("docs", "", "dir of technique docs (markdown)")
	templates := fs.String("templates", "", "dir of nuclei templates (yaml)")
	fs.Parse(args)

	if *keyFile == "" || *keyID == "" || *version == "" || *out == "" {
		return fmt.Errorf("-key, -key-id, -version and -out are required")
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
	if err := add("exploitdb", *exploitdb, any2(true), knowledge.Source{Name: "exploitdb", License: "GPL-2.0 (mixed)"}); err != nil {
		return err
	}
	if err := add("nvd", *nvd, hasExt(".json"), knowledge.Source{Name: "nvd", Version: "NVD 2.0", License: "NVD terms of use"}); err != nil {
		return err
	}
	if err := add("docs", *docs, any2(true), knowledge.Source{Name: "docs"}); err != nil {
		return err
	}
	if err := add("templates", *templates, hasExt(".yaml", ".yml"), knowledge.Source{Name: "nuclei-templates", License: "MIT"}); err != nil {
		return err
	}
	if len(in.Files) == 0 {
		return fmt.Errorf("no source files found; pass at least one of -exploitdb/-nvd/-docs/-templates")
	}

	fmt.Printf("building %s %s (%d files)...\n", in.PackID, in.Version, len(in.Files))
	if err := knowledge.BuildPackFile(*out, in, priv); err != nil {
		return err
	}
	fi, _ := os.Stat(*out)
	fmt.Printf("wrote %s", *out)
	if fi != nil {
		fmt.Printf(" (%d bytes)", fi.Size())
	}
	fmt.Println()
	return nil
}

// collect walks dir and adds each matching file to files under prefix/<relpath>.
func collect(files map[string]string, prefix, dir string, pred func(string) bool) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !pred(path) {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		packPath := prefix + "/" + filepath.ToSlash(rel)
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

func any2(b bool) func(string) bool { return func(string) bool { return b } }

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
