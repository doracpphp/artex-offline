package knowledge

import (
	"strings"
	"testing"
)

// ATT&CK import: techniques become documents; lookup_technique resolves an id,
// returns its tactics/platforms and the local documents tagged with it; a
// template's ATT&CK tags link it both ways; lookup_cve surfaces the techniques
// its templates map to.
func TestStoreAttackAndLookupTechnique(t *testing.T) {
	s, ctx, done := openTestStore(t)
	defer done()
	pub, priv, _ := GenerateKey()

	// A nuclei template tagged with T1190 (via tags) and the CVE it detects.
	tpl := "id: CVE-2021-41773\ninfo:\n  name: Apache path traversal\n  severity: high\n  tags: [cve, cve2021, t1190, apache]\n  classification:\n    cve-id: CVE-2021-41773\n"
	pack := buildPackFrom(t, priv, PackInput{PackID: "artex-core", Version: "1", KeyID: "test-key",
		Sources: []Source{{Name: "mitre-attack", Version: "v16.1"}}}, map[string]string{
		"attack/enterprise-attack.json":           attackBundle,
		"nvd/recent.json":                         nvdSample,
		"templates/http/cves/CVE-2021-41773.yaml": tpl,
	})
	res, err := s.Import(ctx, pack, trustFor(pub), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Techniques != 2 {
		t.Fatalf("import: %d techniques, want 2", res.Techniques)
	}

	// lookup_technique by id and by a normalisable token.
	for _, q := range []string{"T1190", "t1190", "attack.T1190"} {
		info, ok, err := s.LookupTechnique(ctx, q)
		if err != nil || !ok {
			t.Fatalf("lookup_technique(%q): %v ok=%v", q, err, ok)
		}
		if info.ID != "T1190" || !strings.Contains(info.Name, "Exploit Public-Facing") {
			t.Errorf("technique %q: %+v", q, info)
		}
		if len(info.Tactics) != 1 || info.Tactics[0] != "initial-access" || info.Domain != "enterprise" {
			t.Errorf("technique meta: %+v", info)
		}
		if !strings.Contains(info.Description, "Internet-facing") {
			t.Errorf("technique description: %q", info.Description)
		}
	}

	// The template is linked to T1190 both ways.
	info, _, _ := s.LookupTechnique(ctx, "T1190")
	foundTpl := false
	for _, r := range info.Related {
		if r.Kind == "template" && r.Ref == "CVE-2021-41773" {
			foundTpl = true
		}
	}
	if !foundTpl {
		t.Errorf("T1190 related docs must include the template: %+v", info.Related)
	}

	// A sub-technique resolves, and its parent id reaches it.
	if sub, ok, _ := s.LookupTechnique(ctx, "T1059.001"); !ok || sub.Parent != "T1059" {
		t.Errorf("sub-technique: %+v ok=%v", sub, ok)
	}

	// lookup_cve surfaces the ATT&CK ids its templates map to.
	cve, ok, err := s.LookupCVE(ctx, "CVE-2021-41773")
	if err != nil || !ok {
		t.Fatalf("lookup_cve: %v ok=%v", err, ok)
	}
	tagged := false
	for _, tg := range cve.Techniques {
		if tg.ID == "T1190" && strings.Contains(tg.Name, "Exploit Public-Facing") {
			tagged = true
		}
	}
	if !tagged {
		t.Errorf("lookup_cve must surface the template's ATT&CK technique with its name: %+v", cve.Techniques)
	}

	// An unknown technique with nothing tagged is not found; a bad id errors.
	if _, ok, _ := s.LookupTechnique(ctx, "T4242"); ok {
		t.Error("an unknown technique must not be found")
	}
	if _, _, err := s.LookupTechnique(ctx, "not-an-id"); err == nil {
		t.Error("a non-id must error")
	}
}
