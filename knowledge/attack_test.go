package knowledge

import (
	"strings"
	"testing"
)

func TestNormalizeTechniqueID(t *testing.T) {
	ok := map[string]string{
		"T1190":            "T1190",
		"t1190":            "T1190",
		"attack.t1059.001": "T1059.001",
		"ATTACK.T1059.001": "T1059.001",
		"mitre:T1059":      "T1059",
		" T1021 ":          "T1021",
		"technique/t1486":  "T1486",
	}
	for in, want := range ok {
		if got, valid := NormalizeTechniqueID(in); !valid || got != want {
			t.Errorf("NormalizeTechniqueID(%q) = %q,%v; want %q", in, got, valid, want)
		}
	}
	for _, bad := range []string{"", "apache", "cve-2021-1", "T12", "T1190.1", "TA0001", "lfi", "1190"} {
		if got, valid := NormalizeTechniqueID(bad); valid {
			t.Errorf("NormalizeTechniqueID(%q) = %q, should be invalid", bad, got)
		}
	}
}

const attackBundle = `{
  "type": "bundle",
  "objects": [
    {"type": "attack-pattern", "name": "Exploit Public-Facing Application",
     "description": "Adversaries may exploit a weakness in an Internet-facing host.",
     "x_mitre_detection": "Monitor application logs for abnormal behavior.",
     "x_mitre_platforms": ["Windows", "Linux", "macOS"],
     "x_mitre_data_sources": ["Application Log: Application Log Content"],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]},
    {"type": "attack-pattern", "name": "PowerShell", "x_mitre_is_subtechnique": true,
     "description": "Adversaries may abuse PowerShell.",
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]},
    {"type": "attack-pattern", "name": "Revoked", "revoked": true,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
    {"type": "attack-pattern", "name": "Deprecated", "x_mitre_deprecated": true,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T9998"}]},
    {"type": "attack-pattern", "name": "No ATT&CK id",
     "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"}]},
    {"type": "x-mitre-tactic", "name": "Initial Access",
     "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}]},
    {"type": "relationship", "relationship_type": "subtechnique-of"}
  ]
}`

func TestParseAttack(t *testing.T) {
	var got []Technique
	if err := ParseAttack(strings.NewReader(attackBundle), "enterprise", func(tc Technique) error {
		got = append(got, tc)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d techniques (want 2: revoked/deprecated/non-attack skipped): %+v", len(got), got)
	}
	a := got[0]
	if a.ID != "T1190" || a.Name != "Exploit Public-Facing Application" || a.Domain != "enterprise" {
		t.Errorf("T1190: %+v", a)
	}
	if len(a.Tactics) != 1 || a.Tactics[0] != "initial-access" || len(a.Platforms) != 3 || len(a.DataSources) != 1 {
		t.Errorf("T1190 fields: %+v", a)
	}
	if !strings.Contains(a.Detection, "abnormal behavior") {
		t.Errorf("T1190 detection: %q", a.Detection)
	}
	sub := got[1]
	if sub.ID != "T1059.001" || !sub.IsSub || sub.Parent != "T1059" {
		t.Errorf("sub-technique: %+v", sub)
	}
	// A bundle that is not JSON is an error.
	if err := ParseAttack(strings.NewReader("{bad"), "enterprise", func(Technique) error { return nil }); err == nil {
		t.Error("malformed bundle must error")
	}
}

func TestAttackDomain(t *testing.T) {
	for path, want := range map[string]string{
		"attack/enterprise-attack.json": "enterprise",
		"attack/ics-attack.json":        "ics",
		"attack/mobile-attack.json":     "mobile",
		"attack/bundle.json":            "enterprise",
	} {
		if got := AttackDomain(path); got != want {
			t.Errorf("AttackDomain(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestNucleiTemplateTechniqueTags(t *testing.T) {
	tpl := "id: x\ninfo:\n  name: X\n  tags: [cve, t1190, attack.t1059.001, apache, lfi]\n"
	m, ok := ParseNucleiTemplate([]byte(tpl))
	if !ok {
		t.Fatal("must parse")
	}
	if len(m.TechniqueIDs) != 2 || m.TechniqueIDs[0] != "T1190" || m.TechniqueIDs[1] != "T1059.001" {
		t.Errorf("technique tags: %v", m.TechniqueIDs)
	}
}
