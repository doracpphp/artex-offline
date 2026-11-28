package knowledge

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MITRE ATT&CK (docs §4 option E, Phase 4). A pack's attack/ prefix holds the
// STIX 2.1 bundles MITRE publishes (enterprise-attack.json, ics-attack.json,
// mobile-attack.json). Each technique becomes a document of kind "technique"
// with its ATT&CK id (T1190, or T1190.001 for a sub-technique) as ext_id, so
// lookup_technique resolves it and other documents can tag it (technique_ids).

// attackPrefix is where ATT&CK STIX bundles live in a pack.
const attackPrefix = "attack/"

// techniqueIDRe matches an ATT&CK technique id: T#### with an optional
// sub-technique (T1059.001). The number is 4+ digits, as MITRE uses.
var techniqueIDRe = regexp.MustCompile(`^T\d{4,}(?:\.\d{3})?$`)

// NormalizeTechniqueID extracts an ATT&CK technique id from a token such as
// "T1190", "t1190", "attack.t1059.001" or "mitre:T1059". ok is false when the
// token is not a technique id.
func NormalizeTechniqueID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	// Keep the last dotted segment pair for sub-techniques: split on separators
	// that are not the sub-technique dot.
	if i := strings.LastIndexAny(s, ":/ "); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimPrefix(strings.ToLower(s), "attack.")
	s = strings.ToUpper(s)
	if techniqueIDRe.MatchString(s) {
		return s, true
	}
	return "", false
}

// Technique is one ATT&CK technique, as the index stores it.
type Technique struct {
	ID          string   // T#### or T####.###
	Name        string   // "Exploit Public-Facing Application"
	Description string   // the technique's prose
	Detection   string   // x_mitre_detection, appended to the searchable body
	Domain      string   // "enterprise" | "ics" | "mobile", from the matrix
	Tactics     []string // kill-chain phase names, e.g. "initial-access"
	Platforms   []string // x_mitre_platforms
	DataSources []string // x_mitre_data_sources
	IsSub       bool     // a sub-technique (T####.###)
	Parent      string   // the parent technique id for a sub-technique
	Deprecated  bool     // revoked or deprecated (skipped on import)
}

// techniqueMeta is the kb_documents.meta shape for a technique.
type techniqueMeta struct {
	Tactics     []string `json:"tactics,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	DataSources []string `json:"data_sources,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Parent      string   `json:"parent,omitempty"`
}

// stixBundle and stixObject cover only the fields ATT&CK techniques use.
type stixBundle struct {
	Objects []json.RawMessage `json:"objects"`
}

type stixObject struct {
	Type            string   `json:"type"`
	Revoked         bool     `json:"revoked"`
	Deprecated      bool     `json:"x_mitre_deprecated"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Detection       string   `json:"x_mitre_detection"`
	IsSubtechnique  bool     `json:"x_mitre_is_subtechnique"`
	Platforms       []string `json:"x_mitre_platforms"`
	DataSources     []string `json:"x_mitre_data_sources"`
	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases"`
	ExternalReferences []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
}

// attackID returns the object's ATT&CK external id (T####), if any.
func (o *stixObject) attackID() string {
	for _, r := range o.ExternalReferences {
		if r.SourceName == "mitre-attack" && r.ExternalID != "" {
			return strings.ToUpper(strings.TrimSpace(r.ExternalID))
		}
	}
	return ""
}

// ParseAttack streams the techniques of a STIX 2.1 bundle to fn. domain names
// the matrix ("enterprise" / "ics" / "mobile"), recorded on each technique and
// used when the bundle's own name does not say. Revoked and deprecated
// techniques are skipped. A bundle that is not JSON is an error; an object that
// is not a usable attack-pattern is ignored.
func ParseAttack(r io.Reader, domain string, fn func(Technique) error) error {
	var b stixBundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return fmt.Errorf("parse STIX bundle: %w", err)
	}
	for _, raw := range b.Objects {
		var o stixObject
		if err := json.Unmarshal(raw, &o); err != nil {
			continue // one malformed object does not sink the bundle
		}
		if o.Type != "attack-pattern" || o.Revoked || o.Deprecated {
			continue
		}
		id := o.attackID()
		if !techniqueIDRe.MatchString(id) {
			continue
		}
		t := Technique{
			ID: id, Name: strings.TrimSpace(o.Name), Description: strings.TrimSpace(o.Description),
			Detection: strings.TrimSpace(o.Detection), Domain: domain,
			Platforms: trimAll(o.Platforms), DataSources: trimAll(o.DataSources),
			IsSub: o.IsSubtechnique,
		}
		if o.IsSubtechnique {
			if i := strings.IndexByte(id, '.'); i > 0 {
				t.Parent = id[:i]
			}
		}
		for _, p := range o.KillChainPhases {
			if strings.Contains(p.KillChainName, "attack") && p.PhaseName != "" {
				t.Tactics = append(t.Tactics, p.PhaseName)
			}
		}
		t.Tactics = dedupe(t.Tactics)
		if err := fn(t); err != nil {
			return err
		}
	}
	return nil
}

// AttackDomain guesses the matrix from a pack file name under attack/.
func AttackDomain(path string) string {
	name := strings.ToLower(path)
	switch {
	case strings.Contains(name, "ics"):
		return "ics"
	case strings.Contains(name, "mobile"):
		return "mobile"
	default:
		return "enterprise"
	}
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
