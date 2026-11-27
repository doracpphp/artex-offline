package knowledge

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// nuclei-templates (docs §5, option D). A pack's templates/ prefix holds a
// nuclei-templates checkout laid out as in the repository, which is also how the
// image bakes it (/opt/nuclei-templates, NUCLEI_TEMPLATES_DIR): so a template's
// pack path templates/<rel> is <NUCLEI_TEMPLATES_DIR>/<rel> on the image, and a
// search hit can point the agent at a file its local nuclei can run.

// templatesPrefix is where nuclei templates live in a pack.
const templatesPrefix = "templates/"

// NucleiTemplate is the part of a nuclei template the index uses.
type NucleiTemplate struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Tags        []string
	Authors     []string
	CVEs        []string // upper-case CVE ids from classification.cve-id
	CWEs        []string
	Vendor      string // metadata.vendor, when the template names one
	Product     string // metadata.product
}

// nucleiDoc mirrors the template fields read; everything else is ignored.
// Several fields are a string in some templates and a list in others.
type nucleiDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string    `yaml:"name"`
		Author         yamlList  `yaml:"author"`
		Severity       string    `yaml:"severity"`
		Description    string    `yaml:"description"`
		Tags           yamlList  `yaml:"tags"`
		Classification nucleiCls `yaml:"classification"`
		Metadata       yaml.Node `yaml:"metadata"`
	} `yaml:"info"`
}

type nucleiCls struct {
	CVEID yamlList `yaml:"cve-id"`
	CWEID yamlList `yaml:"cwe-id"`
}

// yamlList accepts a scalar ("a, b" — comma separated, as nuclei writes tags and
// authors) or a sequence.
type yamlList []string

func (l *yamlList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		for _, p := range strings.Split(n.Value, ",") {
			if p = strings.TrimSpace(p); p != "" {
				*l = append(*l, p)
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				if v := strings.TrimSpace(c.Value); v != "" {
					*l = append(*l, v)
				}
			}
		}
	}
	return nil
}

var nucleiCVERe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

// ParseNucleiTemplate reads a nuclei template. ok is false when the YAML does
// not parse or has no id: such a file (a workflow helper, a payload list) is
// indexed as plain text instead.
func ParseNucleiTemplate(data []byte) (NucleiTemplate, bool) {
	var d nucleiDoc
	if err := yaml.Unmarshal(data, &d); err != nil || strings.TrimSpace(d.ID) == "" {
		return NucleiTemplate{}, false
	}
	t := NucleiTemplate{
		ID:          strings.TrimSpace(d.ID),
		Name:        strings.TrimSpace(d.Info.Name),
		Severity:    strings.ToLower(strings.TrimSpace(d.Info.Severity)),
		Description: strings.TrimSpace(d.Info.Description),
		Tags:        d.Info.Tags,
		Authors:     d.Info.Author,
	}
	for _, c := range d.Info.Classification.CVEID {
		if c = strings.ToUpper(strings.TrimSpace(c)); nucleiCVERe.MatchString(c) {
			t.CVEs = append(t.CVEs, c)
		}
	}
	for _, c := range d.Info.Classification.CWEID {
		if c = strings.ToUpper(strings.TrimSpace(c)); strings.HasPrefix(c, "CWE-") {
			t.CWEs = append(t.CWEs, c)
		}
	}
	t.CVEs, t.CWEs = dedupe(t.CVEs), dedupe(t.CWEs)
	// metadata is a free-form map; only vendor/product are read.
	if d.Info.Metadata.Kind == yaml.MappingNode {
		c := d.Info.Metadata.Content
		for i := 0; i+1 < len(c); i += 2 {
			if c[i+1].Kind != yaml.ScalarNode {
				continue
			}
			switch c[i].Value {
			case "vendor":
				t.Vendor = strings.ToLower(strings.TrimSpace(c[i+1].Value))
			case "product":
				t.Product = strings.ToLower(strings.TrimSpace(c[i+1].Value))
			}
		}
	}
	return t, true
}

// templateMeta is the kb_documents.meta shape for a nuclei template.
type templateMeta struct {
	TemplateID string   `json:"template_id,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	CWEs       []string `json:"cwes,omitempty"`
}
