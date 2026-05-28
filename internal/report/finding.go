package report

import (
	"fmt"
	"math"
	"strings"

	"sec-watch/internal/scanner"
)

// ViaEntry holds one direct-dep ancestor that pulls in a vulnerable transitive dep.
type ViaEntry struct {
	Pkg    string // "name version" human-readable
	Advice string // from registry lookup, may be ""
}

type Finding struct {
	Rank               int
	Severity           string
	Package            string
	Installed          string
	Fixed              string
	Target             string
	ID                 string
	URL                string
	Title              string
	CVSSScore          float64
	CVSSVector         string
	AttackVector       string
	AttackVectorRank   int
	AttackComplexity   string
	AttackComplexRank  int
	Privileges         string
	PrivilegesRank     int
	UserInteraction    string
	UserInteractRank   int
	Changed            string // only for recent mode
	Indirect           bool
	Via                []ViaEntry
}

func (f *Finding) CVSSScoreStr() string {
	if f.CVSSScore < 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f", f.CVSSScore)
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

func metric(vector, key string) string {
	for _, part := range strings.Split(vector, "/") {
		if strings.HasPrefix(part, key+":") {
			return strings.TrimPrefix(part, key+":")
		}
	}
	return ""
}

func attackVectorLabel(code string) string {
	switch code {
	case "N":
		return "Network"
	case "A":
		return "Adjacent"
	case "L":
		return "Local"
	case "P":
		return "Physical"
	default:
		return "-"
	}
}
func attackVectorRank(code string) int {
	switch code {
	case "N":
		return 0
	case "A":
		return 1
	case "L":
		return 2
	case "P":
		return 3
	default:
		return 9
	}
}

func complexityLabel(code string) string {
	switch code {
	case "L":
		return "Low"
	case "M":
		return "Medium"
	case "H":
		return "High"
	default:
		return "-"
	}
}
func complexityRank(code string) int {
	switch code {
	case "L":
		return 0
	case "M":
		return 1
	case "H":
		return 2
	default:
		return 9
	}
}

func privilegeLabel(code string) string {
	switch code {
	case "N":
		return "None"
	case "L":
		return "Low"
	case "H":
		return "High"
	default:
		return "-"
	}
}
func privilegeRank(code string) int {
	switch code {
	case "N":
		return 0
	case "L":
		return 1
	case "H":
		return 2
	default:
		return 9
	}
}

func authLabel(code string) string {
	switch code {
	case "N":
		return "Auth: None"
	case "S":
		return "Auth: Single"
	case "M":
		return "Auth: Multiple"
	default:
		return "-"
	}
}
func authRank(code string) int {
	switch code {
	case "N":
		return 0
	case "S":
		return 1
	case "M":
		return 2
	default:
		return 9
	}
}

func interactionLabel(code string) string {
	switch code {
	case "N":
		return "None"
	case "R":
		return "Required"
	case "P":
		return "Passive"
	case "A":
		return "Active"
	default:
		return "-"
	}
}
func interactionRank(code string) int {
	switch code {
	case "N":
		return 0
	case "P":
		return 1
	case "R":
		return 2
	case "A":
		return 3
	default:
		return 9
	}
}

func MakeFinding(v *scanner.TrivyVuln, target string) Finding {
	score, vec := v.BestCVSS()
	av := metric(vec, "AV")
	ac := metric(vec, "AC")
	pr := metric(vec, "PR")
	au := metric(vec, "Au")
	ui := metric(vec, "UI")

	privLabel := privilegeLabel(pr)
	privRank := privilegeRank(pr)
	if pr == "" {
		privLabel = authLabel(au)
		privRank = authRank(au)
	}

	title := strings.Join(strings.Fields(v.TitleOrDesc()), " ")
	fixed := v.FixedVersion
	if fixed == "" {
		fixed = "-"
	}
	installed := v.InstalledVersion
	if installed == "" {
		installed = "-"
	}

	via := make([]ViaEntry, len(v.Via))
	for i, vk := range v.Via {
		name, ver, _ := strings.Cut(vk, "@")
		advice := ""
		if i < len(v.ParentFixes) {
			// ParentFixes entries are "name ver — advice" or "name ver"; strip the "name ver — " prefix.
			pf := v.ParentFixes[i]
			prefix := name + " " + ver + " — "
			if strings.HasPrefix(pf, prefix) {
				advice = strings.TrimPrefix(pf, prefix)
			}
		}
		via[i] = ViaEntry{Pkg: name + " " + ver, Advice: advice}
	}

	return Finding{
		Rank:              severityRank(v.Severity),
		Severity:          v.Severity,
		Package:           v.PkgName,
		Installed:         installed,
		Fixed:             fixed,
		Target:            target,
		ID:                v.VulnerabilityID,
		URL:               v.PrimaryURL,
		Title:             title,
		CVSSScore:         math.Round(score*10) / 10,
		CVSSVector:        vec,
		AttackVector:      attackVectorLabel(av),
		AttackVectorRank:  attackVectorRank(av),
		AttackComplexity:  complexityLabel(ac),
		AttackComplexRank: complexityRank(ac),
		Privileges:        privLabel,
		PrivilegesRank:    privRank,
		UserInteraction:   interactionLabel(ui),
		UserInteractRank:  interactionRank(ui),
		Indirect:          v.PkgRelationship == "indirect",
		Via:               via,
	}
}

func AllFindings(result *scanner.TrivyResult) []Finding {
	var out []Finding
	for _, target := range result.Results {
		for i := range target.Vulnerabilities {
			out = append(out, MakeFinding(&target.Vulnerabilities[i], target.Target))
		}
	}
	return out
}

func RecentFindings(result *scanner.TrivyResult, since string) []Finding {
	var out []Finding
	for _, target := range result.Results {
		for i := range target.Vulnerabilities {
			v := &target.Vulnerabilities[i]
			if v.Severity != "CRITICAL" && v.Severity != "HIGH" {
				continue
			}
			d := v.Date()
			if d < since {
				continue
			}
			f := MakeFinding(v, target.Target)
			f.Changed = d
			out = append(out, f)
		}
	}
	return out
}
