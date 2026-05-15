package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type TrivyResult struct {
	Results []TrivyTarget `json:"Results"`
}

type TrivyTarget struct {
	Target          string            `json:"Target"`
	Type            string            `json:"Type"`
	Vulnerabilities []TrivyVuln       `json:"Vulnerabilities"`
}

type TrivyVuln struct {
	VulnerabilityID  string            `json:"VulnerabilityID"`
	PkgName          string            `json:"PkgName"`
	InstalledVersion string            `json:"InstalledVersion"`
	FixedVersion     string            `json:"FixedVersion"`
	Severity         string            `json:"Severity"`
	Title            string            `json:"Title"`
	Description      string            `json:"Description"`
	PrimaryURL       string            `json:"PrimaryURL"`
	LastModifiedDate string            `json:"LastModifiedDate"`
	PublishedDate    string            `json:"PublishedDate"`
	CVSS             map[string]CVSSEntry `json:"CVSS"`
}

type CVSSEntry struct {
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
	V4Score  float64 `json:"V4Score"`
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
	V4Vector string  `json:"V4Vector"`
}

func (v *TrivyVuln) Date() string {
	d := v.LastModifiedDate
	if d == "" {
		d = v.PublishedDate
	}
	if len(d) >= 10 {
		return d[:10]
	}
	return ""
}

func (v *TrivyVuln) BestCVSS() (score float64, vector string) {
	best := -1.0
	for _, entry := range v.CVSS {
		candidates := []struct {
			s float64
			v string
		}{
			{entry.V4Score, entry.V4Vector},
			{entry.V3Score, entry.V3Vector},
			{entry.V2Score, entry.V2Vector},
		}
		for _, c := range candidates {
			if c.s > best {
				best = c.s
				vector = c.v
			}
		}
	}
	if best < 0 {
		return -1, ""
	}
	return best, vector
}

func (v *TrivyVuln) TitleOrDesc() string {
	if v.Title != "" {
		return v.Title
	}
	return v.Description
}

type TrivyCounts struct {
	Total          int
	Critical       int
	High           int
	Medium         int
	Low            int
	RecentHighCrit int
	RecentCritical int
	RecentHigh     int
}

func CountTrivy(result *TrivyResult, since time.Time) TrivyCounts {
	sinceStr := since.Format("2006-01-02")
	var c TrivyCounts
	for _, target := range result.Results {
		for _, v := range target.Vulnerabilities {
			c.Total++
			switch v.Severity {
			case "CRITICAL":
				c.Critical++
			case "HIGH":
				c.High++
			case "MEDIUM":
				c.Medium++
			case "LOW":
				c.Low++
			}
			if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
				if d := v.Date(); d >= sinceStr {
					c.RecentHighCrit++
					if v.Severity == "CRITICAL" {
						c.RecentCritical++
					} else {
						c.RecentHigh++
					}
				}
			}
		}
	}
	return c
}

func FilterTrivy(result *TrivyResult, ecosystems, projects string) *TrivyResult {
	ecoList := splitCSV(ecosystems)
	projList := splitCSV(projects)

	filtered := &TrivyResult{}
	for _, target := range result.Results {
		if len(ecoList) > 0 && !contains(ecoList, target.Type) {
			continue
		}
		if len(projList) > 0 && !matchesProject(target.Target, projList) {
			continue
		}
		filtered.Results = append(filtered.Results, target)
	}
	return filtered
}

func RunTrivy(projectsDir string) (*TrivyResult, error) {
	if _, err := exec.LookPath("trivy"); err != nil {
		return nil, fmt.Errorf("trivy not found")
	}
	out, err := exec.Command("trivy", "fs", "--scanners", "vuln", "--format", "json", projectsDir).Output()
	if err != nil {
		// trivy exits non-zero when vulns found; try to parse anyway
		if len(out) == 0 {
			return nil, fmt.Errorf("trivy failed: %w", err)
		}
	}
	var result TrivyResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("trivy output parse: %w", err)
	}
	return &result, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func matchesProject(target string, projects []string) bool {
	for _, p := range projects {
		if target == p || strings.HasPrefix(target, p+"/") {
			return true
		}
	}
	return false
}
