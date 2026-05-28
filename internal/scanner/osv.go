package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type OSVResult struct {
	Results []OSVResultItem `json:"results"`
}

type OSVResultItem struct {
	Packages []OSVPackage `json:"packages"`
}

type OSVPackage struct {
	Vulnerabilities []OSVVuln `json:"vulnerabilities"`
}

type OSVVuln struct {
	ID       string            `json:"id"`
	Modified string            `json:"modified"`
	Published string           `json:"published"`
	Severity []OSVSeverity     `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func (v *OSVVuln) SeverityLevel() string {
	if ds, ok := v.DatabaseSpecific["severity"].(string); ok && ds != "" {
		return strings.ToUpper(ds)
	}
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return strings.ToUpper(s.Score)
		}
	}
	return ""
}

func (v *OSVVuln) Date() string {
	d := v.Modified
	if d == "" {
		d = v.Published
	}
	if len(d) >= 10 {
		return d[:10]
	}
	return ""
}

type OSVCounts struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Recent   int
}

func CountOSV(result *OSVResult, since time.Time) OSVCounts {
	sinceStr := since.Format("2006-01-02")
	var c OSVCounts
	for _, r := range result.Results {
		for _, pkg := range r.Packages {
			for _, v := range pkg.Vulnerabilities {
				c.Total++
				switch v.SeverityLevel() {
				case "CRITICAL":
					c.Critical++
				case "HIGH":
					c.High++
				case "MEDIUM":
					c.Medium++
				case "LOW":
					c.Low++
				}
				if d := v.Date(); d >= sinceStr {
					c.Recent++
				}
			}
		}
	}
	return c
}

func RunOSV(projectsDir string) (*OSVResult, error) {
	if _, err := exec.LookPath("osv-scanner"); err != nil {
		return nil, fmt.Errorf("osv-scanner not found")
	}
	out, err := exec.Command("osv-scanner", "scan", "source", "-r", "--format", "json", projectsDir).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("osv-scanner failed: %w", err)
	}
	var result OSVResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("osv-scanner output parse: %w", err)
	}
	return &result, nil
}
