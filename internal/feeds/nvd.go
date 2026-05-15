package feeds

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

type nvdFeed struct {
	Vulnerabilities []nvdEntry `json:"vulnerabilities"`
}

type nvdEntry struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string         `json:"id"`
	VulnStatus   string         `json:"vulnStatus"`
	LastModified string         `json:"lastModified"`
	Published    string         `json:"published"`
	Descriptions []nvdDesc      `json:"descriptions"`
	Metrics      nvdMetrics     `json:"metrics"`
}

type nvdDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdMetricEntry `json:"cvssMetricV31"`
	V30 []nvdMetricEntry `json:"cvssMetricV30"`
	V2  []nvdMetricEntry `json:"cvssMetricV2"`
}

type nvdMetricEntry struct {
	CVSSData struct {
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // V2 field location
}

func (e *nvdEntry) date() string {
	d := e.CVE.LastModified
	if d == "" {
		d = e.CVE.Published
	}
	if len(d) >= 10 {
		return d[:10]
	}
	return ""
}

func (e *nvdEntry) searchText() string {
	parts := []string{e.CVE.ID}
	for _, d := range e.CVE.Descriptions {
		parts = append(parts, d.Value)
	}
	return strings.Join(parts, " ")
}

func (e *nvdEntry) isHighOrCritical() bool {
	check := func(sev string) bool {
		s := strings.ToUpper(sev)
		return s == "HIGH" || s == "CRITICAL"
	}
	for _, m := range e.CVE.Metrics.V31 {
		if check(m.CVSSData.BaseSeverity) {
			return true
		}
	}
	for _, m := range e.CVE.Metrics.V30 {
		if check(m.CVSSData.BaseSeverity) {
			return true
		}
	}
	for _, m := range e.CVE.Metrics.V2 {
		if check(m.BaseSeverity) {
			return true
		}
	}
	return false
}

func fetchNVD(ctx context.Context, url string, rx *regexp.Regexp, recentDays int) (count int) {
	data, err := fetchGzip(ctx, url)
	if err != nil {
		return 0
	}
	var feed nvdFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return 0
	}

	since := time.Now().AddDate(0, 0, -recentDays).Format("2006-01-02")

	for _, e := range feed.Vulnerabilities {
		if strings.ToLower(e.CVE.VulnStatus) == "rejected" {
			continue
		}
		if d := e.date(); d < since {
			continue
		}
		if rx != nil && !rx.MatchString(e.searchText()) {
			continue
		}
		if !e.isHighOrCritical() {
			continue
		}
		count++
	}
	return count
}
