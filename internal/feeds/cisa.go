package feeds

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

type cisaFeed struct {
	Vulnerabilities []cisaEntry `json:"vulnerabilities"`
}

type cisaEntry struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	ShortDescription  string `json:"shortDescription"`
	DateAdded         string `json:"dateAdded"`
}

func (e *cisaEntry) searchText() string {
	return strings.Join([]string{e.CveID, e.VendorProject, e.Product, e.VulnerabilityName, e.ShortDescription}, " ")
}

func fetchCISA(ctx context.Context, url string, rx *regexp.Regexp, recentDays, lookbackDays int) (count, recent int) {
	data, err := fetch(ctx, url)
	if err != nil {
		return 0, 0
	}
	var feed cisaFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return 0, 0
	}

	now := time.Now()
	lookbackSince := now.AddDate(0, 0, -lookbackDays).Format("2006-01-02")
	recentSince := now.AddDate(0, 0, -recentDays).Format("2006-01-02")

	for _, e := range feed.Vulnerabilities {
		date := e.DateAdded
		if date == "" {
			date = "0000-00-00"
		}
		if date < lookbackSince {
			continue
		}
		if rx != nil && !rx.MatchString(e.searchText()) {
			continue
		}
		count++
		if date >= recentSince {
			recent++
		}
	}
	return count, recent
}
