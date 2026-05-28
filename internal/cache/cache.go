package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Status struct {
	UpdatedAt           int64  `json:"updated_at"`
	Scanner             string `json:"scanner"`
	Summary             string `json:"summary"`
	DepCount            int    `json:"dep_count"`
	DepCriticalCount    int    `json:"dep_critical_count"`
	DepHighCount        int    `json:"dep_high_count"`
	DepMediumCount      int    `json:"dep_medium_count"`
	DepLowCount         int    `json:"dep_low_count"`
	DepHighCritical     int    `json:"dep_high_critical"`
	DepRecentCount      int    `json:"dep_recent_count"`
	DepRecentCritical   int    `json:"dep_recent_critical"`
	DepRecentHigh       int    `json:"dep_recent_high"`
	WatchCount          int    `json:"watch_count"`
	CisaKevCount        int    `json:"cisa_kev_count"`
	CisaKevRecentCount  int    `json:"cisa_kev_recent_count"`
	NvdRecentCount      int    `json:"nvd_recent_count"`
	RecentChangeCount   int    `json:"recent_change_count"`
	DepReportFile       string `json:"dep_report_file"`
	DepHTMLReportFile   string `json:"dep_html_report_file"`
}

func Read(cacheDir string) (*Status, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, "status.json"))
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func Write(cacheDir string, s *Status) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cacheDir, "status.json"), data, 0o644)
}
