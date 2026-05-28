package status

import (
	"fmt"
	"io"
	"os"

	"sec-watch/internal/cache"
	"sec-watch/internal/config"
)

const (
	colorGray  = "\033[0;90m"
	colorCyan  = "\033[0;36m"
	colorBold  = "\033[1m"
	colorReset = "\033[0m"
)

func fileLink(path string) string {
	return "\033]8;;file://" + path + "\033\\" + path + "\033]8;;\033\\"
}

func IsTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func Print(w io.Writer, s *cache.Status, cfg *config.Config, tty bool) {
	cyan, bold, reset := "", "", ""
	if tty {
		cyan, bold, reset = colorCyan, colorBold, colorReset
	}

	if tty {
		fmt.Fprintf(w, "%s%s%s\n", bold, s.Summary, reset)
	} else {
		fmt.Fprintln(w, s.Summary)
	}

	fields := []struct {
		key  string
		val  string
		link bool
	}{
		{"project_total", fmt.Sprint(s.DepCount), false},
		{"project_critical", fmt.Sprint(s.DepCriticalCount), false},
		{"project_high", fmt.Sprint(s.DepHighCount), false},
		{"project_medium", fmt.Sprint(s.DepMediumCount), false},
		{"project_low", fmt.Sprint(s.DepLowCount), false},
		{"project_recent", fmt.Sprint(s.DepRecentCount), false},
		{"project_recent_critical", fmt.Sprint(s.DepRecentCritical), false},
		{"project_recent_high", fmt.Sprint(s.DepRecentHigh), false},
		{"recent_changes", fmt.Sprint(s.RecentChangeCount), false},
		{"dependency_report", s.DepReportFile, true},
		{"dependency_html_report", s.DepHTMLReportFile, true},
		{"scanner", s.Scanner, false},
		{"public_feeds", cfg.PublicFeeds, false},
		{"watch_config", cfg.WatchConfig, false},
	}

	for _, f := range fields {
		val := f.val
		if tty && f.link && f.val != "" {
			val = fileLink(f.val)
		}
		fmt.Fprintf(w, "%s%s=%s%s\n", cyan, f.key, reset, val)
	}
}

func PrintDefaultsEnv(w io.Writer, cfg *config.Config) {
	fmt.Fprintf(w, "SEC_WATCH_PROJECTS_DIR=%s\n", cfg.ProjectsDir)
	fmt.Fprintf(w, "SEC_WATCH_PROJECTS=%s\n", cfg.SelectedProjects)
	fmt.Fprintf(w, "SEC_WATCH_ECOSYSTEMS=%s\n", cfg.Ecosystems)
	fmt.Fprintf(w, "SEC_WATCH_PUBLIC_FEEDS=%s\n", cfg.PublicFeeds)
	fmt.Fprintf(w, "SEC_WATCH_TTL=%d\n", cfg.TTLSeconds)
	fmt.Fprintf(w, "SEC_WATCH_RECENT_DAYS=%d\n", cfg.RecentDays)
	fmt.Fprintf(w, "SEC_WATCH_CONFIG=%s\n", cfg.WatchConfig)
}
