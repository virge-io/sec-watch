package status

import (
	"fmt"
	"io"
	"os"

	"github.com/virge/sec-watch/internal/cache"
	"github.com/virge/sec-watch/internal/config"
)

const (
	colorGray  = "\033[0;90m"
	colorCyan  = "\033[0;36m"
	colorBold  = "\033[1m"
	colorReset = "\033[0m"
)

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
		key   string
		value string
	}{
		{"project_total", fmt.Sprint(s.DepCount)},
		{"project_critical", fmt.Sprint(s.DepCriticalCount)},
		{"project_high", fmt.Sprint(s.DepHighCount)},
		{"project_medium", fmt.Sprint(s.DepMediumCount)},
		{"project_low", fmt.Sprint(s.DepLowCount)},
		{"project_recent", fmt.Sprint(s.DepRecentCount)},
		{"project_recent_critical", fmt.Sprint(s.DepRecentCritical)},
		{"project_recent_high", fmt.Sprint(s.DepRecentHigh)},
		{"recent_changes", fmt.Sprint(s.RecentChangeCount)},
		{"dependency_report", s.DepReportFile},
		{"dependency_html_report", s.DepHTMLReportFile},
		{"scanner", s.Scanner},
		{"public_feeds", cfg.PublicFeeds},
		{"watch_config", cfg.WatchConfig},
	}

	for _, f := range fields {
		fmt.Fprintf(w, "%s%s=%s%s\n", cyan, f.key, reset, f.value)
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
