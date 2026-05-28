package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"sec-watch/internal/cache"
	"sec-watch/internal/config"
	"sec-watch/internal/feeds"
	"sec-watch/internal/report"
	"sec-watch/internal/scanner"
	"sec-watch/internal/status"
)

func main() {
	cmd := "status"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	cfg := config.Load()

	var debugLog *log.Logger
	if cfg.Debug {
		var dbgW *os.File
		if cfg.DebugFile != "" {
			if err := os.MkdirAll(filepath.Dir(cfg.DebugFile), 0o755); err == nil {
				dbgW, _ = os.OpenFile(cfg.DebugFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			}
		}
		if dbgW != nil {
			debugLog = log.New(io.MultiWriter(os.Stderr, dbgW), "[sec-watch] ", 0)
		} else {
			debugLog = log.New(os.Stderr, "[sec-watch] ", 0)
		}
	}

	debug := func(msg string) {
		if debugLog != nil {
			debugLog.Println(msg)
		}
	}

	switch cmd {
	case "defaults-env":
		status.PrintDefaultsEnv(os.Stdout, cfg)
	case "status":
		runStatus(cfg, debug)
	case "help", "-h", "--help":
		fmt.Fprintln(os.Stderr, "Usage: sec-watch [status|defaults-env]")
	default:
		fmt.Fprintln(os.Stderr, "Usage: sec-watch [status|defaults-env]")
		os.Exit(2)
	}
}

func runStatus(cfg *config.Config, debug func(string)) {
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "sec-watch: cannot create cache dir: %v\n", err)
		os.Exit(1)
	}

	now := time.Now().Unix()
	var s *cache.Status

	cached, err := cache.Read(cfg.CacheDir)
	if err == nil && !cfg.Force && cached.UpdatedAt > 0 && now-cached.UpdatedAt < int64(cfg.TTLSeconds) {
		debug("using cached status")
		s = cached
	} else {
		debug("starting fresh scan")
		s = performScan(cfg, debug)
		s.UpdatedAt = now
		s.DepHighCritical = s.DepCriticalCount + s.DepHighCount
		s.RecentChangeCount = s.DepRecentCount + s.CisaKevRecentCount + s.NvdRecentCount
		s.WatchCount = s.CisaKevCount + s.NvdRecentCount
		s.Summary = fmt.Sprintf("Projects high/critical: %d, Watch: %d, Recent: %d",
			s.DepHighCritical, s.WatchCount, s.RecentChangeCount)
		if werr := cache.Write(cfg.CacheDir, s); werr != nil {
			debug(fmt.Sprintf("cache write failed: %v", werr))
		}
	}

	// ensure consistency
	s.DepHighCritical = s.DepCriticalCount + s.DepHighCount
	s.Summary = fmt.Sprintf("Projects high/critical: %d, Watch: %d, Recent: %d",
		s.DepHighCritical, s.WatchCount, s.RecentChangeCount)

	tty := status.IsTTY(os.Stdout)
	status.Print(os.Stdout, s, cfg, tty)
}

func performScan(cfg *config.Config, debug func(string)) *cache.Status {
	s := &cache.Status{
		Scanner:         "none",
		DepReportFile:   filepath.Join(cfg.CacheDir, "dependency-report.txt"),
		DepHTMLReportFile: filepath.Join(cfg.CacheDir, "dependency-report.html"),
	}

	depJSONFile := filepath.Join(cfg.CacheDir, "dependency-report.json")

	if info, err := os.Stat(cfg.ProjectsDir); err == nil && info.IsDir() {
		debug("running dependency scanner")
		s = runDependencyScanner(cfg, s, depJSONFile, debug)
	} else {
		debug(fmt.Sprintf("projects directory missing: %s", cfg.ProjectsDir))
	}

	if _, err := os.Stat(cfg.WatchConfig); err == nil {
		debug("checking public watch feeds")
		runWatchFeeds(cfg, s, debug)
	} else {
		debug("watch config not found, skipping feeds")
	}

	return s
}

func runDependencyScanner(cfg *config.Config, s *cache.Status, depJSONFile string, debug func(string)) *cache.Status {
	since := time.Now().AddDate(0, 0, -cfg.RecentDays)

	// Try trivy first, then osv-scanner
	trivyResult, err := scanner.RunTrivy(cfg.ProjectsDir)
	if err == nil {
		debug("trivy scan complete, filtering results")
		trivyResult = scanner.FilterTrivy(trivyResult, cfg.Ecosystems, cfg.SelectedProjects)

		if cfg.RegistryLookup {
			debug("enriching parent fix info from registries")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			scanner.EnrichParentFixes(ctx, trivyResult)
		}

		raw, _ := json.MarshalIndent(trivyResult, "", "  ")
		_ = os.WriteFile(depJSONFile, raw, 0o644)

		counts := scanner.CountTrivy(trivyResult, since)
		s.Scanner = "trivy"
		s.DepCount = counts.Total
		s.DepCriticalCount = counts.Critical
		s.DepHighCount = counts.High
		s.DepMediumCount = counts.Medium
		s.DepLowCount = counts.Low
		s.DepRecentCount = counts.RecentHighCrit
		s.DepRecentCritical = counts.RecentCritical
		s.DepRecentHigh = counts.RecentHigh
		debug(fmt.Sprintf("trivy: total=%d critical=%d high=%d", counts.Total, counts.Critical, counts.High))

		writeReports(cfg, s, trivyResult, debug)
		return s
	}

	debug(fmt.Sprintf("trivy unavailable (%v), trying osv-scanner", err))

	osvResult, err := scanner.RunOSV(cfg.ProjectsDir)
	if err == nil {
		raw, _ := json.MarshalIndent(osvResult, "", "  ")
		_ = os.WriteFile(depJSONFile, raw, 0o644)

		counts := scanner.CountOSV(osvResult, since)
		s.Scanner = "osv-scanner"
		s.DepCount = counts.Total
		s.DepCriticalCount = counts.Critical
		s.DepHighCount = counts.High
		s.DepMediumCount = counts.Medium
		s.DepLowCount = counts.Low
		s.DepRecentCount = counts.Recent
		debug(fmt.Sprintf("osv-scanner: total=%d critical=%d high=%d", counts.Total, counts.Critical, counts.High))

		writeOSVReport(cfg, s, depJSONFile)
		return s
	}

	debug("no dependency scanner found")
	return s
}

func writeReports(cfg *config.Config, s *cache.Status, result *scanner.TrivyResult, debug func(string)) {
	debug("writing text report")
	var buf bytes.Buffer
	report.WriteText(&buf, result, s, cfg.RecentDays)
	// inject the correct path into the report header
	_ = os.WriteFile(s.DepReportFile, buf.Bytes(), 0o644)

	debug("writing HTML report")
	var htmlBuf bytes.Buffer
	if err := report.WriteHTML(&htmlBuf, result, s, cfg.ProjectsDir); err == nil {
		_ = os.WriteFile(s.DepHTMLReportFile, htmlBuf.Bytes(), 0o644)
	}
}

func writeOSVReport(cfg *config.Config, s *cache.Status, depJSONFile string) {
	content := fmt.Sprintf(`Security dependency report
Generated: %s
Projects: %s
Scanner: %s

Summary
Critical: %d
High: %d
Medium: %d
Low: %d
Total: %d

Raw JSON: %s

Tip: jless %s
`,
		time.Now().Format("2006-01-02 15:04:05"),
		cfg.ProjectsDir,
		s.Scanner,
		s.DepCriticalCount,
		s.DepHighCount,
		s.DepMediumCount,
		s.DepLowCount,
		s.DepCount,
		depJSONFile,
		depJSONFile,
	)
	_ = os.WriteFile(s.DepReportFile, []byte(content), 0o644)
}

func runWatchFeeds(cfg *config.Config, s *cache.Status, debug func(string)) {
	watchCfg, err := feeds.LoadWatchConfig(cfg.WatchConfig)
	if err != nil {
		debug(fmt.Sprintf("watch config load failed: %v", err))
		return
	}

	rx, err := feeds.KeywordsRegex(watchCfg.Keywords)
	if err != nil || rx == nil {
		debug("no keywords configured")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	lookback := watchCfg.LookbackDays

	counts := feeds.FetchAll(
		ctx,
		config.CisaKevURL,
		config.NvdRecentURL,
		cfg.FeedEnabled("cisa-kev"),
		cfg.FeedEnabled("nvd-recent"),
		rx,
		cfg.RecentDays,
		lookback,
	)

	s.CisaKevCount = counts.CisaKevCount
	s.CisaKevRecentCount = counts.CisaKevRecentCount
	s.NvdRecentCount = counts.NvdRecentCount
	debug(fmt.Sprintf("feeds: cisa=%d nvd=%d", counts.CisaKevCount, counts.NvdRecentCount))
}
