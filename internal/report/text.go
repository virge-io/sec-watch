package report

import (
	"fmt"
	"io"
	"sort"
	"time"

	"sec-watch/internal/cache"
	"sec-watch/internal/scanner"
)

func WriteText(w io.Writer, result *scanner.TrivyResult, s *cache.Status, recentDays int) {
	generated := time.Now().Format("2006-01-02 15:04:05")
	since := time.Now().AddDate(0, 0, -recentDays).Format("2006-01-02")

	fmt.Fprintf(w, "Security dependency report\nGenerated: %s\nProjects: %s\nScanner: trivy\n\n", generated, s.DepReportFile)
	fmt.Fprintf(w, "Summary\nCritical: %d\nHigh: %d\nMedium: %d\nLow: %d\nTotal: %d\nRecent high/critical changes (%d days): %d\n\n",
		s.DepCriticalCount, s.DepHighCount, s.DepMediumCount, s.DepLowCount, s.DepCount, recentDays, s.DepRecentCount)

	fmt.Fprintln(w, "Recent high/critical changes")
	recent := RecentFindings(result, since)
	if len(recent) == 0 {
		fmt.Fprintf(w, "No recent high/critical changes in the last %d days.\n", recentDays)
	} else {
		sort.Slice(recent, func(i, j int) bool {
			if recent[i].Changed != recent[j].Changed {
				return recent[i].Changed > recent[j].Changed
			}
			if recent[i].Rank != recent[j].Rank {
				return recent[i].Rank < recent[j].Rank
			}
			if recent[i].Package != recent[j].Package {
				return recent[i].Package < recent[j].Package
			}
			return recent[i].ID < recent[j].ID
		})
		for i, f := range recent {
			writeBlock(w, i+1, &f, true)
		}
	}

	fmt.Fprintln(w, "\nAll findings")
	all := AllFindings(result)
	if len(all) == 0 {
		fmt.Fprintln(w, "No dependency vulnerabilities found.")
	} else {
		sort.Slice(all, func(i, j int) bool {
			if all[i].Rank != all[j].Rank {
				return all[i].Rank < all[j].Rank
			}
			if all[i].Package != all[j].Package {
				return all[i].Package < all[j].Package
			}
			return all[i].ID < all[j].ID
		})
		for i, f := range all {
			writeBlock(w, i+1, &f, false)
		}
	}
}

func writeBlock(w io.Writer, n int, f *Finding, showChanged bool) {
	fmt.Fprintf(w, "%d. %s %s (CVSS %s)\n", n, f.Severity, f.ID, f.CVSSScoreStr())
	if f.Indirect {
		fmt.Fprintf(w, "   Package: %s %s [indirect]\n", f.Package, f.Installed)
		if f.Fixed != "-" {
			fmt.Fprintf(w, "   Fix: needs %s >= %s\n", f.Package, f.Fixed)
		} else {
			fmt.Fprintf(w, "   Fix: no fixed version known\n")
		}
		if len(f.Via) > 0 {
			for i, ve := range f.Via {
				prefix := "   Via:"
				if i > 0 {
					prefix = "       "
				}
				if ve.Advice != "" {
					fmt.Fprintf(w, "%s %s — %s\n", prefix, ve.Pkg, ve.Advice)
				} else {
					fmt.Fprintf(w, "%s %s\n", prefix, ve.Pkg)
				}
			}
		}
	} else {
		fmt.Fprintf(w, "   Package: %s %s -> %s\n", f.Package, f.Installed, f.Fixed)
	}
	fmt.Fprintf(w, "   Target: %s\n", f.Target)
	if showChanged && f.Changed != "" {
		fmt.Fprintf(w, "   Changed: %s\n", f.Changed)
	}
	fmt.Fprintf(w, "   Attack: vector=%s, complexity=%s, privileges=%s, user_action=%s\n",
		f.AttackVector, f.AttackComplexity, f.Privileges, f.UserInteraction)
	title := f.Title
	if len(title) > 220 {
		title = title[:220]
	}
	fmt.Fprintf(w, "   Title: %s\n", title)
	if f.URL != "" {
		fmt.Fprintf(w, "   URL: %s\n", f.URL)
	}
}
