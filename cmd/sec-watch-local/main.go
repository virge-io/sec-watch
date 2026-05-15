package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var branchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)

type result struct {
	SourcePath        string `json:"source_path"`
	ScanPath          string `json:"scan_path"`
	Summary           string `json:"summary"`
	Scanner           string `json:"scanner"`
	ProjectTotal      string `json:"project_total"`
	ProjectCritical   string `json:"project_critical"`
	ProjectHigh       string `json:"project_high"`
	ProjectMedium     string `json:"project_medium"`
	ProjectLow        string `json:"project_low"`
	DependencyReport  string `json:"dependency_report"`
	DependencyHTMLReport string `json:"dependency_html_report"`
	ExitCode          int    `json:"exit_code"`
}

type errInput struct{ msg string }

func (e errInput) Error() string { return e.msg }

type errCommand struct{ msg string }

func (e errCommand) Error() string { return e.msg }

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("sec-watch-local", flag.ContinueOnError)
	var (
		branch           = flags.String("branch", "", "Scan a local Git branch through a cached worktree.")
		cacheRoot        = flags.String("cache-root", envOr("SEC_WATCH_LOCAL_CACHE", defaultCacheRoot()), "")
		scannerPath      = flags.String("scanner", envOr("SEC_WATCH_SCANNER", defaultScanner()), "")
		ecosystems       = flags.String("ecosystems", os.Getenv("SEC_WATCH_LOCAL_ECOSYSTEMS"), "")
		publicFeeds      = flags.String("public-feeds", os.Getenv("SEC_WATCH_LOCAL_PUBLIC_FEEDS"), "")
		recentDays       = flags.Int("recent-days", envInt("SEC_WATCH_LOCAL_RECENT_DAYS", 0), "")
		gitTimeout       = flags.Int("git-timeout", envInt("SEC_WATCH_LOCAL_GIT_TIMEOUT", 300), "")
		scanTimeout      = flags.Int("scan-timeout", envInt("SEC_WATCH_LOCAL_SCAN_TIMEOUT", 1800), "")
		progressInterval = flags.Int("progress-interval", envInt("SEC_WATCH_LOCAL_PROGRESS_INTERVAL", 10), "")
		debug            = flags.Bool("debug", false, "")
		asJSON           = flags.Bool("json", false, "")
	)
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}

	progress := func(msg string) {
		if *debug || !*asJSON {
			fmt.Fprintf(os.Stderr, "[sec-watch-local] %s\n", msg)
		}
	}
	dbg := func(msg string) {
		if *debug {
			fmt.Fprintf(os.Stderr, "[sec-watch-local:debug] %s\n", msg)
		}
	}

	scanner := mustAbs(*scannerPath)

	var pathArg string
	if flags.NArg() > 0 {
		pathArg = flags.Arg(0)
	} else {
		progress("Loading scanner defaults to determine projects dir")
		p, err := defaultProjectsDir(scanner, *gitTimeout)
		if err != nil {
			printErr(*asJSON, fmt.Sprintf("cannot determine default path: %v", err))
			return 2
		}
		pathArg = p
	}

	progress(fmt.Sprintf("Validating local path: %s", pathArg))
	sourcePath, err := validateDir(pathArg)
	if err != nil {
		printErr(*asJSON, err.Error())
		return 2
	}

	cacheRootAbs := mustAbs(*cacheRoot)
	runID := utcRunID()
	runDir := filepath.Join(cacheRootAbs, "jobs", runID)
	runCacheDir := filepath.Join(runDir, "cache")
	if err := os.MkdirAll(runCacheDir, 0o755); err != nil {
		printErr(*asJSON, fmt.Sprintf("cannot create run dir: %v", err))
		return 1
	}
	progress(fmt.Sprintf("Run cache: %s", runDir))

	scanPath := sourcePath
	if *branch != "" {
		br, err := validateBranch(*branch)
		if err != nil {
			printErr(*asJSON, err.Error())
			return 2
		}
		progress(fmt.Sprintf("Resolving local Git repo for branch %s", br))
		repoPath, err := gitToplevel(sourcePath, *gitTimeout)
		if err != nil {
			printErr(*asJSON, err.Error())
			return 2
		}
		progress("Updating cached local mirror")
		mirrorDir, err := ensureLocalMirror(cacheRootAbs, repoPath, br, *gitTimeout)
		if err != nil {
			printErr(*asJSON, err.Error())
			return 2
		}
		scanPath = filepath.Join(runDir, "worktree")
		progress(fmt.Sprintf("Checking out branch %s into temporary worktree", br))
		if err := checkoutBranchWorktree(mirrorDir, br, scanPath, *gitTimeout); err != nil {
			printErr(*asJSON, err.Error())
			return 2
		}
	}

	// Build scanner env
	env := os.Environ()
	env = setenv(env, "XDG_CACHE_HOME", runCacheDir)
	env = setenv(env, "SEC_WATCH_PROJECTS_DIR", scanPath)
	env = setenv(env, "SEC_WATCH_PROJECTS", "")
	env = setenv(env, "SEC_WATCH_FORCE", "1")
	if *ecosystems != "" {
		env = setenv(env, "SEC_WATCH_ECOSYSTEMS", *ecosystems)
	}
	if *publicFeeds != "" {
		env = setenv(env, "SEC_WATCH_PUBLIC_FEEDS", *publicFeeds)
	}
	if *recentDays > 0 {
		env = setenv(env, "SEC_WATCH_RECENT_DAYS", fmt.Sprint(*recentDays))
	}

	debugFile := filepath.Join(runDir, "debug.log")
	if *debug {
		env = setenv(env, "SEC_WATCH_DEBUG", "1")
		env = setenv(env, "SEC_WATCH_DEBUG_FILE", debugFile)
		dbg(fmt.Sprintf("debug log: %s", debugFile))
		for _, e := range env {
			if strings.HasPrefix(e, "SEC_WATCH_") || strings.HasPrefix(e, "XDG_CACHE_HOME=") {
				dbg(e)
			}
		}
	}

	progress(fmt.Sprintf("Running scanner on %s", scanPath))

	exitCode, stdout, stderr := runScanner(scanner, env, *scanTimeout, *progressInterval, *debug || !*asJSON, debugFile)

	status := parseStatus(stdout)

	r := result{
		SourcePath:           sourcePath,
		ScanPath:             scanPath,
		Summary:              status["summary"],
		Scanner:              status["scanner"],
		ProjectTotal:         orZero(status["project_total"]),
		ProjectCritical:      orZero(status["project_critical"]),
		ProjectHigh:          orZero(status["project_high"]),
		ProjectMedium:        orZero(status["project_medium"]),
		ProjectLow:           orZero(status["project_low"]),
		DependencyReport:     status["dependency_report"],
		DependencyHTMLReport: status["dependency_html_report"],
		ExitCode:             exitCode,
	}
	progress("Scan finished")

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		printHuman(r)
	}

	if exitCode != 0 && stderr != "" {
		tail := stderr
		if len(tail) > 4000 {
			tail = tail[len(tail)-4000:]
		}
		fmt.Fprint(os.Stderr, tail)
	}
	return exitCode
}

func runScanner(scanner string, env []string, timeout, interval int, showProgress bool, debugFile string) (exitCode int, stdout, stderr string) {
	cmd := exec.Command(scanner, "status")
	cmd.Env = env

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		return 1, "", err.Error()
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			if err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return ee.ExitCode(), outBuf.String(), errBuf.String()
				}
				return 1, outBuf.String(), errBuf.String()
			}
			return 0, outBuf.String(), errBuf.String()
		case t := <-ticker.C:
			if t.After(deadline) {
				_ = cmd.Process.Kill()
				return 1, outBuf.String(), "scanner timed out"
			}
			if showProgress {
				elapsed := int(time.Since(deadline.Add(-time.Duration(timeout) * time.Second)).Seconds())
				fmt.Fprintf(os.Stderr, "[sec-watch-local] Scanner still running... %ds\n", elapsed)
			}
			if debugFile != "" {
				_ = tailDebugFile(debugFile)
			}
		}
	}
}

func tailDebugFile(path string) error {
	// just a no-op placeholder; debug file is written by the scanner itself
	return nil
}

func parseStatus(stdout string) map[string]string {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	m := map[string]string{}
	if len(lines) > 0 {
		m["summary"] = strings.TrimSpace(lines[0])
	}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func printHuman(r result) {
	fmt.Println(orDash(r.Summary, "Scan finished"))
	fmt.Printf("Scanner: %s\n", orDash(r.Scanner, "-"))
	fmt.Printf("Source path: %s\n", r.SourcePath)
	fmt.Printf("Scan path: %s\n", r.ScanPath)
	fmt.Printf("Total: %s\n", r.ProjectTotal)
	fmt.Printf("Critical: %s\n", r.ProjectCritical)
	fmt.Printf("High: %s\n", r.ProjectHigh)
	fmt.Printf("Medium: %s\n", r.ProjectMedium)
	fmt.Printf("Low: %s\n", r.ProjectLow)
	fmt.Printf("HTML report: %s\n", orDash(r.DependencyHTMLReport, "-"))
	fmt.Printf("CLI report: %s\n", orDash(r.DependencyReport, "-"))
}

func printErr(asJSON bool, msg string) {
	if asJSON {
		enc := json.NewEncoder(os.Stderr)
		_ = enc.Encode(map[string]string{"error": msg})
	} else {
		fmt.Fprintf(os.Stderr, "sec-watch-local: %s\n", msg)
	}
}

// --- Git helpers ---

func gitToplevel(path string, timeout int) (string, error) {
	out, err := gitCmd(timeout, "-C", path, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", errInput{"--branch requires PATH to be inside a local Git repository"}
	}
	return filepath.Clean(strings.TrimSpace(out)), nil
}

func sourceCacheKey(path string) string {
	h := sha256.Sum256([]byte(path))
	return fmt.Sprintf("%x", h[:12])
}

func ensureLocalMirror(cacheRoot, sourcePath, branch string, timeout int) (string, error) {
	mirrorDir := filepath.Join(cacheRoot, "repos", sourceCacheKey(sourcePath)+".git")
	if err := os.MkdirAll(filepath.Dir(mirrorDir), 0o755); err != nil {
		return "", err
	}

	if _, err := os.Stat(mirrorDir); os.IsNotExist(err) {
		if _, err := gitCmd(timeout, "clone", "--mirror", sourcePath, mirrorDir); err != nil {
			return "", errCommand{fmt.Sprintf("git clone mirror failed: %v", err)}
		}
	} else {
		if _, err := gitCmd(timeout, "-C", mirrorDir, "remote", "set-url", "origin", sourcePath); err != nil {
			return "", err
		}
		if _, err := gitCmd(timeout, "-C", mirrorDir, "remote", "update", "--prune"); err != nil {
			return "", err
		}
	}

	if !mirrorHasBranch(mirrorDir, branch, timeout) {
		return "", errInput{fmt.Sprintf("branch not found in local repository: %s", branch)}
	}
	return mirrorDir, nil
}

func mirrorHasBranch(mirrorDir, branch string, timeout int) bool {
	_, err := gitCmd(timeout, "-C", mirrorDir, "show-ref", "--verify", "--quiet", "refs/heads/"+branch)
	return err == nil
}

func checkoutBranchWorktree(mirrorDir, branch, worktreeDir string, timeout int) error {
	if err := os.RemoveAll(worktreeDir); err != nil {
		return err
	}
	if _, err := gitCmd(timeout, "clone", "--no-checkout", mirrorDir, worktreeDir); err != nil {
		return err
	}
	ref := fmt.Sprintf("refs/heads/%s:refs/remotes/origin/%s", branch, branch)
	if _, err := gitCmd(timeout, "-C", worktreeDir, "fetch", "origin", ref); err != nil {
		return err
	}
	if _, err := gitCmd(timeout, "-C", worktreeDir, "checkout", "--detach", "refs/remotes/origin/"+branch); err != nil {
		return err
	}
	return nil
}

func gitCmd(timeout int, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes")
	out, err := runWithTimeout(cmd, time.Duration(timeout)*time.Second)
	return string(out), err
}

func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return []byte(outBuf.String()), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("timed out after %s", timeout)
	}
}

// --- Path/env helpers ---

func validateDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errInput{err.Error()}
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return "", errInput{"path must be an existing local directory"}
	}
	return abs, nil
}

func validateBranch(branch string) (string, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return "", errInput{"branch is required"}
	}
	if !branchRE.MatchString(branch) || strings.Contains(branch, "..") ||
		strings.Contains(branch, "//") || strings.HasSuffix(branch, "/") ||
		strings.HasSuffix(branch, ".lock") || strings.Contains(branch, "@{") {
		return "", errInput{"invalid git branch name"}
	}
	return branch, nil
}

func defaultProjectsDir(scanner string, timeout int) (string, error) {
	cmd := exec.Command(scanner, "defaults-env")
	out, err := runWithTimeout(cmd, time.Duration(timeout)*time.Second)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && k == "SEC_WATCH_PROJECTS_DIR" && v != "" {
			return v, nil
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Projects"), nil
}

func defaultCacheRoot() string {
	xdg := os.Getenv("XDG_CACHE_HOME")
	if xdg == "" {
		home, _ := os.UserHomeDir()
		xdg = filepath.Join(home, ".cache")
	}
	return filepath.Join(xdg, "sec-watch-local")
}

func defaultScanner() string {
	self, err := os.Executable()
	if err != nil {
		return "sec-watch"
	}
	return filepath.Join(filepath.Dir(self), "sec-watch")
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func setenv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscan(v, &n); err == nil {
			return n
		}
	}
	return fallback
}

func utcRunID() string {
	return fmt.Sprintf("%s-%d", time.Now().UTC().Format("20060102T150405Z"), os.Getpid())
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func orDash(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
