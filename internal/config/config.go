package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	DefaultEcosystems  = "npm,yarn,pnpm,pip,poetry,uv,python-pkg"
	DefaultPublicFeeds = "cisa-kev,nvd-recent"
	DefaultTTL         = 1800
	DefaultRecentDays  = 7
	DefaultLookback    = 14

	CisaKevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	NvdRecentURL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz"
)

type Config struct {
	ProjectsDir     string
	SelectedProjects string
	Ecosystems      string
	PublicFeeds     string
	TTLSeconds      int
	RecentDays      int
	WatchConfig     string
	CacheDir        string
	Force           bool
	Debug           bool
	DebugFile       string
}

func Load() *Config {
	c := &Config{}

	home, _ := os.UserHomeDir()

	xdgCache := os.Getenv("XDG_CACHE_HOME")
	if xdgCache == "" {
		xdgCache = filepath.Join(home, ".cache")
	}
	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}

	c.ProjectsDir = envOr("SEC_WATCH_PROJECTS_DIR", filepath.Join(home, "Projects"))
	c.SelectedProjects = os.Getenv("SEC_WATCH_PROJECTS")
	c.Ecosystems = envOr("SEC_WATCH_ECOSYSTEMS", DefaultEcosystems)
	c.PublicFeeds = envOr("SEC_WATCH_PUBLIC_FEEDS", DefaultPublicFeeds)
	c.TTLSeconds = envInt("SEC_WATCH_TTL", DefaultTTL)
	c.RecentDays = envInt("SEC_WATCH_RECENT_DAYS", DefaultRecentDays)
	c.WatchConfig = envOr("SEC_WATCH_CONFIG", filepath.Join(xdgConfig, "sec-watch", "watch.json"))
	c.CacheDir = filepath.Join(xdgCache, "sec-watch")
	c.Force = os.Getenv("SEC_WATCH_FORCE") == "1"
	c.Debug = os.Getenv("SEC_WATCH_DEBUG") == "1"
	c.DebugFile = os.Getenv("SEC_WATCH_DEBUG_FILE")

	return c
}

func (c *Config) FeedEnabled(name string) bool {
	for _, f := range strings.Split(c.PublicFeeds, ",") {
		if strings.TrimSpace(f) == name {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
