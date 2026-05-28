package feeds

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 25 * time.Second,
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func fetchGzip(ctx context.Context, url string) ([]byte, error) {
	data, err := fetch(ctx, url)
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, 256<<20))
}

// KeywordsRegex builds an alternation regex from the watch config keyword list.
func KeywordsRegex(keywords []string) (*regexp.Regexp, error) {
	if len(keywords) == 0 {
		return nil, nil
	}
	parts := make([]string, len(keywords))
	for i, kw := range keywords {
		parts[i] = regexp.QuoteMeta(kw)
	}
	return regexp.Compile("(?i)" + strings.Join(parts, "|"))
}

// WatchConfig is the user's watch.json.
type WatchConfig struct {
	Keywords    []string `json:"keywords"`
	LookbackDays int     `json:"lookback_days"`
}

func LoadWatchConfig(path string) (*WatchConfig, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var cfg WatchConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.LookbackDays == 0 {
		cfg.LookbackDays = 14
	}
	return &cfg, nil
}

type FeedCounts struct {
	CisaKevCount       int
	CisaKevRecentCount int
	NvdRecentCount     int
}

func FetchAll(ctx context.Context, cisaURL, nvdURL string, enableCisa, enableNvd bool, rx *regexp.Regexp, recentDays, lookbackDays int) FeedCounts {
	type cisaResult struct{ count, recent int }
	type nvdResult struct{ count int }

	cisaCh := make(chan cisaResult, 1)
	nvdCh := make(chan nvdResult, 1)

	if enableCisa {
		go func() {
			c, r := fetchCISA(ctx, cisaURL, rx, recentDays, lookbackDays)
			cisaCh <- cisaResult{c, r}
		}()
	} else {
		cisaCh <- cisaResult{}
	}

	if enableNvd {
		go func() {
			n := fetchNVD(ctx, nvdURL, rx, recentDays)
			nvdCh <- nvdResult{n}
		}()
	} else {
		nvdCh <- nvdResult{}
	}

	cisa := <-cisaCh
	nvd := <-nvdCh
	return FeedCounts{
		CisaKevCount:       cisa.count,
		CisaKevRecentCount: cisa.recent,
		NvdRecentCount:     nvd.count,
	}
}
