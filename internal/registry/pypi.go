package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type pypiResponse struct {
	Info struct {
		Version     string   `json:"version"`
		RequiresDist []string `json:"requires_dist"`
	} `json:"info"`
}

func pypiLookup(ctx context.Context, parentPkg, childPkg, childFixedVersion string) *ParentFix {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", parentPkg)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "sec-watch/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &ParentFix{Advice: "not on PyPI (private package?)"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var data pypiResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	latest := data.Info.Version
	normalChild := normalizePyPI(childPkg)

	// Search requires_dist for a matching dependency on childPkg.
	for _, req := range data.Info.RequiresDist {
		reqName, constraint, ok := parseRequiresDist(req)
		if !ok {
			continue
		}
		if normalizePyPI(reqName) != normalChild {
			continue
		}

		// Extract a lower-bound version from constraint.
		lb := extractLowerBound(constraint)
		if lb == "" {
			return &ParentFix{
				LatestVersion: latest,
				Advice:        fmt.Sprintf("latest %s has no lower-bound constraint on %s", latest, childPkg),
			}
		}

		if versionGTE(lb, childFixedVersion) {
			return &ParentFix{
				LatestVersion: latest,
				Advice:        fmt.Sprintf("upgrade to %s (requires %s>=%s — fixes it)", latest, childPkg, lb),
			}
		}
		return &ParentFix{
			LatestVersion: latest,
			Advice:        fmt.Sprintf("latest %s still allows unfixed %s (>=%s)", latest, childPkg, lb),
		}
	}

	return &ParentFix{
		LatestVersion: latest,
		Advice:        fmt.Sprintf("latest %s has no declared dep on %s", latest, childPkg),
	}
}

// normalizePyPI normalises a package name to lowercase with dashes/dots replaced by underscores.
func normalizePyPI(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	return name
}

// parseRequiresDist splits "name>=1.2; extra=..." into (name, constraint, true).
func parseRequiresDist(s string) (name, constraint string, ok bool) {
	// Strip environment markers after semicolon.
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)

	// Find the first operator character.
	opChars := ">=<!=~"
	idx := strings.IndexAny(s, opChars)
	if idx < 0 {
		return strings.TrimSpace(s), "", true
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx:]), true
}

// extractLowerBound finds the >= lower bound in a PEP 508 constraint string.
// Returns "" if none found.
func extractLowerBound(constraint string) string {
	// Constraints may be comma-separated: ">=1.2,<2.0"
	for _, part := range strings.Split(constraint, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, ">=") {
			return strings.TrimSpace(strings.TrimPrefix(part, ">="))
		}
		if strings.HasPrefix(part, "~=") {
			// Compatible release: ~=1.4.2 means >=1.4.2, ==1.4.*
			return strings.TrimSpace(strings.TrimPrefix(part, "~="))
		}
	}
	return ""
}
