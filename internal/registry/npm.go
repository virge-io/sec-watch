package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type npmLatestResponse struct {
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

func npmLookup(ctx context.Context, parentPkg, childPkg, childFixedVersion string) *ParentFix {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://registry.npmjs.org/%s/latest", parentPkg)
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
		return &ParentFix{Advice: "not on npm (private package?)"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var data npmLatestResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	latest := data.Version

	// Exact match first.
	constraint, found := data.Dependencies[childPkg]
	if !found {
		// Case-insensitive fallback.
		lowerChild := strings.ToLower(childPkg)
		for k, v := range data.Dependencies {
			if strings.ToLower(k) == lowerChild {
				constraint = v
				found = true
				break
			}
		}
	}

	if !found {
		return &ParentFix{
			LatestVersion: latest,
			Advice:        fmt.Sprintf("latest %s has no declared dep on %s", latest, childPkg),
		}
	}

	// Parse constraint: strip leading ^ ~ >= etc., extract version number.
	ver := parseNpmConstraint(constraint)
	if ver == "" {
		return &ParentFix{
			LatestVersion: latest,
			Advice:        fmt.Sprintf("latest %s uses %s@%s (cannot parse constraint)", latest, childPkg, constraint),
		}
	}

	if versionGTE(ver, childFixedVersion) {
		return &ParentFix{
			LatestVersion: latest,
			Advice:        fmt.Sprintf("upgrade to %s (uses %s@%s — fixes it)", latest, childPkg, constraint),
		}
	}
	return &ParentFix{
		LatestVersion: latest,
		Advice:        fmt.Sprintf("latest %s still uses unfixed %s@%s", latest, childPkg, constraint),
	}
}

// parseNpmConstraint strips leading range operators and returns the version number.
func parseNpmConstraint(constraint string) string {
	constraint = strings.TrimSpace(constraint)
	// Strip leading ^ ~ >= <= > < = characters.
	constraint = strings.TrimLeft(constraint, "^~>=<! ")
	// Take up to the first space (handles "1.2.3 || 2.0.0" style — use first range).
	if i := strings.IndexAny(constraint, " |,"); i >= 0 {
		constraint = constraint[:i]
	}
	return strings.TrimSpace(constraint)
}
