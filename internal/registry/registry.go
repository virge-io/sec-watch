package registry

import "context"

// ParentFix holds the result of a registry lookup for a parent package.
type ParentFix struct {
	LatestVersion string
	Advice        string // human-readable advice string
}

// Lookup queries the appropriate registry for parentPkg's latest version and checks
// whether its declared constraint on childPkg satisfies childFixedVersion.
// Returns nil if the ecosystem is unsupported or the lookup fails.
func Lookup(ctx context.Context, ecosystem, parentPkg, childPkg, childFixedVersion string) *ParentFix {
	switch ecosystem {
	case "pip", "pipenv", "poetry", "uv", "python-pkg":
		return pypiLookup(ctx, parentPkg, childPkg, childFixedVersion)
	case "npm", "yarn", "pnpm":
		return npmLookup(ctx, parentPkg, childPkg, childFixedVersion)
	default:
		return nil
	}
}
