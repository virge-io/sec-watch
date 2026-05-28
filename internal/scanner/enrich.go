package scanner

import (
	"context"
	"strings"
	"sync"

	"github.com/virge/sec-watch/internal/registry"
)

type lookupKey struct{ ecosystem, parent, child, fixed string }

// EnrichParentFixes populates ParentFixes on each indirect vulnerability by querying
// package registries for the direct dep(s) that pull in the vulnerable package.
func EnrichParentFixes(ctx context.Context, result *TrivyResult) {
	// Collect unique lookup tuples.
	type tuple struct {
		key       lookupKey
		parentPkg string // name only (without @version)
	}

	seen := map[lookupKey]bool{}
	var tuples []tuple

	for i := range result.Results {
		for j := range result.Results[i].Vulnerabilities {
			v := &result.Results[i].Vulnerabilities[j]
			if v.PkgRelationship != "indirect" || len(v.Via) == 0 {
				continue
			}
			fixedVersion := v.FixedVersion
			if fixedVersion == "" || fixedVersion == "-" {
				continue
			}
			for _, via := range v.Via {
				name, _, _ := strings.Cut(via, "@")
				k := lookupKey{
					ecosystem: v.Ecosystem,
					parent:    via, // store as "name@version" key
					child:     v.PkgName,
					fixed:     fixedVersion,
				}
				// Use name (not name@version) for the actual registry lookup.
				kLookup := lookupKey{
					ecosystem: v.Ecosystem,
					parent:    name,
					child:     v.PkgName,
					fixed:     fixedVersion,
				}
				if seen[k] {
					continue
				}
				seen[k] = true
				tuples = append(tuples, tuple{key: kLookup, parentPkg: name})
			}
		}
	}

	// Deduplicate tuples by lookup key.
	uniqueTuples := map[lookupKey]bool{}
	var dedupedTuples []tuple
	for _, t := range tuples {
		if !uniqueTuples[t.key] {
			uniqueTuples[t.key] = true
			dedupedTuples = append(dedupedTuples, t)
		}
	}

	// Run lookups in parallel.
	var mu sync.Mutex
	cache := make(map[lookupKey]*registry.ParentFix)
	var wg sync.WaitGroup

	for _, t := range dedupedTuples {
		wg.Add(1)
		go func(t tuple) {
			defer wg.Done()
			fix := registry.Lookup(ctx, t.key.ecosystem, t.parentPkg, t.key.child, t.key.fixed)
			mu.Lock()
			cache[t.key] = fix
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	// Apply results back to vulnerabilities.
	for i := range result.Results {
		for j := range result.Results[i].Vulnerabilities {
			v := &result.Results[i].Vulnerabilities[j]
			if v.PkgRelationship != "indirect" || len(v.Via) == 0 {
				continue
			}
			fixedVersion := v.FixedVersion
			if fixedVersion == "" || fixedVersion == "-" {
				// Still populate ParentFixes with just name version for no-fix case.
				v.ParentFixes = make([]string, len(v.Via))
				for k, via := range v.Via {
					name, ver, _ := strings.Cut(via, "@")
					v.ParentFixes[k] = name + " " + ver
				}
				continue
			}

			v.ParentFixes = make([]string, len(v.Via))
			for k, via := range v.Via {
				name, ver, _ := strings.Cut(via, "@")
				kLookup := lookupKey{
					ecosystem: v.Ecosystem,
					parent:    name,
					child:     v.PkgName,
					fixed:     fixedVersion,
				}
				fix := cache[kLookup]
				if fix != nil && fix.Advice != "" {
					v.ParentFixes[k] = name + " " + ver + " — " + fix.Advice
				} else {
					v.ParentFixes[k] = name + " " + ver
				}
			}
		}
	}
}
