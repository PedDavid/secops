package main

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

type ChangedPkg struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

type DiffResult struct {
	Scan            *ScanMetadata      `json:"scan,omitempty"`
	Vulnerabilities *VulnerabilityDiff `json:"vulnerabilities,omitempty"`
	Added           []Package          `json:"added"`
	Removed         []Package          `json:"removed"`
	Changed         []ChangedPkg       `json:"changed"`
}

type syftArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

type syftOutput struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

func computeDiff(oldPkgs, newPkgs []Package) *DiffResult {
	type key struct{ name, typ string }

	// Images can contain several installed versions of one language package.
	// Compare sorted version sets instead of losing all but the last occurrence.
	index := func(pkgs []Package) map[key]string {
		sets := map[key]map[string]bool{}
		for _, p := range pkgs {
			k := key{p.Name, p.Type}
			if sets[k] == nil {
				sets[k] = map[string]bool{}
			}
			sets[k][p.Version] = true
		}
		out := map[key]string{}
		for k, set := range sets {
			versions := make([]string, 0, len(set))
			for v := range set {
				versions = append(versions, v)
			}
			sort.Strings(versions)
			out[k] = strings.Join(versions, ", ")
		}
		return out
	}
	oldMap, newMap := index(oldPkgs), index(newPkgs)

	result := &DiffResult{Added: []Package{}, Removed: []Package{}, Changed: []ChangedPkg{}}

	for k, newVer := range newMap {
		if oldVer, ok := oldMap[k]; !ok {
			result.Added = append(result.Added, Package{Name: k.name, Type: k.typ, Version: newVer})
		} else if oldVer != newVer {
			result.Changed = append(result.Changed, ChangedPkg{
				Name: k.name, Type: k.typ,
				OldVersion: oldVer, NewVersion: newVer,
			})
		}
	}

	for k, oldVer := range oldMap {
		if _, ok := newMap[k]; !ok {
			result.Removed = append(result.Removed, Package{Name: k.name, Type: k.typ, Version: oldVer})
		}
	}

	sort.Slice(result.Added, func(i, j int) bool {
		return result.Added[i].Name+"|"+result.Added[i].Type < result.Added[j].Name+"|"+result.Added[j].Type
	})
	sort.Slice(result.Removed, func(i, j int) bool {
		return result.Removed[i].Name+"|"+result.Removed[i].Type < result.Removed[j].Name+"|"+result.Removed[j].Type
	})
	sort.Slice(result.Changed, func(i, j int) bool {
		return result.Changed[i].Name+"|"+result.Changed[i].Type < result.Changed[j].Name+"|"+result.Changed[j].Type
	})

	return result
}

func cacheKey(oldRef, newRef string) string {
	h := sha256.Sum256([]byte(oldRef + "|" + newRef))
	return fmt.Sprintf("%x", h)
}
