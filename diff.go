package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
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
	Added   []Package    `json:"added"`
	Removed []Package    `json:"removed"`
	Changed []ChangedPkg `json:"changed"`
}

type syftArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

type syftOutput struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

func scanImage(image string) ([]Package, error) {
	cmd := exec.Command("syft", "scan", image, "-o", "json", "-q")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("syft scan %s: %w\nstderr: %s", image, err, ee.Stderr)
		}
		return nil, fmt.Errorf("syft scan %s: %w", image, err)
	}

	var result syftOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse syft output for %s: %w", image, err)
	}

	pkgs := make([]Package, 0, len(result.Artifacts))
	for _, a := range result.Artifacts {
		pkgs = append(pkgs, Package{Name: a.Name, Version: a.Version, Type: a.Type})
	}
	return pkgs, nil
}

func computeDiff(oldPkgs, newPkgs []Package) *DiffResult {
	type key struct{ name, typ string }

	oldMap := make(map[key]string, len(oldPkgs))
	for _, p := range oldPkgs {
		oldMap[key{p.Name, p.Type}] = p.Version
	}
	newMap := make(map[key]string, len(newPkgs))
	for _, p := range newPkgs {
		newMap[key{p.Name, p.Type}] = p.Version
	}

	result := &DiffResult{}

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

	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].Name < result.Added[j].Name })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].Name < result.Removed[j].Name })
	sort.Slice(result.Changed, func(i, j int) bool { return result.Changed[i].Name < result.Changed[j].Name })

	return result
}

func cacheKey(oldRef, newRef string) string {
	h := sha256.Sum256([]byte(oldRef + "|" + newRef))
	return fmt.Sprintf("%x", h)
}
