package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const platform = "linux/amd64"

// Bump when matching settings or report semantics change.
const scanPolicy = "v1-default-grype"

type ScanMetadata struct {
	Platform     string          `json:"platform"`
	SyftVersion  string          `json:"syft_version"`
	GrypeVersion string          `json:"grype_version"`
	Database     json.RawMessage `json:"database"`
	DatabaseID   string          `json:"database_id"`
	ScannedAt    time.Time       `json:"scanned_at"`
}
type Finding struct {
	ID          string   `json:"id"`
	Namespace   string   `json:"namespace"`
	Package     string   `json:"package"`
	Type        string   `json:"type"`
	Version     string   `json:"version"`
	Severity    string   `json:"severity"`
	FixState    string   `json:"fix_state"`
	FixVersions []string `json:"fix_versions"`
}
type VulnerabilityDiff struct {
	Introduced []Finding `json:"introduced"`
	Resolved   []Finding `json:"resolved"`
	Persisting []Finding `json:"persisting"`
}
type grypeOutput struct {
	Matches []struct {
		Vulnerability struct {
			ID        string `json:"id"`
			Namespace string `json:"namespace"`
			Severity  string `json:"severity"`
			Fix       struct {
				State    string   `json:"state"`
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact syftArtifact `json:"artifact"`
	} `json:"matches"`
}

type Scanner struct{ dir, syftVersion, grypeVersion string }

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Matching settings are application-owned so cached results remain reproducible.
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GRYPE_") && !strings.HasPrefix(value, "SYFT_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "GRYPE_CHECK_FOR_APP_UPDATE=false", "SYFT_CHECK_FOR_APP_UPDATE=false")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%s: %s", name, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}
func newScanner(ctx context.Context, dir string) (*Scanner, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(dir, "syft.yaml"), map[string]any{}); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(dir, "grype.yaml"), map[string]any{"db": map[string]any{"cache-dir": filepath.Join(dir, "grype-db"), "auto-update": false, "validate-by-hash-on-start": true, "validate-age": true, "max-allowed-built-age": "120h"}}); err != nil {
		return nil, err
	}

	s := &Scanner{dir: dir}
	for _, tool := range []string{"syft", "grype"} {
		out, err := run(ctx, tool, "version", "-o", "json")
		if err != nil {
			return nil, err
		}
		var v struct {
			Version string `json:"version"`
		}
		if err = json.Unmarshal(out, &v); err != nil {
			return nil, err
		}
		if v.Version == "" {
			return nil, fmt.Errorf("%s returned no version", tool)
		}
		if tool == "syft" {
			s.syftVersion = v.Version
		} else {
			s.grypeVersion = v.Version
		}
	}
	return s, nil
}
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func writeJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}
func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func (s *Scanner) args(tool string, args ...string) []string {
	return append([]string{"--config", filepath.Join(s.dir, tool+".yaml")}, args...)
}
func (s *Scanner) sbom(ctx context.Context, ref string) (string, []Package, error) {
	path := filepath.Join(s.dir, "sboms", hash(ref+"|"+platform+"|"+s.syftVersion)+".json")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", nil, err
	}
	if os.IsNotExist(err) {
		data, err = run(ctx, "syft", s.args("syft", "scan", "registry:"+ref, "--platform", platform, "-o", "syft-json")...)
		if err != nil {
			return "", nil, err
		}
	}
	var out syftOutput
	if err = json.Unmarshal(data, &out); err != nil {
		return "", nil, fmt.Errorf("invalid SBOM: %w", err)
	}
	if out.Artifacts == nil {
		return "", nil, fmt.Errorf("Syft output is missing artifacts")
	}
	// Keep the complete native SBOM, including distro and package locations.
	if err = writeAtomic(path, data); err != nil {
		return "", nil, err
	}
	pkgs := make([]Package, 0, len(out.Artifacts))
	for _, p := range out.Artifacts {
		pkgs = append(pkgs, Package{p.Name, p.Version, p.Type})
	}
	return path, pkgs, nil
}
func parseFindings(data []byte) ([]Finding, error) {
	var out grypeOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out.Matches == nil {
		return nil, fmt.Errorf("Grype output is missing matches")
	}
	findings := make([]Finding, 0, len(out.Matches))
	seen := map[string]bool{}
	for _, m := range out.Matches {
		v := m.Vulnerability
		f := Finding{v.ID, v.Namespace, m.Artifact.Name, m.Artifact.Type, m.Artifact.Version, v.Severity, v.Fix.State, v.Fix.Versions}
		key := findingKey(f) + "|" + f.Version
		if !seen[key] {
			findings = append(findings, f)
			seen[key] = true
		}
	}
	return findings, nil
}

// Exclude installed version: a vulnerable package upgrade can remain affected.
func findingKey(f Finding) string {
	return strings.Join([]string{f.Namespace, f.ID, f.Type, f.Package}, "|")
}
func compareFindings(old, new []Finding) *VulnerabilityDiff {
	d := &VulnerabilityDiff{Introduced: []Finding{}, Resolved: []Finding{}, Persisting: []Finding{}}
	oldMap := map[string]bool{}
	newMap := map[string]bool{}
	for _, f := range old {
		oldMap[findingKey(f)] = true
	}
	for _, f := range new {
		newMap[findingKey(f)] = true
		if oldMap[findingKey(f)] {
			d.Persisting = append(d.Persisting, f)
		} else {
			d.Introduced = append(d.Introduced, f)
		}
	}
	for _, f := range old {
		if !newMap[findingKey(f)] {
			d.Resolved = append(d.Resolved, f)
		}
	}
	rank := map[string]int{"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1}
	for _, fs := range [][]Finding{d.Introduced, d.Resolved, d.Persisting} {
		sort.Slice(fs, func(i, j int) bool {
			if rank[fs[i].Severity] != rank[fs[j].Severity] {
				return rank[fs[i].Severity] > rank[fs[j].Severity]
			}
			return findingKey(fs[i])+fs[i].Version < findingKey(fs[j])+fs[j].Version
		})
	}
	return d
}
func (s *Scanner) findings(ctx context.Context, sbom, dbID string) ([]Finding, error) {
	path := filepath.Join(s.dir, "findings", hash(sbom+"|"+dbID+"|"+s.grypeVersion+"|"+scanPolicy)+".json")
	if b, err := os.ReadFile(path); err == nil {
		var fs []Finding
		if json.Unmarshal(b, &fs) == nil {
			return fs, nil
		}
	}
	b, err := run(ctx, "grype", s.args("grype", "sbom:"+sbom, "-o", "json")...)
	if err != nil {
		return nil, err
	}
	fs, err := parseFindings(b)
	if err != nil {
		return nil, err
	}
	return fs, writeJSON(path, fs)
}

// Called by the single worker: no database update can occur between the two scans.
func (s *Scanner) Compare(ctx context.Context, oldRef, newRef string) (*DiffResult, error) {
	oldSBOM, old, err := s.sbom(ctx, oldRef)
	if err != nil {
		return nil, err
	}
	newSBOM, new, err := s.sbom(ctx, newRef)
	if err != nil {
		return nil, err
	}
	if _, err = run(ctx, "grype", s.args("grype", "db", "update")...); err != nil {
		return nil, fmt.Errorf("database update: %w", err)
	}
	db, err := run(ctx, "grype", s.args("grype", "db", "status", "-o", "json")...)
	if err != nil {
		return nil, err
	}
	var status struct {
		Built         string `json:"built"`
		From          string `json:"from"`
		SchemaVersion string `json:"schemaVersion"`
		Valid         bool   `json:"valid"`
	}
	if err = json.Unmarshal(db, &status); err != nil {
		return nil, err
	}
	if !status.Valid || status.Built == "" {
		return nil, fmt.Errorf("Grype database is not valid")
	}
	// The source URL includes the archive checksum. Include schema and build time; exclude local paths.
	dbID := hash(status.Built + "|" + status.From + "|" + status.SchemaVersion)
	oldFindings, err := s.findings(ctx, oldSBOM, dbID)
	if err != nil {
		return nil, err
	}
	newFindings, err := s.findings(ctx, newSBOM, dbID)
	if err != nil {
		return nil, err
	}
	result := computeDiff(old, new)
	result.Vulnerabilities = compareFindings(oldFindings, newFindings)
	result.Scan = &ScanMetadata{platform, s.syftVersion, s.grypeVersion, db, dbID, time.Now().UTC()}
	return result, nil
}
