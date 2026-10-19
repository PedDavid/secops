package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVulnerabilityComparison(t *testing.T) {
	old := []Finding{{ID: "CVE-1", Namespace: "debian:12", Package: "openssl", Type: "deb", Version: "1", Severity: "High"}, {ID: "CVE-2", Package: "removed", Severity: "Low"}}
	new := []Finding{{ID: "CVE-1", Namespace: "debian:12", Package: "openssl", Type: "deb", Version: "2", Severity: "High", FixState: "fixed", FixVersions: []string{"3"}}, {ID: "CVE-3", Package: "new", Severity: "Critical"}, {ID: "CVE-1", Namespace: "alpine:3", Package: "openssl", Type: "apk", Version: "1"}}
	d := compareFindings(old, new)
	if len(d.Introduced) != 2 || len(d.Resolved) != 1 || len(d.Persisting) != 1 {
		t.Fatalf("unexpected diff: %+v", d)
	}
	if d.Introduced[0].ID != "CVE-3" || d.Persisting[0].Version != "2" || d.Persisting[0].FixVersions[0] != "3" {
		t.Fatalf("lost severity ordering or replacement details: %+v", d)
	}
}
func TestParseFindingsDeduplicatesLocations(t *testing.T) {
	match := `{"vulnerability":{"id":"CVE-1","dataSource":"https://security-tracker.debian.org/tracker/CVE-1","namespace":"debian:12","severity":"High","fix":{"state":"fixed","versions":["3"]}},"artifact":{"name":"libssl","version":"2","type":"deb"}}`
	fs, err := parseFindings([]byte(`{"matches":[` + match + `,` + match + `]}`))
	if err != nil || len(fs) != 1 || fs[0].FixState != "fixed" || fs[0].Link() != "https://security-tracker.debian.org/tracker/CVE-1" {
		t.Fatalf("%+v %v", fs, err)
	}
	if _, err := parseFindings([]byte(`broken`)); err == nil {
		t.Fatal("accepted malformed scanner output")
	}
}
func result() *DiffResult {
	return &DiffResult{Scan: &ScanMetadata{Platform: platform, ScannedAt: time.Now().UTC()}, Vulnerabilities: compareFindings(nil, nil)}
}
func serverForTest(t *testing.T, compare func(context.Context, string, string) (*DiffResult, error)) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{cache: NewCache(t.TempDir()), jobs: map[string]*call{}, queue: make(chan *call, 8), ttl: time.Hour, timeout: time.Second, compare: compare, ctx: ctx}
	done := make(chan struct{})
	go func() { defer close(done); s.worker() }()
	t.Cleanup(func() { cancel(); <-done })
	return s
}
func testRefs() (string, string) {
	return "alpine@sha256:" + strings.Repeat("a", 64), "alpine@sha256:" + strings.Repeat("b", 64)
}
func waitCall(t *testing.T, c *call) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		t.Fatal("job did not finish")
	}
}
func TestJobsDeduplicationAndBackpressure(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	var count atomic.Int32
	s := serverForTest(t, func(ctx context.Context, old, new string) (*DiffResult, error) {
		count.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-gate:
			return result(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	old, new := testRefs()
	key := s.key(old, new)
	c, err := s.startCompute(key, old, new)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	duplicate, err := s.startCompute(key, old, new)
	if err != nil || duplicate != c {
		t.Fatal("duplicate job was not reused")
	}
	for i := 0; i < 8; i++ {
		if _, err = s.startCompute(string(rune('a'+i)), old, new); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.startCompute("overflow", old, new); !errors.Is(err, errBusy) {
		t.Fatalf("expected backpressure, got %v", err)
	}
	close(gate)
	waitCall(t, c)
	if count.Load() < 1 || s.cached(key) == nil {
		t.Fatal("completed result missing")
	}
}
func TestFailureStatusRetryAndFreshness(t *testing.T) {
	var count atomic.Int32
	s := serverForTest(t, func(context.Context, string, string) (*DiffResult, error) {
		if count.Add(1) == 1 {
			return nil, errors.New("registry failed")
		}
		return result(), nil
	})
	old, new := testRefs()
	key := s.key(old, new)
	c, _ := s.startCompute(key, old, new)
	waitCall(t, c)
	q := "?old=" + old + "&new=" + new
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/jobs"+q, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"failed"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/badge"+q, nil))
	if !strings.Contains(w.Body.String(), "failed") || strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("failure badge missing or permanently cached")
	}
	c, _ = s.startCompute(key, old, new)
	waitCall(t, c)
	if c.err != nil || s.cached(key) == nil {
		t.Fatalf("retry failed: %v", c.err)
	}
	r := result()
	r.Scan.ScannedAt = time.Now().Add(-2 * time.Hour)
	if err := s.cache.Set(key, r); err != nil {
		t.Fatal(err)
	}
	if s.cached(key) != nil {
		t.Fatal("expired vulnerability result accepted")
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/badge"+q, nil))
	if !strings.Contains(w.Body.String(), "stale") {
		t.Fatal("missing stale state")
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/diff.json"+q, nil))
	if w.Code != 200 || count.Load() != 3 {
		t.Fatalf("did not refresh: %d, scans %d", w.Code, count.Load())
	}
}
func TestTimeoutAndInputValidation(t *testing.T) {
	s := serverForTest(t, func(ctx context.Context, old, new string) (*DiffResult, error) { <-ctx.Done(); return nil, ctx.Err() })
	s.timeout = 20 * time.Millisecond
	old, new := testRefs()
	c, _ := s.startCompute(s.key(old, new), old, new)
	waitCall(t, c)
	if !errors.Is(c.err, context.DeadlineExceeded) {
		t.Fatalf("got %v", c.err)
	}
	for _, path := range []string{"/diff?old=/etc/passwd&new=alpine", "/jobs?old=--help&new=alpine", "/diff.json"} {
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 400 {
			t.Fatalf("accepted %s", path)
		}
	}
}
func TestReportEscapesAndIncludesFindings(t *testing.T) {
	r := result()
	r.Vulnerabilities.Introduced = []Finding{{ID: "CVE-1", Package: "<script>alert(1)</script>", FixState: "fixed", FixVersions: []string{"2"}}}
	var b bytes.Buffer
	renderHTML(&b, "old", "new", r)
	if strings.Contains(b.String(), "<script>") || !strings.Contains(b.String(), "CVE-1") || !strings.Contains(b.String(), "fixed") {
		t.Fatal("unsafe or incomplete HTML")
	}
}
func TestSBOMCachePreservesMetadata(t *testing.T) {
	dir := t.TempDir()
	s := &Scanner{dir: dir, syftVersion: "test"}
	ref, _ := testRefs()
	path := filepath.Join(dir, "sboms", hash(ref+"|"+platform+"|test")+".json")
	raw := []byte(`{"artifacts":[{"name":"libssl","type":"deb","version":"2","locations":[{"path":"/usr/lib"}]}],"distro":{"name":"debian","version":"12"}}`)
	if err := writeAtomic(path, raw); err != nil {
		t.Fatal(err)
	}
	got, pkgs, err := s.sbom(context.Background(), ref)
	if err != nil || got != path || len(pkgs) != 1 {
		t.Fatalf("%s %+v %v", got, pkgs, err)
	}
	data, _ := os.ReadFile(path)
	var full map[string]json.RawMessage
	json.Unmarshal(data, &full)
	if full["distro"] == nil || !bytes.Contains(data, []byte("locations")) {
		t.Fatal("native SBOM metadata discarded")
	}
}

func TestScannerPipelineAndDatabaseInvalidation(t *testing.T) {
	fixtures := t.TempDir()
	bin := t.TempDir()
	t.Setenv("TEST_SCAN_FIXTURES", fixtures)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	// Deliberately conflicting ambient options must not affect application-owned matching.
	t.Setenv("GRYPE_ONLY_FIXED", "true")
	script := `#!/bin/sh
set -eu
if [ "${GRYPE_ONLY_FIXED+x}" = x ]; then exit 91; fi
if [ "$1" = version ]; then echo '{"version":"test-1"}'; exit; fi
[ "$1" = --config ] && shift 2
printf '%s\n' "$*" >> "$TEST_SCAN_FIXTURES/commands"
case "$1" in
 scan)
  case "$2" in
   *aaaaaaaa*) echo '{"artifacts":[{"name":"libssl","version":"1","type":"deb"}],"distro":{"name":"debian","version":"12"}}';;
   *) echo '{"artifacts":[{"name":"libssl","version":"2","type":"deb"}],"distro":{"name":"debian","version":"12"}}';;
  esac;;
 db)
  case "$2" in
   update) echo updated;;
   status) cat "$TEST_SCAN_FIXTURES/database.json";;
  esac;;
 sbom:*)
  if grep -q '"version":"1"' "${1#sbom:}"; then
   echo '{"matches":[{"vulnerability":{"id":"CVE-old","namespace":"debian:12","severity":"High","fix":{"state":"fixed","versions":["2"]}},"artifact":{"name":"libssl","version":"1","type":"deb"}}]}'
  else echo '{"matches":[]}'
  fi;;
 *) exit 92;;
esac
`
	for _, name := range []string{"syft", "grype"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	dbPath := filepath.Join(fixtures, "database.json")
	if err := os.WriteFile(dbPath, []byte(`{"valid":true,"schemaVersion":"6.0.0","built":"2026-10-19T00:00:00Z","from":"https://grype.anchore.io/db?checksum=sha256:one"}`), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := newScanner(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old, new := testRefs()
	r, err := s.Compare(context.Background(), old, new)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Changed) != 1 || len(r.Vulnerabilities.Resolved) != 1 || r.Scan.DatabaseID == "" {
		t.Fatalf("incomplete report: %+v", r)
	}
	firstID := r.Scan.DatabaseID
	r, err = s.Compare(context.Background(), old, new)
	if err != nil {
		t.Fatal(err)
	}
	log, _ := os.ReadFile(filepath.Join(fixtures, "commands"))
	if strings.Count(string(log), "scan registry:") != 2 || strings.Count(string(log), "sbom:") != 2 {
		t.Fatalf("artifacts were rescanned unnecessarily: %s", log)
	}
	if err = os.WriteFile(dbPath, []byte(`{"valid":true,"schemaVersion":"6.0.0","built":"2026-10-19T00:00:00Z","from":"https://grype.anchore.io/db?checksum=sha256:two"}`), 0644); err != nil {
		t.Fatal(err)
	}
	r, err = s.Compare(context.Background(), old, new)
	if err != nil {
		t.Fatal(err)
	}
	log, _ = os.ReadFile(filepath.Join(fixtures, "commands"))
	if r.Scan.DatabaseID == firstID || strings.Count(string(log), "scan registry:") != 2 || strings.Count(string(log), "sbom:") != 4 {
		t.Fatalf("database change did not invalidate findings: %s", log)
	}
	if err = os.WriteFile(dbPath, []byte(`{"valid":false}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Compare(context.Background(), old, new); err == nil {
		t.Fatal("accepted invalid database")
	}
}

func TestLiveComparison(t *testing.T) {
	if os.Getenv("DIGEST_DIFF_LIVE") != "1" {
		t.Skip("set DIGEST_DIFF_LIVE=1 and two digest references to exercise real scanners")
	}
	old, new := os.Getenv("DIGEST_DIFF_OLD"), os.Getenv("DIGEST_DIFF_NEW")
	if !imageRef.MatchString(old) || !imageRef.MatchString(new) {
		t.Fatal("DIGEST_DIFF_OLD and DIGEST_DIFF_NEW must be digest-pinned image references")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
	defer cancel()
	dir := t.TempDir()
	scanner, err := newScanner(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(ctx, NewCache(filepath.Join(dir, "reports")), scanner, time.Hour, 15*time.Minute)
	key := s.key(old, new)
	c, err := s.startCompute(key, old, new)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if c.err != nil {
		t.Fatal(c.err)
	}
	if c.result.Scan == nil || c.result.Vulnerabilities == nil || c.result.Scan.Platform != platform {
		t.Fatal("missing real scan metadata")
	}
	q := "?old=" + old + "&new=" + new
	for _, path := range []string{"/diff", "/diff.json", "/badge", "/jobs"} {
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, httptest.NewRequest("GET", path+q, nil))
		if w.Code != 200 {
			t.Fatalf("%s returned %d: %s", path, w.Code, w.Body)
		}
	}
	cached := s.cached(key)
	if cached == nil || !cached.Scan.ScannedAt.Equal(c.result.Scan.ScannedAt) {
		t.Fatal("fresh report not reused")
	}
	t.Logf("Syft %s, Grype %s, database %s: %d package changes; findings %d introduced, %d resolved, %d persisting", scanner.syftVersion, scanner.grypeVersion, c.result.Scan.DatabaseID, len(c.result.Changed), len(c.result.Vulnerabilities.Introduced), len(c.result.Vulnerabilities.Resolved), len(c.result.Vulnerabilities.Persisting))
}

func TestPackageDiffRetainsMultipleVersions(t *testing.T) {
	old := []Package{{"library", "1", "python"}, {"library", "2", "python"}, {"library", "2", "python"}}
	same := []Package{{"library", "2", "python"}, {"library", "1", "python"}}
	if d := computeDiff(old, same); len(d.Changed) != 0 {
		t.Fatalf("inventory order changed result: %+v", d)
	}
	d := computeDiff(old, []Package{{"library", "2", "python"}})
	if len(d.Changed) != 1 || d.Changed[0].OldVersion != "1, 2" || d.Changed[0].NewVersion != "2" {
		t.Fatalf("lost installed version: %+v", d)
	}
}

func TestAdvisoryLinks(t *testing.T) {
	for _, tc := range []struct {
		finding Finding
		want    string
	}{
		{Finding{ID: "CVE-2025-12345"}, "https://www.cve.org/CVERecord?id=CVE-2025-12345"},
		{Finding{ID: "GHSA-abcd-1234-efgh"}, "https://github.com/advisories/GHSA-abcd-1234-efgh"},
		{Finding{ID: "CVE-2025-12345", URL: "https://security.example.org/advisory/123"}, "https://security.example.org/advisory/123"},
		{Finding{ID: "CVE-2025-12345", URL: "javascript:alert(1)"}, "https://www.cve.org/CVERecord?id=CVE-2025-12345"},
		{Finding{ID: "unknown", URL: "//evil.example/advisory"}, ""},
		{Finding{ID: "unknown", URL: "https://user:password@example.org/advisory"}, ""},
		{Finding{ID: "<script>alert(1)</script>"}, ""},
	} {
		if got := tc.finding.Link(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.finding.ID, got, tc.want)
		}
	}
	r := result()
	for _, section := range []*[]Finding{&r.Vulnerabilities.Introduced, &r.Vulnerabilities.Resolved, &r.Vulnerabilities.Persisting} {
		*section = []Finding{{ID: "CVE-2025-12345"}}
	}
	var full, fragment bytes.Buffer
	renderHTML(&full, "old", "new", r)
	renderFragment(&fragment, r)
	for _, html := range []string{full.String(), fragment.String()} {
		if strings.Count(html, `href="https://www.cve.org/CVERecord?id=CVE-2025-12345"`) != 3 {
			t.Fatal("missing advisory links in report sections")
		}
	}
}
