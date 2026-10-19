package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProgressiveReport(t *testing.T) {
	inventory := make(chan struct{})
	vulnerabilities := make(chan struct{})
	packagesReady := make(chan struct{})
	var scans atomic.Int32
	s := serverForTest(t, func(ctx context.Context, old, new string) (*DiffResult, error) {
		scans.Add(1)
		reportProgress(ctx, "inventory_old", nil)
		select {
		case <-inventory:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		partial := computeDiff([]Package{{"openssl", "1", "deb"}}, []Package{{"openssl", "2", "deb"}})
		reportProgress(ctx, "database", partial)
		close(packagesReady)
		select {
		case <-vulnerabilities:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		partial.Scan = result().Scan
		partial.Vulnerabilities = compareFindings(nil, []Finding{{ID: "CVE-new", Package: "openssl", Severity: "High"}})
		return partial, nil
	})
	old, new := testRefs()
	q := "?old=" + old + "&new=" + new
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/diff"+q, nil))
		response <- w
	}()
	select {
	case w := <-response:
		if w.Code != 200 || !strings.Contains(w.Body.String(), `id="scan-status"`) || strings.Contains(w.Body.String(), "No package differences") {
			t.Fatalf("missing initial loading page: %d %s", w.Code, w.Body)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("HTML request blocked on the scan")
	}
	// A second browser joins the existing job.
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/diff"+q, nil))
	close(inventory)
	<-packagesReady
	if scans.Load() != 1 {
		t.Fatal("page requests duplicated the scan")
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/jobs"+q, nil))
	var job Job
	if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.Stage != "database" || !job.PackagesReady || job.State != "running" {
		t.Fatalf("missing stage/partial status: %+v", job)
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/diff"+q+"&fragment=1", nil))
	if w.Code != 202 || !strings.Contains(w.Body.String(), "openssl") || !strings.Contains(w.Body.String(), "still pending") || strings.Contains(w.Body.String(), "Vulnerability changes") {
		t.Fatalf("bad partial: %d %s", w.Code, w.Body)
	}
	// JSON callers retain the original wait-for-completion contract.
	jsonResponse := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/diff.json"+q, nil))
		jsonResponse <- w
	}()
	select {
	case <-jsonResponse:
		t.Fatal("JSON returned an incomplete report")
	case <-time.After(20 * time.Millisecond):
	}
	close(vulnerabilities)
	select {
	case w = <-jsonResponse:
	case <-time.After(time.Second):
		t.Fatal("JSON did not complete")
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), "CVE-new") {
		t.Fatalf("bad completed JSON: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/diff"+q+"&fragment=1", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "CVE-new") || strings.Contains(w.Body.String(), "still pending") {
		t.Fatalf("bad completed fragment: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/diff"+q, nil))
	if strings.Contains(w.Body.String(), `id="scan-status"`) || !strings.Contains(w.Body.String(), "CVE-new") {
		t.Fatal("fresh report should render immediately")
	}
}

func TestPartialReportSurvivesFailure(t *testing.T) {
	s := serverForTest(t, func(ctx context.Context, old, new string) (*DiffResult, error) {
		reportProgress(ctx, "database", computeDiff(nil, []Package{{"visible-package", "2", "deb"}}))
		return nil, errors.New("database unreachable")
	})
	old, new := testRefs()
	c, err := s.startCompute(s.key(old, new), old, new)
	if err != nil {
		t.Fatal(err)
	}
	waitCall(t, c)
	q := "?old=" + old + "&new=" + new
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/jobs"+q, nil))
	var job Job
	json.Unmarshal(w.Body.Bytes(), &job)
	if job.State != "failed" || job.Stage != "database" || !job.PackagesReady {
		t.Fatalf("lost failed partial state: %+v", job)
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/diff"+q+"&fragment=1", nil))
	if w.Code != 202 || !strings.Contains(w.Body.String(), "visible-package") {
		t.Fatalf("lost partial report after failure: %s", w.Body)
	}
	w = httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest("GET", "/assets/progress.js", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Fatal("progress client unavailable")
	}
}
