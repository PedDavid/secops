package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var errBusy = errors.New("scan queue is full; retry later")
var imageRef = regexp.MustCompile(`^[a-z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$`)

type Job struct {
	State         string     `json:"state"`
	Stage         string     `json:"stage,omitempty"`
	PackagesReady bool       `json:"packages_ready"`
	Error         string     `json:"error,omitempty"`
	SubmittedAt   time.Time  `json:"submitted_at,omitzero"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}
type call struct {
	done                chan struct{}
	oldRef, newRef, key string
	job                 Job
	result              *DiffResult
	partial             *DiffResult
	err                 error
}
type Server struct {
	cache                     *Cache
	mu                        sync.Mutex
	jobs                      map[string]*call
	queue                     chan *call
	ttl, timeout              time.Duration
	syftVersion, grypeVersion string
	compare                   func(context.Context, string, string) (*DiffResult, error)
	ctx                       context.Context
}

func NewServer(ctx context.Context, cache *Cache, scanner *Scanner, ttl, timeout time.Duration) *Server {
	s := &Server{cache: cache, jobs: map[string]*call{}, queue: make(chan *call, 8), ttl: ttl, timeout: timeout, syftVersion: scanner.syftVersion, grypeVersion: scanner.grypeVersion, compare: scanner.Compare, ctx: ctx}
	go s.worker()
	return s
}
func (s *Server) key(old, new string) string {
	return cacheKey(old, new) + "-" + hash(platform+s.syftVersion+s.grypeVersion+scanPolicy)
}
func (s *Server) cached(key string) *DiffResult {
	r, err := s.cache.Get(key)
	if err != nil || r == nil || r.Scan == nil || r.Vulnerabilities == nil || time.Since(r.Scan.ScannedAt) > s.ttl {
		return nil
	}
	return r
}
func (s *Server) startCompute(key, oldRef, newRef string) (*call, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.jobs[key]; c != nil && (c.job.State == "queued" || c.job.State == "running") {
		return c, nil
	}
	// Keep bounded recent job history, evicting completed jobs first.
	if len(s.jobs) >= 128 {
		oldestKey := ""
		var oldest time.Time
		for k, c := range s.jobs {
			if c.job.FinishedAt != nil && (oldestKey == "" || c.job.FinishedAt.Before(oldest)) {
				oldestKey = k
				oldest = *c.job.FinishedAt
			}
		}
		if oldestKey != "" {
			delete(s.jobs, oldestKey)
		} else {
			return nil, errBusy
		}
	}
	c := &call{done: make(chan struct{}), key: key, oldRef: oldRef, newRef: newRef, job: Job{State: "queued", SubmittedAt: time.Now().UTC()}}
	select {
	case s.queue <- c:
		s.jobs[key] = c
		return c, nil
	default:
		return nil, errBusy
	}
}
func (s *Server) worker() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case c := <-s.queue:
			s.mu.Lock()
			c.job.State = "running"
			s.mu.Unlock()
			ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
			ctx = context.WithValue(ctx, progressKey{}, func(stage string, partial *DiffResult) {
				s.mu.Lock()
				defer s.mu.Unlock()
				c.job.Stage = stage
				if partial != nil {
					c.partial = partial
					c.job.PackagesReady = true
				}
			})
			r, err := s.compare(ctx, c.oldRef, c.newRef)
			cancel()
			if err == nil {
				err = s.cache.Set(c.key, r)
			}
			s.mu.Lock()
			c.result = r
			c.err = err
			t := time.Now().UTC()
			c.job.FinishedAt = &t
			c.job.State = "completed"
			if err == nil {
				c.job.Stage = "completed"
			}
			c.job.PackagesReady = err == nil || c.partial != nil
			if err != nil {
				c.job.State = "failed"
				c.job.Error = "Scan failed; see service logs for details."
				slog.Error("scan failed", "old", c.oldRef, "new", c.newRef, "err", err)
			}
			close(c.done)
			s.mu.Unlock()
		}
	}
}
func refs(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	old, new := r.URL.Query().Get("old"), r.URL.Query().Get("new")
	if len(old) > 512 || len(new) > 512 || !imageRef.MatchString(old) || !imageRef.MatchString(new) {
		http.Error(w, "old and new must be image@sha256:<64 lowercase hex characters> references", http.StatusBadRequest)
		return "", "", false
	}
	return old, new, true
}
func (s *Server) getOrCompute(ctx context.Context, key, old, new string) (*DiffResult, error) {
	if r := s.cached(key); r != nil {
		return r, nil
	}
	c, err := s.startCompute(key, old, new)
	if err != nil {
		return nil, err
	}
	select {
	case <-c.done:
		return c.result, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	old, new, ok := refs(w, r)
	if !ok {
		return
	}
	key := s.key(old, new)
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/diff" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if result := s.cached(key); result != nil {
			if r.URL.Query().Get("fragment") == "1" {
				renderFragment(w, result)
			} else {
				renderHTML(w, old, new, result)
			}
			return
		}
		if r.URL.Query().Get("fragment") == "1" {
			s.mu.Lock()
			var partial *DiffResult
			if c := s.jobs[key]; c != nil {
				partial = c.partial
			}
			s.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			if partial != nil {
				renderFragment(w, partial)
			}
			return
		}
		// Rendering never waits for a scanner or a free queue slot.
		if _, err := s.startCompute(key, old, new); errors.Is(err, errBusy) {
			w.Header().Set("Retry-After", "30")
		}
		renderHTML(w, old, new, nil)
		return
	}
	result, err := s.getOrCompute(r.Context(), s.key(old, new), old, new)
	if err != nil {
		if errors.Is(err, errBusy) {
			w.Header().Set("Retry-After", "30")
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		} else {
			http.Error(w, "Scan failed; inspect GET /jobs with the same parameters and service logs.", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
func (s *Server) handleBadge(w http.ResponseWriter, r *http.Request) {
	old, new, ok := refs(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "max-age=15, must-revalidate")
	key := s.key(old, new)
	if result := s.cached(key); result != nil {
		renderBadge(w, badgeSummary(result), badgeColor(result))
		return
	}
	label := "not scanned"
	s.mu.Lock()
	if c := s.jobs[key]; c != nil {
		label = c.job.State
		if label == "completed" {
			label = "stale"
		}
	}
	s.mu.Unlock()
	if label == "not scanned" {
		if r, _ := s.cache.Get(key); r != nil {
			label = "stale"
		}
	}
	color := "#9f9f9f"
	if label == "failed" {
		color = "#e05d44"
	}
	renderBadge(w, label, color)
}
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	old, new, ok := refs(w, r)
	if !ok {
		return
	}
	key := s.key(old, new)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", "/diff?"+url.Values{"old": {old}, "new": {new}}.Encode())
	if result := s.cached(key); result != nil {
		json.NewEncoder(w).Encode(Job{State: "completed", Stage: "completed", PackagesReady: true, FinishedAt: &result.Scan.ScannedAt})
		return
	}
	if r.Method == http.MethodGet {
		s.mu.Lock()
		c := s.jobs[key]
		var job Job
		if c != nil {
			job = c.job
		}
		s.mu.Unlock()
		if c == nil {
			job.State = "not_scanned"
			if r, _ := s.cache.Get(key); r != nil {
				job.State = "stale"
			}
			w.WriteHeader(http.StatusNotFound)
		} else if job.State == "completed" {
			job.State = "stale"
		}
		json.NewEncoder(w).Encode(job)
		return
	}
	c, err := s.startCompute(key, old, new)
	if err != nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.mu.Lock()
	job := c.job
	s.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(job)
}
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/progress.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write([]byte(progressJS))
	})
	mux.HandleFunc("GET /diff", s.handleDiff)
	mux.HandleFunc("GET /diff.json", s.handleDiff)
	mux.HandleFunc("GET /badge", s.handleBadge)
	mux.HandleFunc("POST /jobs", s.handleJobs)
	mux.HandleFunc("GET /jobs", s.handleJobs)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	return mux
}
func duration(name, def string) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		v = def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return d, nil
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dir := os.Getenv("CACHE_DIR")
	if dir == "" {
		dir = "/var/cache/digest-diff"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		slog.Error("invalid PORT")
		os.Exit(1)
	}
	ttl, err := duration("SCAN_TTL", "6h")
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	timeout, err := duration("SCAN_TIMEOUT", "15m")
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	scanner, err := newScanner(initCtx, dir)
	cancel()
	if err != nil {
		slog.Error("scanner initialization failed", "err", err)
		os.Exit(1)
	}
	s := NewServer(ctx, NewCache(dir+"/reports"), scanner, ttl, timeout)
	server := &http.Server{Addr: ":" + port, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	slog.Info("starting server", "port", port, "platform", platform, "syft", scanner.syftVersion, "grype", scanner.grypeVersion)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}
