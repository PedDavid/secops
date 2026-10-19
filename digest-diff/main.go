package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
)

type call struct {
	done   chan struct{}
	result *DiffResult
	err    error
}

type Server struct {
	cache *Cache
	mu    sync.Mutex
	inflight map[string]*call
}

func NewServer(cache *Cache) *Server {
	return &Server{
		cache:    cache,
		inflight: make(map[string]*call),
	}
}

// startCompute enqueues a diff computation if none is already in progress for key.
// It returns the call immediately without blocking.
func (s *Server) startCompute(key, oldRef, newRef string) *call {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c, ok := s.inflight[key]; ok {
		return c
	}

	c := &call{done: make(chan struct{})}
	s.inflight[key] = c

	go func() {
		defer close(c.done)
		defer func() {
			s.mu.Lock()
			delete(s.inflight, key)
			s.mu.Unlock()
		}()

		oldPkgs, err := scanImage(oldRef)
		if err != nil {
			c.err = err
			return
		}
		newPkgs, err := scanImage(newRef)
		if err != nil {
			c.err = err
			return
		}

		result := computeDiff(oldPkgs, newPkgs)
		if err := s.cache.Set(key, result); err != nil {
			slog.Warn("failed to write cache", "key", key, "err", err)
		}
		c.result = result
	}()

	return c
}

// getOrCompute returns a cached result or blocks until the diff is computed.
func (s *Server) getOrCompute(key, oldRef, newRef string) (*DiffResult, error) {
	if result, err := s.cache.Get(key); err == nil && result != nil {
		return result, nil
	}
	c := s.startCompute(key, oldRef, newRef)
	<-c.done
	return c.result, c.err
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	oldRef := r.URL.Query().Get("old")
	newRef := r.URL.Query().Get("new")
	if oldRef == "" || newRef == "" {
		http.Error(w, "old and new query params are required", http.StatusBadRequest)
		return
	}

	key := cacheKey(oldRef, newRef)
	result, err := s.getOrCompute(key, oldRef, newRef)
	if err != nil {
		slog.Error("diff failed", "old", oldRef, "new", newRef, "err", err)
		http.Error(w, "diff computation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	renderHTML(w, oldRef, newRef, result)
}

func (s *Server) handleDiffJSON(w http.ResponseWriter, r *http.Request) {
	oldRef := r.URL.Query().Get("old")
	newRef := r.URL.Query().Get("new")
	if oldRef == "" || newRef == "" {
		http.Error(w, "old and new query params are required", http.StatusBadRequest)
		return
	}

	key := cacheKey(oldRef, newRef)
	result, err := s.getOrCompute(key, oldRef, newRef)
	if err != nil {
		slog.Error("diff failed", "old", oldRef, "new", newRef, "err", err)
		http.Error(w, "diff computation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleBadge(w http.ResponseWriter, r *http.Request) {
	oldRef := r.URL.Query().Get("old")
	newRef := r.URL.Query().Get("new")
	if oldRef == "" || newRef == "" {
		http.Error(w, "old and new query params are required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "image/svg+xml")

	key := cacheKey(oldRef, newRef)
	result, err := s.cache.Get(key)
	if err != nil {
		slog.Error("cache read failed for badge", "err", err)
	}

	if result == nil {
		// Job is pending or not yet submitted — return a transient badge and let
		// the client retry. Cache-Control is intentionally short so the browser
		// re-fetches once the result is ready.
		w.Header().Set("Cache-Control", "max-age=15")
		renderBadge(w, "pending", "#9f9f9f")
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	renderBadge(w, badgeSummary(result), badgeColor(result))
}

// handleJobs enqueues a diff computation in the background and returns immediately.
// POST /jobs?old=<image@sha256:digest>&new=<image@sha256:digest>
// → 200 OK + Location if already cached
// → 202 Accepted + Location if enqueued
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	oldRef := r.URL.Query().Get("old")
	newRef := r.URL.Query().Get("new")
	if oldRef == "" || newRef == "" {
		http.Error(w, "old and new query params are required", http.StatusBadRequest)
		return
	}

	loc := "/diff?old=" + url.QueryEscape(oldRef) + "&new=" + url.QueryEscape(newRef)
	w.Header().Set("Location", loc)

	key := cacheKey(oldRef, newRef)
	if result, _ := s.cache.Get(key); result != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	s.startCompute(key, oldRef, newRef)
	w.WriteHeader(http.StatusAccepted)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func main() {
	cacheDir := os.Getenv("CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/var/cache/digest-diff"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := NewServer(NewCache(cacheDir))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /diff", srv.handleDiff)
	mux.HandleFunc("GET /diff.json", srv.handleDiffJSON)
	mux.HandleFunc("GET /badge", srv.handleBadge)
	mux.HandleFunc("POST /jobs", srv.handleJobs)
	mux.HandleFunc("GET /healthz", handleHealth)

	slog.Info("starting server", "port", port, "cache_dir", cacheDir)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}
