package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Server struct {
	cfg    *Config
	mgr    *Manager
	logger *logrus.Logger
	server *http.Server
}

func NewServer(cfg *Config, mgr *Manager, logger *logrus.Logger) *Server {
	return &Server{cfg: cfg, mgr: mgr, logger: logger}
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Legacy WHIP endpoints (require -websocket flag)
	mux.HandleFunc("/api/whip", s.wrapWHIP("/api/whip", PreferCodecH264))
	mux.HandleFunc("/api/whip/", s.wrapWHIP("/api/whip", PreferCodecH264))
	mux.HandleFunc("/api/whip-vp8", s.wrapWHIP("/api/whip-vp8", PreferCodecVP8))
	mux.HandleFunc("/api/whip-vp8/", s.wrapWHIP("/api/whip-vp8", PreferCodecVP8))

	// Cloud endpoints (dynamic Wowza host per request)
	mux.HandleFunc("/api/cloud/", s.wrapCloud("/api/cloud", PreferCodecH264))
	mux.HandleFunc("/api/cloud-vp8/", s.wrapCloud("/api/cloud-vp8", PreferCodecVP8))

	// Static files and utilities
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/stats", s.handleStats)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	s.server = &http.Server{
		Addr:              s.cfg.WHIPAddress,
		Handler:           s.withLogging(s.withCORS(mux)),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	s.logger.WithField("address", s.cfg.WHIPAddress).Info("HTTP server started")

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.Stop(shutdownCtx)
	}
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server != nil {
		_ = s.server.Shutdown(ctx)
	}
	return s.mgr.Shutdown(ctx)
}

func (s *Server) wrapWHIP(prefix string, pref VideoCodecPreference) http.HandlerFunc {
	trimmed := strings.TrimSuffix(prefix, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		urlPath := strings.TrimPrefix(r.URL.Path, trimmed)
		urlPath = strings.TrimPrefix(urlPath, "/")
		s.handleWHIP(w, r, pref, urlPath)
	}
}

func (s *Server) handleWHIP(w http.ResponseWriter, r *http.Request, pref VideoCodecPreference, urlPath string) {
	// Legacy WHIP endpoints require -websocket flag
	if s.cfg.WowzaWSURL == "" {
		http.Error(w, "websocket URL not configured - use /api/cloud/ endpoints or start with -websocket flag", http.StatusServiceUnavailable)
		return
	}

	if urlPath == "" {
		http.Error(w, "application path required", http.StatusBadRequest)
		return
	}

	parts := strings.Split(urlPath, "/")
	if len(parts) > 0 && strings.HasPrefix(parts[len(parts)-1], "session-") {
		app := strings.Join(parts[:len(parts)-1], "/")
		s.handleSessionVerb(w, r, parts[len(parts)-1], app)
		return
	}

	switch r.Method {
	case http.MethodPost:
		s.handleCreate(w, r, urlPath, "", pref) // Empty wsURL = use config
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSessionVerb(w http.ResponseWriter, r *http.Request, sessionID, app string) {
	switch r.Method {
	case http.MethodDelete:
		if _, ok := s.mgr.Get(sessionID); !ok {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		s.mgr.Remove(sessionID)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// wrapCloud handles /api/cloud/{host}/{app...} endpoints
func (s *Server) wrapCloud(prefix string, pref VideoCodecPreference) http.HandlerFunc {
	trimmed := strings.TrimSuffix(prefix, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		urlPath := strings.TrimPrefix(r.URL.Path, trimmed)
		urlPath = strings.TrimPrefix(urlPath, "/")
		s.handleCloud(w, r, pref, urlPath)
	}
}

func (s *Server) handleCloud(w http.ResponseWriter, r *http.Request, pref VideoCodecPreference, urlPath string) {
	if urlPath == "" {
		http.Error(w, "host and application path required", http.StatusBadRequest)
		return
	}

	// Parse: {host}/{app...} or {host}/{app}/session-xxx
	parts := strings.SplitN(urlPath, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "format: /api/cloud/{host}/{app}", http.StatusBadRequest)
		return
	}

	host := parts[0]
	appPath := parts[1]

	// Validate host
	if !isValidHost(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// Check allowed hosts
	if !s.cfg.IsHostAllowed(host) {
		s.logger.WithField("host", host).Warn("Host not in allowed list")
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	// Check for session verb (DELETE)
	appParts := strings.Split(appPath, "/")
	if len(appParts) > 0 && strings.HasPrefix(appParts[len(appParts)-1], "session-") {
		app := strings.Join(appParts[:len(appParts)-1], "/")
		s.handleSessionVerb(w, r, appParts[len(appParts)-1], app)
		return
	}

	// Build WebSocket URL
	// If host contains a dot, treat as full hostname (on-prem)
	// Otherwise, treat as Wowza Cloud ID
	var wsURL string
	if strings.Contains(host, ".") {
		wsURL = fmt.Sprintf("wss://%s/webrtc-session.json", host)
	} else {
		wsURL = fmt.Sprintf("wss://%s.entrypoint.cloud.wowza.com/webrtc-session.json", host)
	}

	switch r.Method {
	case http.MethodPost:
		s.handleCreate(w, r, appPath, wsURL, pref)
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// isValidHost validates the host (alphanumeric with optional dots and hyphens)
func isValidHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, r := range host {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-') {
			return false
		}
	}
	// Don't allow consecutive dots or starting/ending with dot/hyphen
	if strings.Contains(host, "..") || host[0] == '.' || host[0] == '-' || host[len(host)-1] == '.' || host[len(host)-1] == '-' {
		return false
	}
	return true
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request, app, wsURL string, pref VideoCodecPreference) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "Bearer token required", http.StatusUnauthorized)
		return
	}
	streamKey := strings.TrimPrefix(auth, "Bearer ")
	if streamKey == "" {
		http.Error(w, "Bearer token required", http.StatusUnauthorized)
		return
	}

	appClean, err := sanitizeAppPath(app)
	if err != nil {
		s.logger.WithError(err).WithField("app", app).Warn("Invalid app path")
		http.Error(w, "invalid application path", http.StatusBadRequest)
		return
	}

	if err := validateStreamKey(streamKey); err != nil {
		s.logger.WithError(err).WithField("stream_key", redactStreamKey(streamKey)).Warn("Invalid stream key")
		http.Error(w, "invalid stream key", http.StatusBadRequest)
		return
	}

	offer, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "failed to read offer", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	s.logger.WithFields(logrus.Fields{
		"event":      "whip_request",
		"app":        appClean,
		"codec_pref": codecPrefString(pref),
		"user_agent": r.Header.Get("User-Agent"),
	}).Info("WHIP create request")

	sessionID, session, err := s.mgr.Create(streamKey, appClean, pref, wsURL)
	if err != nil {
		status := http.StatusInternalServerError
		msg := "failed to create session"
		if errors.Is(err, ErrMaxSessions) {
			status = http.StatusServiceUnavailable
			msg = "session capacity reached"
		}
		s.logger.WithError(err).WithField("app", appClean).Error("Failed to create session")
		http.Error(w, msg, status)
		return
	}

	answer, err := session.ProcessOffer(string(offer))
	if err != nil {
		s.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to process offer")
		s.mgr.Remove(sessionID)
		http.Error(w, "failed to process offer", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/sdp")
	w.Header().Set("Location", path.Join(r.URL.Path, sessionID))
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(answer))

	s.logger.WithFields(logrus.Fields{
		"event":      "whip_session_ready",
		"session_id": sessionID,
		"app":        appClean,
	}).Info("Session ready")
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]any{
		"status":          "healthy",
		"active_sessions": len(s.mgr.ActiveIDs()),
		"timestamp":       time.Now().Unix(),
		"version":         Version,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.mgr.Stats())
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Expose-Headers", "Location")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if r.URL.Path == "/health" {
			return
		}
		s.logger.WithFields(logrus.Fields{
			"event":    "http_request",
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   sw.status,
			"duration": time.Since(start).String(),
		}).Info("HTTP request")
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

var appSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func sanitizeAppPath(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("application path required")
	}
	if strings.Contains(raw, "..") {
		return "", fmt.Errorf("path traversal not allowed")
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+raw), "/")
	if cleaned == "" {
		return "", fmt.Errorf("application path required")
	}
	segments := strings.Split(cleaned, "/")
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("invalid path segment")
		}
		if !appSegmentRe.MatchString(seg) {
			return "", fmt.Errorf("invalid path segment")
		}
	}
	return strings.Join(segments, "/"), nil
}

func validateStreamKey(key string) error {
	if key == "" {
		return fmt.Errorf("stream key required")
	}
	if len(key) > 256 {
		return fmt.Errorf("stream key too long")
	}
	if strings.ContainsAny(key, "/\\") {
		return fmt.Errorf("stream key may not contain path separators")
	}
	for _, r := range key {
		if r < 33 || r > 126 {
			return fmt.Errorf("stream key contains invalid characters")
		}
	}
	return nil
}

func redactStreamKey(key string) string {
	parts := strings.Split(key, "?")
	if len(parts) == 1 {
		return key
	}
	stream := parts[0]
	token := strings.TrimPrefix(parts[1], "token=")
	if len(token) <= 8 {
		return key
	}
	masked := token[:4] + "..." + token[len(token)-4:]
	return fmt.Sprintf("%s?token=%s", stream, masked)
}

func codecPrefString(pref VideoCodecPreference) string {
	switch pref {
	case PreferCodecH264:
		return "h264"
	case PreferCodecVP8:
		return "vp8"
	default:
		return "auto"
	}
}
