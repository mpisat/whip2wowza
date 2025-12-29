package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"
	"github.com/sirupsen/logrus"
)

var ErrMaxSessions = errors.New("max sessions reached")

type Manager struct {
	cfg    *Config
	api    *webrtc.API
	logger *logrus.Logger

	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewManager(cfg *Config, api *webrtc.API, logger *logrus.Logger) *Manager {
	return &Manager{
		cfg:      cfg,
		api:      api,
		logger:   logger,
		sessions: make(map[string]*Session),
	}
}

func (m *Manager) Create(streamKey, appName string, pref VideoCodecPreference, wsURL string) (string, *Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.MaxSessions > 0 && len(m.sessions) >= m.cfg.MaxSessions {
		return "", nil, ErrMaxSessions
	}

	id := fmt.Sprintf("session-%s", uuid.New().String())
	sess, err := NewSession(id, streamKey, appName, pref, wsURL, m.cfg, m.api, m.logger)
	if err != nil {
		return "", nil, err
	}

	sess.SetStopCallback(m.onSessionStopped)
	m.sessions[id] = sess

	m.logger.WithFields(logrus.Fields{
		"event":      "session_created",
		"session_id": id,
		"app":        appName,
		"stream_key": redactStreamKey(streamKey),
		"active":     len(m.sessions),
	}).Info("Session created")

	return id, sess, nil
}

func (m *Manager) onSessionStopped(id string) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()

	fields := logrus.Fields{
		"event":      "session_removed",
		"session_id": id,
		"active":     len(m.sessions),
	}
	if sess != nil {
		fields["app"] = sess.appName
	}
	m.logger.WithFields(fields).Info("Session removed")
}

func (m *Manager) Remove(id string) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()

	if ok && sess != nil {
		go sess.Stop()
	}
}

func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[id]
	return sess, ok
}

func (m *Manager) ActiveIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		out = append(out, id)
	}
	return out
}

func (m *Manager) Stats() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := make([]map[string]any, 0, len(m.sessions))
	for _, sess := range m.sessions {
		sessions = append(sessions, sess.Stats())
	}
	return map[string]any{
		"active_sessions": len(m.sessions),
		"timestamp":       time.Now().Unix(),
		"sessions":        sessions,
	}
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.RLock()
	snapshot := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		snapshot = append(snapshot, s)
	}
	m.mu.RUnlock()

	if len(snapshot) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	for _, s := range snapshot {
		wg.Add(1)
		go func(ss *Session) {
			defer wg.Done()
			_ = ss.Stop()
		}(s)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
