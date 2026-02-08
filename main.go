package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

var (
	Version   = "1.0.1"
	GitCommit = "dev"
	BuildDate = "unknown"
)

func main() {
	cfg := NewConfig()
	flag.Parse()

	logger := cfg.Logger()

	fields := logrus.Fields{
		"event":     "startup",
		"version":   Version,
		"whip_addr": cfg.WHIPAddress,
	}
	if cfg.WowzaWSURL != "" {
		fields["wowza_url"] = cfg.WowzaWSURL
		fields["mode"] = "legacy"
	} else {
		fields["mode"] = "cloud"
	}
	logger.WithFields(fields).Info("Starting WHIP to Wowza gateway")

	api, err := cfg.WebRTCAPI()
	if err != nil {
		logger.WithError(err).Fatal("Failed to create WebRTC API")
	}

	mgr := NewManager(cfg, api, logger)
	srv := NewServer(cfg, mgr, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	select {
	case sig := <-sigCh:
		logger.WithField("signal", sig.String()).Info("Shutdown signal received")
		cancel()
		if err := <-errCh; err != nil {
			logger.WithError(err).Error("Server shutdown error")
			os.Exit(1)
		}
	case err := <-errCh:
		if err != nil {
			logger.WithError(err).Fatal("Server error")
		}
	}

	logger.Info("Shutdown complete")
}
