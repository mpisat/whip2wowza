package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
	"github.com/sirupsen/logrus"
)

type VideoCodecPreference int

const (
	PreferCodecH264 VideoCodecPreference = iota
	PreferCodecVP8
)

type Config struct {
	WHIPAddress string
	WowzaWSURL  string

	VideoBitrateKbps int
	AudioBitrateKbps int
	VideoFPS         int

	Verbose     bool
	InsecureTLS bool
	LogFormat   string

	H264RepacketizeMode string
	PLIBurstCount       int
	PLIBurstInterval    time.Duration
	PLIBurstMinGap      time.Duration
	SRInterval          time.Duration

	ReadyTimeout   time.Duration
	MaxSessions    int
	ICEUDPMuxPort  int
	ICETCPMuxPort  int
	UDPPortMin     uint16
	UDPPortMax     uint16
	RetryAttempts  int
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration

	EnableIPv6 bool
	NAT1To1IP  string

	AllowedHosts string // Comma-separated list, supports wildcards like *.wowza.com
}

func NewConfig() *Config {
	c := &Config{
		WHIPAddress:         env("WHIP_ADDRESS", ":8080"),
		WowzaWSURL:          env("WOWZA_WEBSOCKET_URL", ""),
		VideoBitrateKbps:    envInt("VIDEO_BITRATE_KBPS", 800),
		AudioBitrateKbps:    envInt("AUDIO_BITRATE_KBPS", 96),
		VideoFPS:            envInt("VIDEO_FPS", 30),
		Verbose:             envBool("VERBOSE", false),
		InsecureTLS:         envBool("INSECURE_TLS", false),
		LogFormat:           env("LOG_FORMAT", "auto"),
		H264RepacketizeMode: env("H264_REPACKETIZE", "auto"),
		PLIBurstCount:       3,
		PLIBurstInterval:    250 * time.Millisecond,
		PLIBurstMinGap:      2 * time.Second,
		SRInterval:          envDuration("SR_INTERVAL", 5*time.Second),
		ReadyTimeout:        envDuration("VIDEO_READY_TIMEOUT", 15*time.Second),
		MaxSessions:         envInt("MAX_SESSIONS", 0),
		ICEUDPMuxPort:       envInt("ICE_UDP_MUX_PORT", 0),
		ICETCPMuxPort:       envInt("ICE_TCP_MUX_PORT", 0),
		UDPPortMin:          uint16(envInt("UDP_PORT_MIN", 10000)),
		UDPPortMax:          uint16(envInt("UDP_PORT_MAX", 12000)),
		RetryAttempts:       3,
		RetryBaseDelay:      time.Second,
		RetryMaxDelay:       8 * time.Second,
		EnableIPv6:          envBool("ENABLE_IPV6", false),
		NAT1To1IP:           env("NAT_1TO1_IP", ""),
		AllowedHosts:        env("ALLOWED_HOSTS", ""),
	}

	flag.StringVar(&c.WHIPAddress, "whip-address", c.WHIPAddress, "WHIP server bind address (env: WHIP_ADDRESS)")
	flag.StringVar(&c.WowzaWSURL, "websocket", c.WowzaWSURL, "Wowza WebSocket URL (env: WOWZA_WEBSOCKET_URL)")
	flag.IntVar(&c.VideoBitrateKbps, "video-bitrate-kbps", c.VideoBitrateKbps, "SDP bandwidth hint for video (b=AS line), not enforced")
	flag.IntVar(&c.AudioBitrateKbps, "audio-bitrate-kbps", c.AudioBitrateKbps, "SDP bandwidth hint for audio (b=AS line), not enforced")
	flag.IntVar(&c.VideoFPS, "video-fps", c.VideoFPS, "SDP framerate hint (a=framerate line), not enforced")
	flag.BoolVar(&c.Verbose, "verbose", c.Verbose, "Enable debug logging (env: VERBOSE)")
	flag.BoolVar(&c.InsecureTLS, "insecure-tls", c.InsecureTLS, "Skip TLS verification (env: INSECURE_TLS)")
	flag.StringVar(&c.H264RepacketizeMode, "h264-repacketize", c.H264RepacketizeMode, "H264 repacketization: off|on|auto (env: H264_REPACKETIZE)")
	flag.DurationVar(&c.ReadyTimeout, "video-ready-timeout", c.ReadyTimeout, "Max wait for first video RTP (env: VIDEO_READY_TIMEOUT)")
	flag.IntVar(&c.MaxSessions, "max-sessions", c.MaxSessions, "Maximum concurrent sessions, 0=unlimited (env: MAX_SESSIONS)")
	flag.DurationVar(&c.SRInterval, "sr-interval", c.SRInterval, "RTCP Sender Report interval (env: SR_INTERVAL)")
	flag.IntVar(&c.ICEUDPMuxPort, "ice-udp-mux-port", c.ICEUDPMuxPort, "Single UDP port for ICE, 0=use range (env: ICE_UDP_MUX_PORT)")
	flag.IntVar(&c.ICETCPMuxPort, "ice-tcp-mux-port", c.ICETCPMuxPort, "Single TCP port for ICE, 0=disabled (env: ICE_TCP_MUX_PORT)")
	flag.BoolVar(&c.EnableIPv6, "enable-ipv6", c.EnableIPv6, "Enable IPv6 ICE candidates on WHIP ingest side (env: ENABLE_IPV6)")
	flag.StringVar(&c.NAT1To1IP, "nat-1to1-ip", c.NAT1To1IP, "Comma-separated public IPs for ICE host candidates (env: NAT_1TO1_IP)")
	flag.StringVar(&c.AllowedHosts, "allowed-hosts", c.AllowedHosts, "Allowed Wowza hosts, comma-separated, supports wildcards (env: ALLOWED_HOSTS)")

	return c
}

// IsHostAllowed checks if a host is in the allowed list.
// Empty string or "*" means all hosts allowed.
func (c *Config) IsHostAllowed(host string) bool {
	allowed := strings.TrimSpace(c.AllowedHosts)
	if allowed == "" || allowed == "*" {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	for _, pattern := range strings.Split(allowed, ",") {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" || pattern == "*" {
			return true
		}
		if matchHost(pattern, host) {
			return true
		}
	}
	return false
}

func matchHost(pattern, host string) bool {
	if pattern == host {
		return true
	}
	// Wildcard match: *.example.com matches foo.example.com and bar.foo.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(host, suffix)
	}
	return false
}

func (c *Config) Logger() *logrus.Logger {
	log := logrus.New()

	format := strings.ToLower(c.LogFormat)
	if format == "auto" {
		if os.Getenv("TERM") != "" {
			format = "text"
		} else {
			format = "json"
		}
	}
	if format == "text" {
		log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, TimestampFormat: time.RFC3339, ForceColors: true})
	} else {
		log.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339})
	}

	level := logrus.InfoLevel
	if c.Verbose {
		level = logrus.DebugLevel
	}
	log.SetLevel(level)

	return log
}

func (c *Config) WebRTCAPI() (*webrtc.API, error) {
	media := &webrtc.MediaEngine{}

	// Header extensions for video
	for _, ext := range []string{
		"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
		"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
		"urn:3gpp:video-orientation",
	} {
		if err := media.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: ext}, webrtc.RTPCodecTypeVideo); err != nil {
			return nil, err
		}
	}

	// Audio codecs - stereo and mono Opus
	audioCodecs := []webrtc.RTPCodecParameters{
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "audio/opus", ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1;stereo=1;sprop-stereo=1"}, PayloadType: 111},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "audio/opus", ClockRate: 48000, Channels: 1, SDPFmtpLine: "minptime=10;useinbandfec=0"}, PayloadType: 96},
	}
	for _, codec := range audioCodecs {
		if err := media.RegisterCodec(codec, webrtc.RTPCodecTypeAudio); err != nil {
			return nil, err
		}
	}

	// Video codecs - H264 profiles + VP8
	videoCodecs := []webrtc.RTPCodecParameters{
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f", RTCPFeedback: defaultFeedback()}, PayloadType: 102},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f", RTCPFeedback: defaultFeedback()}, PayloadType: 105},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f", RTCPFeedback: defaultFeedback()}, PayloadType: 106},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f", RTCPFeedback: defaultFeedback()}, PayloadType: 103},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000, RTCPFeedback: defaultFeedback()}, PayloadType: 97},
	}
	for _, codec := range videoCodecs {
		if err := media.RegisterCodec(codec, webrtc.RTPCodecTypeVideo); err != nil {
			return nil, err
		}
	}

	settings := webrtc.SettingEngine{}
	settings.SetICETimeouts(30*time.Second, 30*time.Second, time.Second)

	nat1To1IPs, hasIPv4NAT, err := parseNAT1To1IPs(c.NAT1To1IP)
	if err != nil {
		return nil, err
	}
	if len(nat1To1IPs) > 0 {
		if !hasIPv4NAT {
			return nil, fmt.Errorf("NAT_1TO1_IP must include at least one IPv4 address for Wowza relay")
		}
		settings.SetNAT1To1IPs(nat1To1IPs, webrtc.ICECandidateTypeHost)
	}

	// ICE UDP configuration
	if c.ICEUDPMuxPort > 0 {
		// Single UDP port mode - all connections share one socket
		udpAddr := &net.UDPAddr{Port: c.ICEUDPMuxPort}
		network := "udp4"
		if c.EnableIPv6 {
			network = "udp"
			udpAddr = &net.UDPAddr{IP: net.IPv6zero, Port: c.ICEUDPMuxPort}
		}
		udpConn, err := net.ListenUDP(network, udpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s port %d: %w", network, c.ICEUDPMuxPort, err)
		}
		udpMux := ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: udpConn})
		settings.SetICEUDPMux(udpMux)
	} else {
		// Ephemeral port range mode
		settings.SetEphemeralUDPPortRange(c.UDPPortMin, c.UDPPortMax)
	}

	// ICE TCP configuration (optional)
	if c.ICETCPMuxPort > 0 {
		tcpAddr := &net.TCPAddr{Port: c.ICETCPMuxPort}
		network := "tcp4"
		if c.EnableIPv6 {
			network = "tcp"
			tcpAddr = &net.TCPAddr{IP: net.IPv6zero, Port: c.ICETCPMuxPort}
		}
		tcpListener, err := net.ListenTCP(network, tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s port %d: %w", network, c.ICETCPMuxPort, err)
		}
		tcpMux := ice.NewTCPMuxDefault(ice.TCPMuxParams{Listener: tcpListener})
		settings.SetICETCPMux(tcpMux)
	}

	// Enable both UDP and TCP for Wowza Cloud compatibility
	// TCP is needed for outbound connections to Wowza (port 1935)
	networkTypes := []webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
		webrtc.NetworkTypeTCP4,
	}
	if c.EnableIPv6 {
		networkTypes = append(networkTypes, webrtc.NetworkTypeUDP6, webrtc.NetworkTypeTCP6)
	}
	settings.SetNetworkTypes(networkTypes)

	return webrtc.NewAPI(webrtc.WithMediaEngine(media), webrtc.WithSettingEngine(settings)), nil
}

func defaultFeedback() []webrtc.RTCPFeedback {
	return []webrtc.RTCPFeedback{
		{Type: "nack"},
		{Type: "nack", Parameter: "pli"},
		{Type: "ccm", Parameter: "fir"},
		{Type: "goog-remb"},
		{Type: "transport-cc"},
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		v = strings.ToLower(v)
		return v == "true" || v == "1" || v == "yes"
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func parseNAT1To1IPs(raw string) ([]string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false, nil
	}

	parts := strings.Split(raw, ",")
	ips := make([]string, 0, len(parts))
	hasIPv4 := false
	for _, part := range parts {
		ipStr := strings.TrimSpace(part)
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, false, fmt.Errorf("invalid NAT_1TO1_IP value: %q", ipStr)
		}
		if ip.To4() != nil {
			hasIPv4 = true
		}
		ips = append(ips, ipStr)
	}

	if len(ips) == 0 {
		return nil, false, nil
	}

	return ips, hasIPv4, nil
}
