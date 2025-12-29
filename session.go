package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/rtcp"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type Session struct {
	id        string
	streamKey string
	appName   string
	pref      VideoCodecPreference
	wsURL     string // Per-session WebSocket URL (overrides config if set)

	cfg    *Config
	api    *webrtc.API
	logger *logrus.Entry

	ctx    context.Context
	cancel context.CancelFunc

	pubPC   *webrtc.PeerConnection // Publisher (browser) peer connection
	wowzaPC *webrtc.PeerConnection // Wowza peer connection
	wowzaWS *websocket.Conn

	tracks  map[string]*webrtc.TrackLocalStaticRTP
	trackMu sync.RWMutex

	videoReady   chan struct{}
	wowzaReady   chan struct{}
	closed       atomic.Bool
	dialOnce     sync.Once
	readyTimer   *time.Timer
	readyTimerMu sync.Mutex

	// Video track info for RTCP SR
	videoSSRC      atomic.Uint32
	videoCodec     atomic.Value // string
	videoProfile   atomic.Value // string
	videoPM        atomic.Int32 // packetization-mode
	videoPackets   atomic.Uint64
	videoOctets    atomic.Uint64
	videoTimestamp atomic.Uint32

	// Audio track info
	audioChannels int

	// Browser H264 offer info
	browserH264Order   []string
	browserH264Profile map[string]string
	browserH264PM1     map[string]bool
	browserH264FMTP    map[string]string
	browserAnyPM1      bool
	browserVP8PT       int // Browser's VP8 payload type (-1 if not found)

	pliLastBurst time.Time

	onStop   func(string)
	stopOnce atomic.Bool
}

func NewSession(id, streamKey, appName string, pref VideoCodecPreference, wsURL string, cfg *Config, api *webrtc.API, logger *logrus.Logger) (*Session, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		id:                 id,
		streamKey:          streamKey,
		appName:            appName,
		pref:               pref,
		wsURL:              wsURL,
		cfg:                cfg,
		api:                api,
		logger:             logger.WithField("session_id", id),
		ctx:                ctx,
		cancel:             cancel,
		tracks:             make(map[string]*webrtc.TrackLocalStaticRTP),
		videoReady:         make(chan struct{}),
		wowzaReady:         make(chan struct{}),
		browserH264Profile: make(map[string]string),
		browserH264PM1:     make(map[string]bool),
		browserH264FMTP:    make(map[string]string),
		audioChannels:      1,
	}
	s.videoPM.Store(-1)
	s.browserVP8PT = -1

	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}},
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create publisher peer connection: %w", err)
	}
	s.pubPC = pc
	s.setupPublisherCallbacks()

	return s, nil
}

func (s *Session) SetStopCallback(fn func(string)) { s.onStop = fn }

func (s *Session) ProcessOffer(offer string) (string, error) {
	s.inspectOffer(offer)

	if err := s.pubPC.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		return "", fmt.Errorf("set remote description: %w", err)
	}

	s.applyCodecPreference()

	answer, err := s.pubPC.CreateAnswer(nil)
	if err != nil {
		return "", fmt.Errorf("create answer: %w", err)
	}
	if err := s.pubPC.SetLocalDescription(answer); err != nil {
		return "", fmt.Errorf("set local description: %w", err)
	}
	<-webrtc.GatheringCompletePromise(s.pubPC)

	if s.cfg.ReadyTimeout > 0 {
		s.startReadyTimer(s.cfg.ReadyTimeout)
	}

	return s.pubPC.LocalDescription().SDP, nil
}

func (s *Session) Stop() error {
	if !s.stopOnce.CompareAndSwap(false, true) {
		return nil
	}
	s.logger.Info("Stopping session")
	s.closed.Store(true)
	s.stopReadyTimer()
	s.cancel()

	if s.wowzaWS != nil {
		_ = s.wowzaWS.Close()
	}
	if s.wowzaPC != nil {
		_ = s.wowzaPC.Close()
	}
	if s.pubPC != nil {
		_ = s.pubPC.Close()
	}

	if s.onStop != nil {
		s.onStop(s.id)
	}
	return nil
}

func (s *Session) Stats() map[string]any {
	codec := ""
	if v := s.videoCodec.Load(); v != nil {
		codec, _ = v.(string)
	}
	return map[string]any{
		"id":          s.id,
		"app":         s.appName,
		"video_codec": codec,
		"audio_ch":    s.audioChannels,
	}
}

// setupPublisherCallbacks sets up browser peer connection event handlers
func (s *Session) setupPublisherCallbacks() {
	s.pubPC.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		s.logger.WithField("state", state.String()).Debug("Publisher ICE state")
		if state == webrtc.ICEConnectionStateFailed || state == webrtc.ICEConnectionStateDisconnected || state == webrtc.ICEConnectionStateClosed {
			_ = s.Stop()
		}
	})

	s.pubPC.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		s.logger.WithFields(logrus.Fields{
			"kind":  track.Kind().String(),
			"codec": track.Codec().MimeType,
		}).Info("Track received from publisher")

		if track.Kind() == webrtc.RTPCodecTypeVideo {
			s.handleVideoTrack(track)
		}

		local, err := webrtc.NewTrackLocalStaticRTP(track.Codec().RTPCodecCapability, track.ID(), track.StreamID())
		if err != nil {
			s.logger.WithError(err).Error("Failed to create local track")
			return
		}

		key := track.Kind().String()
		s.trackMu.Lock()
		s.tracks[key] = local
		s.trackMu.Unlock()

		go s.forwardRTP(track, local)
		s.maybeDialWowza()
	})
}

func (s *Session) handleVideoTrack(track *webrtc.TrackRemote) {
	mime := strings.ToLower(track.Codec().MimeType)
	if strings.Contains(mime, "h264") {
		s.videoCodec.Store("h264")
		profile, pm := parseH264Params(track.Codec().SDPFmtpLine)
		if profile != "" {
			s.videoProfile.Store(profile)
		}
		if pm >= 0 {
			s.videoPM.Store(int32(pm))
		}
	} else if strings.Contains(mime, "vp8") {
		s.videoCodec.Store("vp8")
	}
	s.videoSSRC.Store(uint32(track.SSRC()))

	select {
	case <-s.videoReady:
	default:
		close(s.videoReady)
	}
}

// inspectOffer parses browser offer to extract H264 profiles, VP8 PT, and audio channels
func (s *Session) inspectOffer(offerSDP string) {
	s.browserH264Order = nil
	for k := range s.browserH264Profile {
		delete(s.browserH264Profile, k)
	}
	for k := range s.browserH264PM1 {
		delete(s.browserH264PM1, k)
	}
	for k := range s.browserH264FMTP {
		delete(s.browserH264FMTP, k)
	}
	s.browserAnyPM1 = false
	s.browserVP8PT = -1
	s.audioChannels = 1

	var parsed sdp.SessionDescription
	if err := parsed.Unmarshal([]byte(offerSDP)); err != nil {
		return
	}

	for _, md := range parsed.MediaDescriptions {
		switch strings.ToLower(md.MediaName.Media) {
		case "audio":
			s.inspectAudio(md)
		case "video":
			s.inspectVideo(md)
		}
	}
}

func (s *Session) inspectAudio(md *sdp.MediaDescription) {
	rtpmap := rtpMapByPayload(md)
	for _, format := range md.MediaName.Formats {
		enc := strings.ToLower(rtpmap[format])
		if strings.Contains(enc, "opus/48000") {
			parts := strings.Split(enc, "/")
			if len(parts) >= 3 {
				if val, err := strconv.Atoi(parts[2]); err == nil && (val == 1 || val == 2) {
					s.audioChannels = val
					return
				}
			}
		}
	}
}

func (s *Session) inspectVideo(md *sdp.MediaDescription) {
	rtpmap := rtpMapByPayload(md)
	fmtpMap := fmtpMapByPayload(md)

	for _, format := range md.MediaName.Formats {
		enc := strings.ToLower(rtpmap[format])

		// Check for VP8
		if strings.Contains(enc, "vp8") && s.browserVP8PT < 0 {
			if pt, err := strconv.Atoi(format); err == nil {
				s.browserVP8PT = pt
			}
			continue
		}

		// Check for H264
		if !strings.Contains(enc, "h264") {
			continue
		}

		s.browserH264Order = append(s.browserH264Order, format)
		params := strings.TrimSpace(fmtpMap[format])
		s.browserH264FMTP[format] = params

		profile, pm := parseH264Params(params)
		if profile != "" {
			s.browserH264Profile[format] = strings.ToLower(profile)
		}
		if pm == 1 {
			s.browserH264PM1[format] = true
			s.browserAnyPM1 = true
		} else if pm == 0 {
			s.browserH264PM1[format] = false
		}
	}
}

// applyCodecPreference sets codec preference on transceiver
func (s *Session) applyCodecPreference() {
	if s.pref == PreferCodecVP8 {
		// Use browser's VP8 PT if found, otherwise default to 97
		pt := webrtc.PayloadType(97)
		if s.browserVP8PT > 0 {
			pt = webrtc.PayloadType(s.browserVP8PT)
		}
		s.setVideoPrefs([]webrtc.RTPCodecParameters{
			{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000, RTCPFeedback: defaultFeedback()}, PayloadType: pt},
		})
		return
	}

	if !s.browserAnyPM1 {
		return // Firefox PM=0 case, let it negotiate naturally
	}

	opts := s.buildH264Options()
	if len(opts) > 0 {
		s.setVideoPrefs([]webrtc.RTPCodecParameters{opts[0].codec})
	}
}

type h264Option struct {
	codec   webrtc.RTPCodecParameters
	profile string
}

func (s *Session) buildH264Options() []h264Option {
	type candidate struct {
		opt   h264Option
		rank  int
		order int
	}
	var list []candidate
	seen := map[string]bool{}
	codecs := h264CodecMap()

	for idx, pt := range s.browserH264Order {
		prof := s.browserH264Profile[pt]
		if prof == "" || !s.browserH264PM1[pt] {
			continue
		}
		canonical, ok := canonicalH264Profile(prof)
		if !ok || seen[canonical] {
			continue
		}
		codec, ok := codecs[canonical]
		if !ok {
			continue
		}
		// Use browser's FMTP if available
		if fmtp := s.browserH264FMTP[pt]; fmtp != "" {
			codec.RTPCodecCapability.SDPFmtpLine = fmtp
		}
		// Mirror browser's PT
		if ptNum, err := strconv.Atoi(pt); err == nil {
			codec.PayloadType = webrtc.PayloadType(ptNum)
		}
		list = append(list, candidate{opt: h264Option{codec: codec, profile: prof}, rank: rankH264Profile(prof), order: idx})
		seen[canonical] = true
	}

	if len(list) == 0 {
		return nil
	}

	sort.SliceStable(list, func(i, j int) bool {
		if list[i].rank == list[j].rank {
			return list[i].order < list[j].order
		}
		return list[i].rank < list[j].rank
	})

	opts := make([]h264Option, len(list))
	for i, c := range list {
		opts[i] = c.opt
	}
	return opts
}

func (s *Session) setVideoPrefs(prefs []webrtc.RTPCodecParameters) {
	for _, tr := range s.pubPC.GetTransceivers() {
		if tr == nil || tr.Kind() != webrtc.RTPCodecTypeVideo {
			continue
		}
		_ = tr.SetCodecPreferences(prefs)
		return
	}
}

// maybeDialWowza connects to Wowza when video is ready
func (s *Session) maybeDialWowza() {
	s.trackMu.RLock()
	_, haveVideo := s.tracks["video"]
	s.trackMu.RUnlock()

	if !haveVideo {
		return
	}

	s.dialOnce.Do(func() {
		s.stopReadyTimer()
		s.logger.Debug("Video ready, connecting to Wowza")
		go func() {
			if err := s.connectWowza(); err != nil {
				s.logger.WithError(err).Error("Wowza connection failed")
				_ = s.Stop()
			}
		}()
	})
}

func (s *Session) connectWowza() error {
	attempts := s.cfg.RetryAttempts
	if attempts <= 0 {
		attempts = 1
	}
	baseDelay := s.cfg.RetryBaseDelay
	maxDelay := s.cfg.RetryMaxDelay

	for attempt := 1; attempt <= attempts; attempt++ {
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		if attempt > 1 {
			delay := baseDelay * time.Duration(1<<uint(attempt-2))
			if delay > maxDelay {
				delay = maxDelay
			}
			if n, err := crand.Int(crand.Reader, big.NewInt(int64(delay/2))); err == nil {
				delay += time.Duration(n.Int64())
			}
			s.logger.WithField("attempt", attempt).Warn("Retrying Wowza connection")
			select {
			case <-time.After(delay):
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
		}
		if err := s.dialWowza(); err != nil {
			if attempt == attempts {
				return err
			}
			s.logger.WithError(err).Warn("Wowza dial failed")
			continue
		}
		return nil
	}
	return fmt.Errorf("wowza connection failed")
}

func (s *Session) dialWowza() error {
	wsURL := s.wsURL
	if wsURL == "" {
		wsURL = s.cfg.WowzaWSURL
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: s.cfg.InsecureTLS},
	}
	conn, _, err := dialer.DialContext(s.ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	s.wowzaWS = conn
	go func() { <-s.ctx.Done(); _ = conn.Close() }()

	pc, err := s.api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		conn.Close()
		return fmt.Errorf("create wowza peer connection: %w", err)
	}
	s.wowzaPC = pc
	go func() { <-s.ctx.Done(); _ = pc.Close() }()

	s.trackMu.RLock()
	for kind, trk := range s.tracks {
		if _, err := pc.AddTrack(trk); err != nil {
			s.trackMu.RUnlock()
			pc.Close()
			conn.Close()
			return fmt.Errorf("add %s track: %w", kind, err)
		}
	}
	s.trackMu.RUnlock()

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		s.logger.WithField("state", state.String()).Debug("Wowza ICE state")
		if state == webrtc.ICEConnectionStateConnected {
			select {
			case <-s.wowzaReady:
			default:
				close(s.wowzaReady)
			}
			go s.requestKeyframe("wowza_connected")
		} else if state == webrtc.ICEConnectionStateFailed || state == webrtc.ICEConnectionStateDisconnected || state == webrtc.ICEConnectionStateClosed {
			_ = s.Stop()
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		pc.Close()
		conn.Close()
		return fmt.Errorf("create offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		pc.Close()
		conn.Close()
		return fmt.Errorf("set local description: %w", err)
	}
	<-webrtc.GatheringCompletePromise(pc)

	snap := s.buildSnapshot()
	munged := mungeSDP(pc.LocalDescription().SDP, s.cfg, snap)

	wowzaOffer := WowzaOffer{}
	wowzaOffer.Direction = "publish"
	wowzaOffer.Command = "sendOffer"
	wowzaOffer.StreamInfo.ApplicationName = snap.AppName
	wowzaOffer.StreamInfo.StreamName = snap.WowzaStreamName
	wowzaOffer.SDP.Type = "offer"
	wowzaOffer.SDP.SDP = munged

	s.logger.WithFields(logrus.Fields{
		"app":    snap.AppName,
		"stream": snap.StreamName,
		"codec":  snap.VideoCodec,
	}).Info("Sending offer to Wowza")

	if s.logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
		s.logger.Debug("Wowza offer SDP:\n" + munged)
	}

	if err := conn.WriteJSON(&wowzaOffer); err != nil {
		pc.Close()
		conn.Close()
		return fmt.Errorf("send offer: %w", err)
	}

	var answer WowzaAnswer
	if err := conn.ReadJSON(&answer); err != nil {
		pc.Close()
		conn.Close()
		return fmt.Errorf("read answer: %w", err)
	}
	if answer.Status < 200 || answer.Status >= 300 {
		pc.Close()
		conn.Close()
		return fmt.Errorf("wowza status %d", answer.Status)
	}

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer.SDP.SDP}); err != nil {
		pc.Close()
		conn.Close()
		return fmt.Errorf("set remote description: %w", err)
	}

	// Add ICE candidates with Wowza Cloud fixes
	for _, cand := range answer.ICECandidates {
		cleaned := cleanWowzaCandidate(cand.Candidate)
		_ = pc.AddICECandidate(webrtc.ICECandidateInit{
			Candidate:     cleaned,
			SDPMid:        cand.SDPMid,
			SDPMLineIndex: cand.SDPMLineIndex,
		})
	}

	go s.runSessionLoops()

	return nil
}

func (s *Session) runSessionLoops() {
	g, ctx := errgroup.WithContext(s.ctx)

	g.Go(func() error {
		return s.sendSenderReports(ctx)
	})

	for _, sender := range s.wowzaPC.GetSenders() {
		sender := sender
		if sender.Track() == nil {
			continue
		}
		g.Go(func() error {
			return s.relayWowzaRTCP(ctx, sender)
		})
	}

	if err := g.Wait(); err != nil {
		s.logger.WithError(err).Error("Session loop failed")
		_ = s.Stop()
	}
}

// sendSenderReports sends RTCP SR to browser for timing sync
func (s *Session) sendSenderReports(ctx context.Context) error {
	ticker := time.NewTicker(s.cfg.SRInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ssrc := s.videoSSRC.Load()
			if ssrc == 0 || s.pubPC == nil {
				continue
			}
			sr := &rtcp.SenderReport{
				SSRC:        ssrc,
				NTPTime:     toNTPTime(time.Now()),
				RTPTime:     s.videoTimestamp.Load(),
				PacketCount: uint32(s.videoPackets.Load()),
				OctetCount:  uint32(s.videoOctets.Load()),
			}
			if err := s.pubPC.WriteRTCP([]rtcp.Packet{sr}); err != nil {
				s.logger.WithError(err).Debug("Failed to send SR")
			}
		}
	}
}

// relayWowzaRTCP relays RTCP from Wowza to browser
func (s *Session) relayWowzaRTCP(ctx context.Context, sender *webrtc.RTPSender) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		pkts, _, err := sender.ReadRTCP()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		for _, pkt := range pkts {
			switch p := pkt.(type) {
			case *rtcp.PictureLossIndication:
				s.forwardPLI(p.MediaSSRC)
			case *rtcp.FullIntraRequest:
				// Convert FIR to PLI - browsers respond better to PLI
				s.forwardPLI(p.MediaSSRC)
			case *rtcp.SenderReport:
				s.forwardSR(p)
			}
		}
	}
}

func (s *Session) forwardPLI(mediaSSRC uint32) {
	ssrc := s.videoSSRC.Load()
	if ssrc == 0 || s.pubPC == nil {
		return
	}
	pli := &rtcp.PictureLossIndication{MediaSSRC: ssrc}
	if err := s.pubPC.WriteRTCP([]rtcp.Packet{pli}); err != nil {
		s.logger.WithError(err).Debug("Failed to forward PLI")
	} else {
		s.logger.Debug("Forwarded PLI to browser")
	}
}

func (s *Session) forwardSR(sr *rtcp.SenderReport) {
	if s.pubPC == nil {
		return
	}
	// Forward SR with mapped SSRC
	newSR := &rtcp.SenderReport{
		SSRC:        s.videoSSRC.Load(),
		NTPTime:     sr.NTPTime,
		RTPTime:     sr.RTPTime,
		PacketCount: sr.PacketCount,
		OctetCount:  sr.OctetCount,
	}
	_ = s.pubPC.WriteRTCP([]rtcp.Packet{newSR})
}

// forwardRTP forwards RTP packets from browser to Wowza
func (s *Session) forwardRTP(remote *webrtc.TrackRemote, local *webrtc.TrackLocalStaticRTP) {
	isVideo := remote.Kind() == webrtc.RTPCodecTypeVideo
	isH264 := isVideo && strings.EqualFold(remote.Codec().MimeType, webrtc.MimeTypeH264)
	h264Counts := map[uint8]uint64{}
	h264Warned := map[uint8]bool{}
	mode := strings.ToLower(s.cfg.H264RepacketizeMode)

	// Wait for Wowza to be ready before forwarding
	select {
	case <-s.wowzaReady:
	case <-s.ctx.Done():
		return
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, _, err := remote.ReadRTP()
		if err != nil {
			if err != io.EOF {
				s.logger.WithError(err).Debug("RTP read error")
			}
			return
		}

		// Track video stats for RTCP SR
		if isVideo {
			s.videoPackets.Add(1)
			s.videoOctets.Add(uint64(len(pkt.Payload)))
			s.videoTimestamp.Store(pkt.Timestamp)
		}

		// H264 repacketization
		if isH264 && len(pkt.Payload) > 0 {
			nalu := pkt.Payload[0] & 0x1F
			if name, bad := h264UnsupportedMap()[nalu]; bad {
				h264Counts[nalu]++
				if !h264Warned[nalu] {
					s.logger.WithField("type", name).Warn("Unsupported H264 NAL type detected")
					h264Warned[nalu] = true
				}
				if mode == "on" || (mode == "auto" && h264Counts[nalu] > H264AutoRepackThreshold) {
					if normalized, err := sanitizeH264(pkt.Payload); err == nil {
						pkt.Payload = normalized
					}
				}
			}
		}

		if err := local.WriteRTP(pkt); err != nil {
			s.logger.WithError(err).Debug("RTP write error")
		}
	}
}

// requestKeyframe sends PLI burst to browser
func (s *Session) requestKeyframe(reason string) {
	now := time.Now()
	if now.Sub(s.pliLastBurst) < s.cfg.PLIBurstMinGap {
		return
	}
	s.pliLastBurst = now

	ssrc := s.videoSSRC.Load()
	if ssrc == 0 || s.pubPC == nil {
		return
	}

	count := s.cfg.PLIBurstCount
	interval := s.cfg.PLIBurstInterval

	for i := 0; i < count; i++ {
		pli := &rtcp.PictureLossIndication{MediaSSRC: ssrc}
		if err := s.pubPC.WriteRTCP([]rtcp.Packet{pli}); err == nil {
			s.logger.WithField("reason", reason).Debug("PLI sent to browser")
		}
		if i < count-1 {
			time.Sleep(interval)
		}
	}
}

func (s *Session) buildSnapshot() *SessionSnapshot {
	snap := &SessionSnapshot{
		AppName:       s.appName,
		AudioChannels: s.audioChannels,
		AudioKbps:     s.cfg.AudioBitrateKbps,
		VideoCodec:    "h264",
		VideoKbps:     s.cfg.VideoBitrateKbps,
		VideoFPS:      s.cfg.VideoFPS,
		VideoPM:       1,
	}

	// Parse stream key for Wowza
	parts := strings.Split(s.streamKey, "?")
	snap.StreamName = parts[0]
	snap.WowzaStreamName = s.streamKey // Full stream key including token

	if s.pref == PreferCodecVP8 {
		snap.VideoCodec = "vp8"
	}
	if v := s.videoCodec.Load(); v != nil {
		if codec, _ := v.(string); codec != "" {
			snap.VideoCodec = codec
		}
	}
	if v := s.videoProfile.Load(); v != nil {
		if profile, _ := v.(string); profile != "" {
			snap.VideoProfile = profile
		}
	}
	if pm := s.videoPM.Load(); pm == 0 || pm == 1 {
		snap.VideoPM = int(pm)
	}
	// Firefox PM=0 fix
	if snap.VideoCodec == "h264" && !s.browserAnyPM1 {
		snap.VideoPM = 0
	}

	return snap
}

func (s *Session) startReadyTimer(d time.Duration) {
	s.readyTimerMu.Lock()
	defer s.readyTimerMu.Unlock()
	if s.readyTimer != nil {
		s.readyTimer.Stop()
	}
	s.readyTimer = time.AfterFunc(d, func() {
		s.logger.Error("Video ready timeout - no video track received")
		_ = s.Stop()
	})
}

func (s *Session) stopReadyTimer() {
	s.readyTimerMu.Lock()
	defer s.readyTimerMu.Unlock()
	if s.readyTimer != nil {
		s.readyTimer.Stop()
		s.readyTimer = nil
	}
}

// toNTPTime converts time.Time to NTP timestamp
func toNTPTime(t time.Time) uint64 {
	// NTP epoch is 1900, Unix is 1970 - 70 years difference
	const ntpEpochOffset = 2208988800
	secs := uint64(t.Unix()) + ntpEpochOffset
	frac := uint64(t.Nanosecond()) * (1 << 32) / 1e9
	return (secs << 32) | frac
}
