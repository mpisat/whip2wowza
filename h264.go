package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/pion/webrtc/v4"
)

const (
	h264NalMask   = 0x1F
	h264NALStapA  = 24
	h264NALStapB  = 25
	h264NALMTAP16 = 26
	h264NALMTAP24 = 27
	h264NALFUA    = 28
	h264NALFUB    = 29

	H264AutoRepackThreshold = 5
)

// h264CodecMap returns codec parameters for common H264 profiles
func h264CodecMap() map[string]webrtc.RTPCodecParameters {
	return map[string]webrtc.RTPCodecParameters{
		"42e01f": {RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f", RTCPFeedback: defaultFeedback()}, PayloadType: 102},
		"42001f": {RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f", RTCPFeedback: defaultFeedback()}, PayloadType: 105},
		"4d001f": {RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f", RTCPFeedback: defaultFeedback()}, PayloadType: 106},
		"64001f": {RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f", RTCPFeedback: defaultFeedback()}, PayloadType: 103},
	}
}

// h264UnsupportedMap returns NAL types that Wowza silently ignores
func h264UnsupportedMap() map[uint8]string {
	return map[uint8]string{
		h264NALStapB:  "STAP-B",
		h264NALMTAP16: "MTAP-16",
		h264NALMTAP24: "MTAP-24",
		h264NALFUB:    "FU-B",
	}
}

// sanitizeH264 converts unsupported NAL types to supported ones
func sanitizeH264(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	switch payload[0] & h264NalMask {
	case h264NALStapB:
		return convertStapBToStapA(payload)
	case h264NALMTAP16:
		return convertMTAP16ToStapA(payload)
	case h264NALMTAP24:
		return convertMTAP24ToStapA(payload)
	case h264NALFUB:
		return convertFUBToFUA(payload)
	default:
		return payload, nil
	}
}

func convertStapBToStapA(payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("stap-b too short")
	}
	head := payload[0]
	offset := 3 // skip header + DON
	out := make([]byte, 1, len(payload)-2)
	out[0] = (head &^ h264NalMask) | h264NALStapA
	for offset+2 <= len(payload) {
		size := int(binary.BigEndian.Uint16(payload[offset:]))
		offset += 2
		if offset+size > len(payload) {
			return nil, fmt.Errorf("stap-b size overflow")
		}
		out = binary.BigEndian.AppendUint16(out, uint16(size))
		out = append(out, payload[offset:offset+size]...)
		offset += size
	}
	return out, nil
}

func convertMTAP16ToStapA(payload []byte) ([]byte, error) {
	if len(payload) < 6 {
		return nil, fmt.Errorf("mtap-16 too short")
	}
	head := payload[0]
	offset := 3 // skip header + DON
	out := make([]byte, 1, len(payload))
	out[0] = (head &^ h264NalMask) | h264NALStapA
	for offset+2 <= len(payload) {
		size := int(binary.BigEndian.Uint16(payload[offset:]))
		offset += 2
		if offset >= len(payload) {
			return nil, fmt.Errorf("mtap-16 missing DOND")
		}
		offset++ // skip DOND
		if offset+2 > len(payload) {
			return nil, fmt.Errorf("mtap-16 missing timestamp")
		}
		offset += 2 // skip timestamp offset
		if offset+size > len(payload) {
			return nil, fmt.Errorf("mtap-16 size overflow")
		}
		out = binary.BigEndian.AppendUint16(out, uint16(size))
		out = append(out, payload[offset:offset+size]...)
		offset += size
	}
	return out, nil
}

func convertMTAP24ToStapA(payload []byte) ([]byte, error) {
	if len(payload) < 7 {
		return nil, fmt.Errorf("mtap-24 too short")
	}
	head := payload[0]
	offset := 3 // skip header + DON
	out := make([]byte, 1, len(payload))
	out[0] = (head &^ h264NalMask) | h264NALStapA
	for offset+2 <= len(payload) {
		size := int(binary.BigEndian.Uint16(payload[offset:]))
		offset += 2
		if offset >= len(payload) {
			return nil, fmt.Errorf("mtap-24 missing DOND")
		}
		offset++ // skip DOND
		if offset+3 > len(payload) {
			return nil, fmt.Errorf("mtap-24 missing timestamp")
		}
		offset += 3 // skip 3-byte timestamp offset
		if offset+size > len(payload) {
			return nil, fmt.Errorf("mtap-24 size overflow")
		}
		out = binary.BigEndian.AppendUint16(out, uint16(size))
		out = append(out, payload[offset:offset+size]...)
		offset += size
	}
	return out, nil
}

func convertFUBToFUA(payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("fu-b too short")
	}
	out := make([]byte, 2+len(payload)-4)
	out[0] = (payload[0] &^ h264NalMask) | h264NALFUA
	out[1] = payload[1]
	copy(out[2:], payload[4:])
	return out, nil
}

// parseH264Params extracts profile-level-id and packetization-mode from fmtp
func parseH264Params(fmtp string) (profile string, pm int) {
	pm = -1
	for _, token := range strings.Split(fmtp, ";") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		parts := strings.SplitN(t, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := strings.ToLower(strings.TrimSpace(parts[1]))
		switch key {
		case "profile-level-id":
			if len(val) >= 6 {
				profile = val[:6]
			} else {
				profile = val
			}
		case "packetization-mode":
			if val == "0" {
				pm = 0
			} else if val == "1" {
				pm = 1
			}
		}
	}
	return
}

// rankH264Profile returns ranking for profile preference (lower = better)
func rankH264Profile(profile string) int {
	profile = strings.ToLower(profile)
	switch {
	case strings.HasPrefix(profile, "42"): // Baseline
		return 0
	case strings.HasPrefix(profile, "4d"): // Main
		return 1
	case strings.HasPrefix(profile, "64"): // High
		return 2
	default:
		return 3
	}
}

// canonicalH264Profile normalizes profile to a known canonical form
func canonicalH264Profile(profile string) (string, bool) {
	profile = strings.ToLower(profile)
	if len(profile) < 2 {
		return "", false
	}
	prefix, err := strconv.ParseUint(profile[:2], 16, 8)
	if err != nil {
		return "", false
	}
	switch prefix {
	case 0x42: // Baseline
		if len(profile) >= 4 && profile[:4] == "42e0" {
			return "42e01f", true
		}
		return "42001f", true
	case 0x4d, 0x58: // Main
		return "4d001f", true
	case 0x64: // High
		return "64001f", true
	default:
		return "", false
	}
}
