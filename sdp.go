package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pion/sdp/v3"
)

type SessionSnapshot struct {
	AppName         string
	StreamName      string
	WowzaStreamName string
	AudioChannels   int
	AudioKbps       int
	VideoCodec      string
	VideoKbps       int
	VideoFPS        int
	VideoProfile    string
	VideoPM         int // packetization-mode
}

// mungeSDP transforms the SDP for Wowza compatibility
func mungeSDP(orig string, cfg *Config, snap *SessionSnapshot) string {
	var desc sdp.SessionDescription
	if err := desc.Unmarshal([]byte(orig)); err != nil {
		return orig
	}

	for _, md := range desc.MediaDescriptions {
		switch strings.ToLower(md.MediaName.Media) {
		case "video":
			mungeVideoMedia(md, snap)
		case "audio":
			mungeAudioMedia(md, snap)
		}
		stripTransportCC(md)
	}

	bytes, err := desc.Marshal()
	if err != nil {
		return orig
	}

	// Filter private IPs and add trickle ICE for Wowza Cloud
	result := string(bytes)
	result = filterPrivateIPs(result)
	result = addTrickleICE(result)
	return result
}

func mungeVideoMedia(md *sdp.MediaDescription, snap *SessionSnapshot) {
	rtpmap := rtpMapByPayload(md)
	fmtpParams := fmtpMapByPayload(md)

	type entry struct {
		pt, profile, fmtp, mime string
	}
	keep := make([]entry, 0, len(md.MediaName.Formats))
	targetCodec := strings.ToLower(snap.VideoCodec)

	for _, format := range md.MediaName.Formats {
		enc := strings.ToLower(rtpmap[format])
		// Filter RTX
		if strings.Contains(enc, "rtx") {
			continue
		}
		// Filter based on target codec
		if targetCodec == "h264" && !strings.Contains(enc, "h264") {
			continue
		}
		if targetCodec == "vp8" && !strings.Contains(enc, "vp8") {
			continue
		}
		profile := ""
		if strings.Contains(enc, "h264") {
			profile, _ = parseH264Params(strings.TrimSpace(fmtpParams[format]))
		}
		keep = append(keep, entry{pt: format, mime: enc, fmtp: strings.TrimSpace(fmtpParams[format]), profile: profile})
	}

	if len(keep) == 0 {
		setASBandwidth(md, snap.VideoKbps)
		return
	}

	formats := make([]string, 0, len(keep))
	keepSet := map[string]entry{}
	for _, e := range keep {
		formats = append(formats, e.pt)
		keepSet[e.pt] = e
	}
	md.MediaName.Formats = formats

	filtered := make([]sdp.Attribute, 0, len(md.Attributes))
	seenFB := map[string]bool{}

	for _, attr := range md.Attributes {
		switch attr.Key {
		case "rtpmap":
			payload := parseAttrPayload(attr.Value)
			if _, ok := keepSet[payload]; ok {
				filtered = append(filtered, attr)
			}
		case "fmtp":
			payload := parseAttrPayload(attr.Value)
			ent, ok := keepSet[payload]
			if !ok {
				continue
			}
			if strings.Contains(ent.mime, "h264") {
				params := rewriteH264FMTP(ent.fmtp, snap.VideoPM)
				filtered = append(filtered, sdp.Attribute{Key: "fmtp", Value: fmt.Sprintf("%s %s", payload, params)})
			} else {
				filtered = append(filtered, attr)
			}
		case "rtcp-fb":
			payload, rest := splitAttrValue(attr.Value)
			if payload == "" || payload == "*" {
				continue
			}
			if _, ok := keepSet[payload]; !ok {
				continue
			}
			lower := strings.ToLower(rest)
			if strings.Contains(lower, "transport-cc") {
				continue
			}
			key := fmt.Sprintf("%s:%s", payload, rest)
			if seenFB[key] {
				continue
			}
			seenFB[key] = true
			filtered = append(filtered, attr)
		case "extmap":
			if strings.Contains(strings.ToLower(attr.Value), "transport-wide-cc") {
				continue
			}
			filtered = append(filtered, attr)
		case "framerate":
			// will re-add
		default:
			filtered = append(filtered, attr)
		}
	}

	md.Attributes = filtered
	if snap.VideoFPS > 0 {
		md.Attributes = append(md.Attributes, sdp.Attribute{Key: "framerate", Value: fmt.Sprintf("%d", snap.VideoFPS)})
	}
	setASBandwidth(md, snap.VideoKbps)
}

func mungeAudioMedia(md *sdp.MediaDescription, snap *SessionSnapshot) {
	rtpmap := rtpMapByPayload(md)
	desired := snap.AudioChannels

	// Filter to matching channel count
	matches := map[string]bool{}
	for _, format := range md.MediaName.Formats {
		enc := strings.ToLower(rtpmap[format])
		if !strings.Contains(enc, "opus/48000") {
			continue
		}
		parts := strings.Split(enc, "/")
		channels := 1
		if len(parts) >= 3 {
			if val, err := strconv.Atoi(parts[2]); err == nil {
				channels = val
			}
		}
		if channels == desired {
			matches[format] = true
		}
	}

	formats := make([]string, 0, len(md.MediaName.Formats))
	selected := map[string]bool{}

	if len(matches) > 0 {
		for _, f := range md.MediaName.Formats {
			if matches[f] {
				selected[f] = true
				formats = append(formats, f)
			}
		}
	} else {
		// fallback: keep all
		for _, f := range md.MediaName.Formats {
			selected[f] = true
			formats = append(formats, f)
		}
	}
	md.MediaName.Formats = formats

	filtered := make([]sdp.Attribute, 0, len(md.Attributes))
	for _, attr := range md.Attributes {
		switch attr.Key {
		case "rtpmap":
			payload, rest := splitAttrValue(attr.Value)
			if !selected[payload] {
				continue
			}
			if strings.Contains(strings.ToLower(rest), "opus/48000") {
				rest = fmt.Sprintf("opus/48000/%d", desired)
			}
			filtered = append(filtered, sdp.Attribute{Key: "rtpmap", Value: fmt.Sprintf("%s %s", payload, rest)})
		case "fmtp":
			payload, _ := splitAttrValue(attr.Value)
			if !selected[payload] {
				continue
			}
			enc := strings.ToLower(rtpmap[payload])
			if strings.Contains(enc, "opus/48000") {
				filtered = append(filtered, sdp.Attribute{Key: "fmtp", Value: fmt.Sprintf("%s %s", payload, audioFMTP(desired))})
			} else {
				filtered = append(filtered, attr)
			}
		case "rtcp-fb":
			payload, rest := splitAttrValue(attr.Value)
			if !selected[payload] {
				continue
			}
			if strings.Contains(strings.ToLower(rest), "transport-cc") {
				continue
			}
			filtered = append(filtered, attr)
		case "extmap":
			if strings.Contains(strings.ToLower(attr.Value), "transport-wide-cc") {
				continue
			}
			filtered = append(filtered, attr)
		default:
			filtered = append(filtered, attr)
		}
	}

	md.Attributes = filtered
	setASBandwidth(md, snap.AudioKbps)
}

func stripTransportCC(md *sdp.MediaDescription) {
	filtered := make([]sdp.Attribute, 0, len(md.Attributes))
	for _, attr := range md.Attributes {
		if attr.Key == "rtcp-fb" && strings.Contains(strings.ToLower(attr.Value), "transport-cc") {
			continue
		}
		if attr.Key == "extmap" && strings.Contains(strings.ToLower(attr.Value), "transport-wide-cc") {
			continue
		}
		filtered = append(filtered, attr)
	}
	md.Attributes = filtered
}

func setASBandwidth(md *sdp.MediaDescription, kbps int) {
	filtered := make([]sdp.Bandwidth, 0, len(md.Bandwidth))
	for _, bw := range md.Bandwidth {
		if !strings.EqualFold(bw.Type, "AS") {
			filtered = append(filtered, bw)
		}
	}
	md.Bandwidth = filtered
	if kbps > 0 {
		md.Bandwidth = append(md.Bandwidth, sdp.Bandwidth{Type: "AS", Bandwidth: uint64(kbps)})
	}
}

func audioFMTP(channels int) string {
	if channels >= 2 {
		return "minptime=10;useinbandfec=1;stereo=1;sprop-stereo=1"
	}
	return "minptime=10;useinbandfec=0"
}

func rewriteH264FMTP(params string, pm int) string {
	items := strings.Split(params, ";")
	kept := make([]string, 0, len(items))
	for _, raw := range items {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(t), "packetization-mode=") {
			continue
		}
		kept = append(kept, t)
	}
	if pm < 0 {
		pm = 1
	}
	kept = append(kept, fmt.Sprintf("packetization-mode=%d", pm))
	return strings.Join(kept, ";")
}

// filterPrivateIPs removes private and IPv6 candidates for Wowza Cloud compatibility
func filterPrivateIPs(sdpStr string) string {
	lines := strings.Split(sdpStr, "\r\n")
	filtered := make([]string, 0, len(lines))

	for _, line := range lines {
		// Remove end-of-candidates for trickle ICE
		if strings.HasPrefix(line, "a=end-of-candidates") {
			continue
		}
		// Filter candidate lines by parsing IP at correct position
		// Format: a=candidate:foundation component transport priority address port typ type
		if strings.HasPrefix(line, "a=candidate:") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				// IP is at index 4 (after a=candidate:foundation component transport priority)
				ipStr := parts[4]
				ip := net.ParseIP(ipStr)
				if ip != nil {
					// Skip IPv6
					if ip.To4() == nil {
						continue
					}
					// Skip private IPs
					if isPrivateIP(ip) {
						continue
					}
				}
			}
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\r\n")
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	private := []net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)},
	}
	for _, block := range private {
		if block.Contains(ip4) {
			return true
		}
	}
	return false
}

// addTrickleICE adds trickle ICE option for Wowza Cloud
func addTrickleICE(sdpStr string) string {
	if strings.Contains(sdpStr, "a=ice-options:trickle") {
		return sdpStr
	}
	// Add after session-level attributes
	lines := strings.Split(sdpStr, "\r\n")
	result := make([]string, 0, len(lines)+1)
	added := false
	for _, line := range lines {
		result = append(result, line)
		if !added && strings.HasPrefix(line, "a=ice-ufrag:") {
			result = append(result, "a=ice-options:trickle")
			added = true
		}
	}
	return strings.Join(result, "\r\n")
}

// cleanWowzaCandidate fixes Wowza Cloud candidate format issues
func cleanWowzaCandidate(candidate string) string {
	// Remove "generation X" suffix (non-standard)
	if idx := strings.Index(candidate, " generation"); idx > 0 {
		candidate = strings.TrimSpace(candidate[:idx])
	}

	// Add tcptype passive for TCP candidates (RFC 6544 requirement)
	parts := strings.Fields(candidate)
	if len(parts) >= 3 {
		transport := strings.ToUpper(parts[2])
		if transport == "TCP" && !strings.Contains(candidate, "tcptype") {
			candidate = candidate + " tcptype passive"
		}
	}

	return candidate
}

func rtpMapByPayload(md *sdp.MediaDescription) map[string]string {
	out := make(map[string]string)
	for _, attr := range md.Attributes {
		if attr.Key != "rtpmap" {
			continue
		}
		payload, rest := splitAttrValue(attr.Value)
		if payload != "" {
			out[payload] = rest
		}
	}
	return out
}

func fmtpMapByPayload(md *sdp.MediaDescription) map[string]string {
	out := make(map[string]string)
	for _, attr := range md.Attributes {
		if attr.Key != "fmtp" {
			continue
		}
		payload, rest := splitAttrValue(attr.Value)
		if payload != "" {
			out[payload] = rest
		}
	}
	return out
}

func splitAttrValue(val string) (string, string) {
	trimmed := strings.TrimSpace(val)
	if idx := strings.IndexAny(trimmed, " \t"); idx >= 0 {
		return trimmed[:idx], strings.TrimSpace(trimmed[idx+1:])
	}
	return trimmed, ""
}

func parseAttrPayload(val string) string {
	payload, _ := splitAttrValue(val)
	return payload
}
