package main

type WowzaOffer struct {
	Direction  string `json:"direction"`
	Command    string `json:"command"`
	StreamInfo struct {
		ApplicationName string `json:"applicationName"`
		StreamName      string `json:"streamName"`
	} `json:"streamInfo"`
	SDP struct {
		SDP  string `json:"sdp"`
		Type string `json:"type"`
	} `json:"sdp"`
}

type WowzaICECandidate struct {
	Candidate     string  `json:"candidate"`
	SDPMid        *string `json:"sdpMid"`
	SDPMLineIndex *uint16 `json:"sdpMLineIndex"`
}

type WowzaAnswer struct {
	Status int `json:"status"`
	SDP    struct {
		SDP string `json:"sdp"`
	} `json:"sdp"`
	ICECandidates []WowzaICECandidate `json:"iceCandidates"`
}
