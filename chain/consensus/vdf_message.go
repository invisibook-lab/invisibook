package consensus

import (
	"encoding/json"
	"fmt"
)

// VDFMessageTopic is the P2P topic for broadcasting VDF results between miners.
const VDFMessageTopic = "vdf_message"

// VDFMessage carries a miner's VDF result for the current block round.
// The miner's public key is recovered from the signature, so it is not
// included explicitly.
type VDFMessage struct {
	// VDFResult is the computed VDF output for this round.
	VDFResult *VDFResult `json:"vdf_result"`
	// Input is the previous block hash used as VDF input.
	Input []byte `json:"input"`
	// Signature is the miner's signature over (Input || VDFResult.ProofBlob).
	Signature []byte `json:"signature"`
}

// EncodeVDFMessage serializes a VDFMessage into JSON bytes.
func EncodeVDFMessage(msg *VDFMessage) ([]byte, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encode vdf message: %w", err)
	}
	return data, nil
}

// DecodeVDFMessage deserializes JSON bytes into a VDFMessage.
func DecodeVDFMessage(raw []byte) (*VDFMessage, error) {
	var msg VDFMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, fmt.Errorf("decode vdf message: %w", err)
	}
	return &msg, nil
}
