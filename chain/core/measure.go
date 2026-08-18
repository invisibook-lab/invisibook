package core

import "log"

// ────────────────────── Measurement hooks ──────────────────────
//
// The chain prints the two numbers an experiment cannot obtain from
// outside: the byte size of each writing's request payload, and the
// wall-clock of each proof verification (see zkverify.go and
// plonkverify.go). experiments/rq3_end_to_end.sh reads both from the node
// log.

// LogPayloadSize prints the byte length of one writing's on-chain request
// payload. `name` must be the writing's registered name.
func LogPayloadSize(name string, payload []byte) {
	log.Printf("[tx] %s payload %d B", name, len(payload))
}
