//go:build cozk2p

package core

/*
#cgo LDFLAGS: ${SRCDIR}/../lib/libcozk2p.a -ldl -lm -lpthread
#include <stddef.h>
#include <stdint.h>

// Implemented by the cozk2p Rust staticlib (cozk2p/src/ffi.rs). Returns 0
// when the proof verifies; non-zero writes a NUL-terminated message to err.
int32_t cozk2p_verify_settle(const uint8_t* vk, size_t vk_len,
                             const uint8_t* public_json, size_t public_json_len,
                             const uint8_t* proof, size_t proof_len,
                             uint8_t* err, size_t err_cap);

// Merged-statement variant: public_json is the 15-signal PairPublic JSON.
int32_t cozk2p_verify_settle_pair(const uint8_t* vk, size_t vk_len,
                                  const uint8_t* public_json, size_t public_json_len,
                                  const uint8_t* proof, size_t proof_len,
                                  uint8_t* err, size_t err_cap);
*/
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"
)

// plonkVerifySettle2p bridges to the Rust cozk2p verifier over cgo. All
// three inputs must be non-empty (VerifyPlonkSettle2p guarantees this).
func plonkVerifySettle2p(vkBytes, publicJSON, proofBytes []byte) error {
	errBuf := make([]byte, 512)
	code := C.cozk2p_verify_settle(
		(*C.uint8_t)(unsafe.Pointer(&vkBytes[0])), C.size_t(len(vkBytes)),
		(*C.uint8_t)(unsafe.Pointer(&publicJSON[0])), C.size_t(len(publicJSON)),
		(*C.uint8_t)(unsafe.Pointer(&proofBytes[0])), C.size_t(len(proofBytes)),
		(*C.uint8_t)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)),
	)
	return plonkCodeToError(code, errBuf)
}

// plonkVerifySettlePair bridges the MERGED-statement verifier over cgo.
func plonkVerifySettlePair(vkBytes, publicJSON, proofBytes []byte) error {
	errBuf := make([]byte, 512)
	code := C.cozk2p_verify_settle_pair(
		(*C.uint8_t)(unsafe.Pointer(&vkBytes[0])), C.size_t(len(vkBytes)),
		(*C.uint8_t)(unsafe.Pointer(&publicJSON[0])), C.size_t(len(publicJSON)),
		(*C.uint8_t)(unsafe.Pointer(&proofBytes[0])), C.size_t(len(proofBytes)),
		(*C.uint8_t)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)),
	)
	return plonkCodeToError(code, errBuf)
}

// plonkCodeToError maps an FFI return code + error buffer to a Go error.
func plonkCodeToError(code C.int32_t, errBuf []byte) error {
	if code == 0 {
		return nil
	}
	msg := errBuf
	if i := bytes.IndexByte(errBuf, 0); i >= 0 {
		msg = errBuf[:i]
	}
	return fmt.Errorf("cozk2p verifier returned %d: %s", int32(code), msg)
}

// PlonkVerifierAvailable reports whether this binary carries the cozk2p
// PLONK verifier (true: built with `-tags cozk2p`).
func PlonkVerifierAvailable() bool { return true }
