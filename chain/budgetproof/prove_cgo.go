//go:build budgetstark

package budgetproof

/*
#cgo LDFLAGS: ${SRCDIR}/../lib/libbudget_stark_ffi.a -ldl -lm -lpthread
#include <stddef.h>
#include <stdint.h>

// Implemented by the budget-stark-ffi Rust staticlib (lib/budget-stark-ffi).
int32_t budget_stark_prove(const uint64_t* amounts, const uint8_t* randoms, size_t n,
                           uint8_t* commitments_out, uint8_t* proof_out, size_t proof_cap,
                           size_t* proof_len, uint64_t* prepaid_out,
                           uint8_t* err, size_t err_cap);
*/
import "C"

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"unsafe"
)

// Return codes of budget_stark_prove.
const (
	budgetOK             = 0
	budgetBufferTooSmall = 4
)

// initialProofCap comfortably holds a proof for the largest table (~150 KB).
const initialProofCap = 512 * 1024

// prove calls the Rust prover. `randoms` is the 32-byte blinding factors
// concatenated; its length must be 32 · len(amounts).
func prove(amounts []uint64, randoms []byte) (*Proof, error) {
	n := len(amounts)
	commitments := make([]byte, 32*n)
	proof := make([]byte, initialProofCap)
	for {
		var proofLen C.size_t
		var prepaid C.uint64_t
		errBuf := make([]byte, 512)
		code := C.budget_stark_prove(
			(*C.uint64_t)(unsafe.Pointer(&amounts[0])),
			(*C.uint8_t)(unsafe.Pointer(&randoms[0])),
			C.size_t(n),
			(*C.uint8_t)(unsafe.Pointer(&commitments[0])),
			(*C.uint8_t)(unsafe.Pointer(&proof[0])),
			C.size_t(len(proof)),
			&proofLen,
			&prepaid,
			(*C.uint8_t)(unsafe.Pointer(&errBuf[0])),
			C.size_t(len(errBuf)),
		)
		switch code {
		case budgetOK:
			out := &Proof{
				Prepaid:     uint64(prepaid),
				Commitments: make([]string, n),
				Bytes:       proof[:proofLen],
			}
			for i := range out.Commitments {
				out.Commitments[i] = hex.EncodeToString(commitments[32*i : 32*(i+1)])
			}
			return out, nil
		case budgetBufferTooSmall:
			// Proving again is cheap next to guessing a size that must hold
			// every table: the prover already reported what it needs.
			proof = make([]byte, int(proofLen))
		default:
			msg := errBuf
			if i := bytes.IndexByte(errBuf, 0); i >= 0 {
				msg = errBuf[:i]
			}
			return nil, fmt.Errorf("budget prover (code %d): %s", code, msg)
		}
	}
}
