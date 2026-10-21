package consensus

import (
	"bytes"
	"testing"

	blake2b "github.com/minio/blake2b-simd"
)

// blake2bNoPersonal is plain blake2b-256 over the same bytes — the digest
// CKB would *not* recognise. It exists only so a test can show the
// personalization actually reaches the hash.
func blake2bNoPersonal(data []byte) ([]byte, error) {
	h, err := blake2b.New(&blake2b.Config{Size: ckbHashSize})
	if err != nil {
		return nil, err
	}
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// NOTE: these tests pin the shape and the parameters of the hash, not its
// agreement with CKB itself. Confirming that Blake160 produces the same args
// a CKB node would needs a known vector — a real public key and the lock args
// derived from it — and that check belongs with the first real client.

// The personalization is part of the hash's definition: the same bytes under
// a different one give a different digest. Pinned as a literal so moving it
// takes a deliberate edit, because a wrong value yields hashes that look
// perfectly well-formed and match nothing on chain.
func TestCkbHashPersonalisation(t *testing.T) {
	if ckbHashPersonal != "ckb-default-hash" {
		t.Fatalf("personalization = %q, want %q", ckbHashPersonal, "ckb-default-hash")
	}
	if ckbHashSize != 32 {
		t.Fatalf("digest size = %d, want 32", ckbHashSize)
	}
}

// CKB's standard lock carries 20 bytes of args, not the full digest.
func TestBlake160IsTwentyBytes(t *testing.T) {
	got, err := Blake160([]byte{0x02, 0xaa})
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	if len(got) != blake160Len {
		t.Fatalf("length = %d, want %d", len(got), blake160Len)
	}
	if blake160Len != 20 {
		t.Fatalf("blake160Len = %d, want 20 — CKB's standard lock args", blake160Len)
	}
}

func TestBlake160IsDeterministicAndDistinguishing(t *testing.T) {
	first, err := Blake160([]byte("a public key"))
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	again, err := Blake160([]byte("a public key"))
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("the same key must hash to the same args")
	}

	other, err := Blake160([]byte("another public key"))
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	if bytes.Equal(first, other) {
		t.Fatal("different keys must hash to different args")
	}
}

// The personalization has to reach the digest. A plain blake2b-256 over the
// same bytes must not produce the same answer, or the parameter is being
// dropped somewhere and every comparison against CKB would fail in a way no
// other test here would notice.
func TestBlake160DiffersFromUnpersonalisedBlake2b(t *testing.T) {
	key := []byte("a public key")

	personalised, err := Blake160(key)
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	plain, err := blake2bNoPersonal(key)
	if err != nil {
		t.Fatalf("plain blake2b: %v", err)
	}

	if bytes.Equal(personalised, plain[:blake160Len]) {
		t.Fatal("the personalization is not reaching the digest")
	}
}
