package core

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVerifyPlonkSharesPassesDecodedOpaquePayloadsToBridge(t *testing.T) {
	vk := &PlonkVK{Name: "settle_cozk2p", VKBytes: []byte{0x91, 0x92}}
	public := []byte(`{"cmp":1}`)
	var called bool
	err := verifyPlonkSharesWith(vk, " 00ff ", "a1b2c3", public,
		func(gotVK, gotPublic, gotA, gotB []byte) error {
			called = true
			if !bytes.Equal(gotVK, vk.VKBytes) || !bytes.Equal(gotPublic, public) {
				t.Fatal("verifier bridge received the wrong VK or public statement")
			}
			if !bytes.Equal(gotA, []byte{0x00, 0xff}) {
				t.Fatalf("order A share = %x", gotA)
			}
			if !bytes.Equal(gotB, []byte{0xa1, 0xb2, 0xc3}) {
				t.Fatalf("order B share = %x", gotB)
			}
			return nil
		})
	if err != nil {
		t.Fatalf("verifying opaque shares: %v", err)
	}
	if !called {
		t.Fatal("native-share verifier bridge was not called")
	}
}

func TestVerifyPlonkSharesRejectsMalformedInputBeforeBridge(t *testing.T) {
	vk := &PlonkVK{Name: "settle_cozk2p", VKBytes: []byte{1}}
	for name, tc := range map[string]struct {
		a, b   string
		public []byte
	}{
		"bad A hex":       {a: "zz", b: "00", public: []byte(`{}`)},
		"empty A":         {a: "", b: "00", public: []byte(`{}`)},
		"bad B hex":       {a: "00", b: "zz", public: []byte(`{}`)},
		"empty B":         {a: "00", b: "", public: []byte(`{}`)},
		"empty statement": {a: "00", b: "01", public: nil},
	} {
		t.Run(name, func(t *testing.T) {
			bridge := func(_, _, _, _ []byte) error {
				t.Fatal("bridge must not be called for malformed input")
				return nil
			}
			if err := verifyPlonkSharesWith(vk, tc.a, tc.b, tc.public, bridge); err == nil {
				t.Fatal("malformed native proof share must be rejected")
			}
		})
	}
}

func TestVerifyPlonkSharesWrapsBridgeRejection(t *testing.T) {
	vk := &PlonkVK{Name: "settle_cozk2p", VKBytes: []byte{1}}
	err := verifyPlonkSharesWith(vk, "00", "01", []byte(`{}`),
		func(_, _, _, _ []byte) error { return errors.New("bad party tag") })
	if err == nil || !strings.Contains(err.Error(), "bad party tag") {
		t.Fatalf("bridge rejection was not preserved: %v", err)
	}
}
