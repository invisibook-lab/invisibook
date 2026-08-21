package core

import (
	"encoding/json"
	"os"
	"testing"
)

// poolFixture mirrors `lib/chain/examples/dump_pool_fixture.rs` output: one
// valid proof per shielded-pool circuit over the golden 3-leaf tree, plus
// the exact public vectors the prover emitted. Verifying them here pins the
// chain-side public rebuild (including the bind transcript) to the Rust
// prover byte-for-byte.
type poolFixture struct {
	ChainID      uint64              `json:"chain_id"`
	GenesisNotes []string            `json:"genesis_notes"`
	Anchor       string              `json:"anchor"`
	Deposit      poolDepositFixture  `json:"deposit"`
	Withdraw     poolWithdrawFixture `json:"withdraw"`
}

type poolDepositFixture struct {
	Token            string          `json:"token"`
	BridgeCommitment string          `json:"bridge_commitment"`
	OutputCommitment string          `json:"output_commitment"`
	ProofJSON        json.RawMessage `json:"proof_json"`
	PublicJSON       []string        `json:"public_json"`
	VKPath           string          `json:"vk_path"`
}

type poolWithdrawFixture struct {
	Token               string          `json:"token"`
	Anchor              string          `json:"anchor"`
	Nullifiers          []string        `json:"nullifiers"`
	BridgeOutCommitment string          `json:"bridge_out_commitment"`
	ChangeCommitment    string          `json:"change_commitment"`
	ProofJSON           json.RawMessage `json:"proof_json"`
	PublicJSON          []string        `json:"public_json"`
	VKPath              string          `json:"vk_path"`
}

func loadPoolFixture(t *testing.T) poolFixture {
	t.Helper()
	const path = "/tmp/pool_fixture.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `cargo run -p invisibook-lib --example dump_pool_fixture -- %s`", path, path)
	}
	var f poolFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return f
}

// rebuildNoteDepositSignals builds the public vector exactly as the
// NoteDeposit handler does.
func rebuildNoteDepositSignals(t *testing.T, chainID uint64, fx *poolDepositFixture) []string {
	t.Helper()
	req := &NoteDepositRequest{
		Token:            TokenID(fx.Token),
		BridgeCommitment: fx.BridgeCommitment,
		OutputCommitment: fx.OutputCommitment,
	}
	assetID, err := AssetID(req.Token)
	if err != nil {
		t.Fatal(err)
	}
	bridgeDec, err := HexToDecimal(req.BridgeCommitment)
	if err != nil {
		t.Fatal(err)
	}
	cmDec, err := HexToDecimal(req.OutputCommitment)
	if err != nil {
		t.Fatal(err)
	}
	bind := noteDepositBind(chainID, req)
	return []string{bridgeDec, assetID.String(), cmDec, bind.String()}
}

// rebuildNoteWithdrawSignals builds the public vector exactly as the
// NoteWithdraw handler does.
func rebuildNoteWithdrawSignals(t *testing.T, chainID uint64, fx *poolWithdrawFixture) []string {
	t.Helper()
	req := &NoteWithdrawRequest{
		Token:               TokenID(fx.Token),
		Anchor:              fx.Anchor,
		Nullifiers:          fx.Nullifiers,
		BridgeOutCommitment: fx.BridgeOutCommitment,
		ChangeCommitment:    fx.ChangeCommitment,
	}
	assetID, err := AssetID(req.Token)
	if err != nil {
		t.Fatal(err)
	}
	toDec := func(h string) string {
		d, err := HexToDecimal(h)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	bind := noteWithdrawBind(chainID, req)
	return []string{
		toDec(req.Anchor), toDec(req.Nullifiers[0]), toDec(req.Nullifiers[1]),
		assetID.String(), toDec(req.BridgeOutCommitment), toDec(req.ChangeCommitment),
		bind.String(),
	}
}

// The chain-side rebuild must equal the prover's emitted publics — this is
// the Go↔Rust lockstep for the bind transcript and the signal layouts.
func TestPoolSignalRebuildMatchesProver(t *testing.T) {
	fx := loadPoolFixture(t)

	dep := rebuildNoteDepositSignals(t, fx.ChainID, &fx.Deposit)
	if len(dep) != len(fx.Deposit.PublicJSON) {
		t.Fatalf("deposit publics: %d != %d", len(dep), len(fx.Deposit.PublicJSON))
	}
	for i := range dep {
		if dep[i] != fx.Deposit.PublicJSON[i] {
			t.Fatalf("deposit public[%d]: chain %s != prover %s", i, dep[i], fx.Deposit.PublicJSON[i])
		}
	}

	wd := rebuildNoteWithdrawSignals(t, fx.ChainID, &fx.Withdraw)
	if len(wd) != len(fx.Withdraw.PublicJSON) {
		t.Fatalf("withdraw publics: %d != %d", len(wd), len(fx.Withdraw.PublicJSON))
	}
	for i := range wd {
		if wd[i] != fx.Withdraw.PublicJSON[i] {
			t.Fatalf("withdraw public[%d]: chain %s != prover %s", i, wd[i], fx.Withdraw.PublicJSON[i])
		}
	}
}

func TestVerifyNoteDepositProof(t *testing.T) {
	fx := loadPoolFixture(t)
	vk, err := LoadVK("note_deposit", fx.Deposit.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	signals := rebuildNoteDepositSignals(t, fx.ChainID, &fx.Deposit)
	if err := VerifyGroth16(vk, string(fx.Deposit.ProofJSON), signals); err != nil {
		t.Fatalf("valid note_deposit proof must verify: %v", err)
	}

	// Tampering with the minted commitment must break verification.
	tampered := rebuildNoteDepositSignals(t, fx.ChainID, &fx.Deposit)
	tampered[2] = bumpLastDigit(tampered[2])
	if err := VerifyGroth16(vk, string(fx.Deposit.ProofJSON), tampered); err == nil {
		t.Fatal("tampered cm_out must be rejected")
	}

	// A different chain id changes bind and must break verification —
	// cross-chain replay protection.
	crossChain := rebuildNoteDepositSignals(t, fx.ChainID+1, &fx.Deposit)
	if err := VerifyGroth16(vk, string(fx.Deposit.ProofJSON), crossChain); err == nil {
		t.Fatal("cross-chain replay must be rejected")
	}
}

func TestVerifyNoteWithdrawProof(t *testing.T) {
	fx := loadPoolFixture(t)
	vk, err := LoadVK("spend_withdraw", fx.Withdraw.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	signals := rebuildNoteWithdrawSignals(t, fx.ChainID, &fx.Withdraw)
	if err := VerifyGroth16(vk, string(fx.Withdraw.ProofJSON), signals); err != nil {
		t.Fatalf("valid spend_withdraw proof must verify: %v", err)
	}

	// Substituting a nullifier must break verification (nullifier squatting
	// via proof reuse).
	tampered := rebuildNoteWithdrawSignals(t, fx.ChainID, &fx.Withdraw)
	tampered[1] = bumpLastDigit(tampered[1])
	if err := VerifyGroth16(vk, string(fx.Withdraw.ProofJSON), tampered); err == nil {
		t.Fatal("tampered nullifier must be rejected")
	}

	// Growing the change commitment must break verification (inflation).
	tampered = rebuildNoteWithdrawSignals(t, fx.ChainID, &fx.Withdraw)
	tampered[5] = bumpLastDigit(tampered[5])
	if err := VerifyGroth16(vk, string(fx.Withdraw.ProofJSON), tampered); err == nil {
		t.Fatal("tampered change commitment must be rejected")
	}
}
