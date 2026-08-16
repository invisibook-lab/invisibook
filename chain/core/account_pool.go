package core

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
)

// Shielded-pool writings and readings of the Account tripod (plan rev. 3,
// Phase 2). The pool state itself lives in pool_scheme.go; the derivations
// in pool.go.

// bindDomain is the ASCII domain every bind transcript starts with.
const bindDomain = "invisibook.bind.v1"

// bindVersion is the circuit-family version baked into every bind
// transcript; bump together with any circuit statement change.
const bindVersion = 1

// bridgeDepositSigDomain prefixes the message the bridge operator signs.
const bridgeDepositSigDomain = "invisibook-bridge-deposit-v1"

// u64be / u32be render integers for bind transcripts.
func u64be(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func u32be(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// ────────────────────── Writing: NoteDeposit ──────────────────────

// NoteDepositRequest mints one shielded note from a bridged deposit.
// `BridgeSig` is the bridge operator's ed25519 signature over the canonical
// deposit message; required whenever the chain has an operator configured.
type NoteDepositRequest struct {
	Token            TokenID `json:"token"             validate:"required"`
	BridgeCommitment string  `json:"bridge_commitment" validate:"required,len=64"`
	OutputCommitment string  `json:"output_commitment" validate:"required,len=64"` // cm_out
	BridgeSig        string  `json:"bridge_sig,omitempty"`
	ZkProof          string  `json:"zk_proof"          validate:"required"`
}

// noteDepositBind computes the bind public input for a deposit request.
// Field layout is canonical and mirrored by the Rust client.
func noteDepositBind(chainID uint64, req *NoteDepositRequest) *big.Int {
	return BindHash(
		[]byte(bindDomain),
		u64be(chainID),
		[]byte("note_deposit"),
		u32be(bindVersion),
		[]byte(req.Token),
		[]byte(req.BridgeCommitment),
		[]byte(req.OutputCommitment),
	)
}

// bridgeDepositMessage is the canonical message the bridge operator signs.
func bridgeDepositMessage(req *NoteDepositRequest) []byte {
	msg := make([]byte, 0, 200)
	for _, f := range [][]byte{
		[]byte(bridgeDepositSigDomain),
		[]byte(req.Token),
		[]byte(req.BridgeCommitment),
		[]byte(req.OutputCommitment),
	} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		msg = append(msg, l[:]...)
		msg = append(msg, f...)
	}
	return msg
}

// NoteDeposit verifies the deposit proof (and, when configured, the bridge
// operator's authorization), then appends the new note to the tree.
// Replay is stopped by the bridge_seen dedup; forgery by the operator
// signature — the real bridge inclusion proof replaces both eventually.
func (a *Account) NoteDeposit(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(NoteDepositRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	assetID, err := AssetID(req.Token)
	if err != nil {
		return err
	}

	// Bridge authorization (interim trusted signer; see config docs).
	if a.cfg.BridgeOperatorPubkey != "" {
		opKey, err := hex.DecodeString(a.cfg.BridgeOperatorPubkey)
		if err != nil || len(opKey) != ed25519.PublicKeySize {
			return fmt.Errorf("misconfigured bridge_operator_pubkey")
		}
		sig, err := hex.DecodeString(req.BridgeSig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("deposit requires a bridge operator signature")
		}
		if !ed25519.Verify(opKey, bridgeDepositMessage(req), sig) {
			return fmt.Errorf("bridge operator signature verification failed")
		}
	}

	// Replay: each bridge commitment mints at most once.
	seen, err := a.BridgeSeen(req.BridgeCommitment)
	if err != nil {
		return err
	}
	if seen {
		return fmt.Errorf("bridge commitment %s already consumed", req.BridgeCommitment)
	}

	// Rebuild the public vector in circuit order:
	// [bridge_commitment, asset_id, cm_out, bind].
	bridgeDec, err := HexToDecimal(req.BridgeCommitment)
	if err != nil {
		return fmt.Errorf("invalid bridge_commitment: %w", err)
	}
	cmDec, err := HexToDecimal(req.OutputCommitment)
	if err != nil {
		return fmt.Errorf("invalid output_commitment: %w", err)
	}
	bind := noteDepositBind(a.cfg.ChainID, req)
	signals := []string{bridgeDec, assetID.String(), cmDec, bind.String()}

	if err := VerifyGroth16(a.noteDepositVK, req.ZkProof, signals); err != nil {
		return fmt.Errorf("note_deposit proof verification failed: %w", err)
	}

	cm, ok := new(big.Int).SetString(req.OutputCommitment, 16)
	if !ok {
		return fmt.Errorf("output_commitment is not hex")
	}
	indices, err := a.ApplyPoolMutation(PoolMutation{
		NoteCms: []*big.Int{cm},
		Height:  uint64(ctx.Block.Height),
		Source:  "deposit",
		By:      "note-deposit",
		Extra: func(tx *gorm.DB) error {
			return tx.Create(&BridgeSeenScheme{
				BridgeCommitment: req.BridgeCommitment,
				Height:           uint64(ctx.Block.Height),
			}).Error
		},
	})
	if err != nil {
		return fmt.Errorf("applying deposit: %w", err)
	}

	ctx.EmitStringEvent("note-deposit: token=%s leaf=%d root=%s",
		string(req.Token), indices[0], a.PoolRoot())
	return nil
}

// ────────────────────── Writing: NoteWithdraw ──────────────────────

// NoteWithdrawRequest spends two note slots (dummies allowed) and withdraws
// value out through the bridge, minting a change note. There is no identity
// on this request at all — authorization is the spend proof itself, welded
// to these exact fields via bind.
type NoteWithdrawRequest struct {
	Token               TokenID  `json:"token"                 validate:"required"`
	Anchor              string   `json:"anchor"                validate:"required,len=64"`
	Nullifiers          []string `json:"nullifiers"            validate:"required,len=2,dive,len=64"`
	BridgeOutCommitment string   `json:"bridge_out_commitment" validate:"required,len=64"`
	ChangeCommitment    string   `json:"change_commitment"     validate:"required,len=64"`
	ZkProof             string   `json:"zk_proof"              validate:"required"`
}

// noteWithdrawBind computes the bind public input for a withdraw request.
func noteWithdrawBind(chainID uint64, req *NoteWithdrawRequest) *big.Int {
	return BindHash(
		[]byte(bindDomain),
		u64be(chainID),
		[]byte("spend_withdraw"),
		u32be(bindVersion),
		[]byte(req.Token),
		[]byte(req.Anchor),
		[]byte(req.Nullifiers[0]),
		[]byte(req.Nullifiers[1]),
		[]byte(req.BridgeOutCommitment),
		[]byte(req.ChangeCommitment),
	)
}

// NoteWithdraw checks cheap facts first (zcashd's ordering: duplicate
// nullifiers, spent set, anchor known), verifies the proof last, then
// commits atomically — nullifiers, change note, frontier, anchor in one
// transaction.
func (a *Account) NoteWithdraw(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(NoteWithdrawRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	assetID, err := AssetID(req.Token)
	if err != nil {
		return err
	}

	// Request-internal duplicate (both slots emitting one nf would let one
	// note satisfy two slots).
	if req.Nullifiers[0] == req.Nullifiers[1] {
		return fmt.Errorf("duplicate nullifier in request")
	}
	for _, nf := range req.Nullifiers {
		spent, err := a.NullifierSpent(nf)
		if err != nil {
			return err
		}
		if spent {
			return fmt.Errorf("nullifier %s already spent", nf)
		}
	}
	known, err := a.AnchorKnown(req.Anchor)
	if err != nil {
		return err
	}
	if !known {
		return fmt.Errorf("unknown anchor %s", req.Anchor)
	}

	// Rebuild the public vector in circuit order:
	// [anchor, nf_0, nf_1, asset_id, bridge_out_commitment, cm_change, bind].
	dec := func(hexStr, what string) (string, error) {
		d, err := HexToDecimal(hexStr)
		if err != nil {
			return "", fmt.Errorf("invalid %s: %w", what, err)
		}
		return d, nil
	}
	anchorDec, err := dec(req.Anchor, "anchor")
	if err != nil {
		return err
	}
	nf0Dec, err := dec(req.Nullifiers[0], "nullifiers[0]")
	if err != nil {
		return err
	}
	nf1Dec, err := dec(req.Nullifiers[1], "nullifiers[1]")
	if err != nil {
		return err
	}
	bridgeDec, err := dec(req.BridgeOutCommitment, "bridge_out_commitment")
	if err != nil {
		return err
	}
	changeDec, err := dec(req.ChangeCommitment, "change_commitment")
	if err != nil {
		return err
	}
	bind := noteWithdrawBind(a.cfg.ChainID, req)
	signals := []string{anchorDec, nf0Dec, nf1Dec, assetID.String(), bridgeDec, changeDec, bind.String()}

	if err := VerifyGroth16(a.spendWithdrawVK, req.ZkProof, signals); err != nil {
		return fmt.Errorf("spend_withdraw proof verification failed: %w", err)
	}

	cmChange, ok := new(big.Int).SetString(req.ChangeCommitment, 16)
	if !ok {
		return fmt.Errorf("change_commitment is not hex")
	}
	indices, err := a.ApplyPoolMutation(PoolMutation{
		Nullifiers: req.Nullifiers,
		NoteCms:    []*big.Int{cmChange},
		Height:     uint64(ctx.Block.Height),
		Source:     "withdraw-change",
		By:         "note-withdraw",
	})
	if err != nil {
		return fmt.Errorf("applying withdrawal: %w", err)
	}

	ctx.EmitStringEvent("note-withdraw: token=%s change_leaf=%d root=%s",
		string(req.Token), indices[0], a.PoolRoot())
	return nil
}

// ────────────────────── Readings ──────────────────────

// GetNotesRequest asks for a range of leaves so a client can rebuild the
// tree locally (range reads leak nothing about which leaf interests the
// caller).
type GetNotesRequest struct {
	StartIndex uint64 `json:"start_index"`
	Limit      int    `json:"limit"`
}

// NoteItem is one leaf in a GetNotes response.
type NoteItem struct {
	LeafIndex uint64 `json:"leaf_index"`
	Cm        string `json:"cm"`
	Height    uint64 `json:"height"`
}

// GetNotes returns leaves from `start_index` (limit 0 = all), plus the
// current pool size and root for cross-checking the client-side tree.
func (a *Account) GetNotes(ctx *context.ReadContext) {
	req := new(GetNotesRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rows, err := a.FindNotes(req.StartIndex, req.Limit)
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	notes := make([]NoteItem, 0, len(rows))
	for _, r := range rows {
		notes = append(notes, NoteItem{LeafIndex: r.LeafIndex, Cm: r.Cm, Height: r.Height})
	}
	ctx.JsonOk(map[string]any{
		"leaf_count":  a.PoolSize(),
		"latest_root": a.PoolRoot(),
		"notes":       notes,
	})
}

// GetPoolInfo returns the pool size and current root.
func (a *Account) GetPoolInfo(ctx *context.ReadContext) {
	ctx.JsonOk(map[string]any{
		"leaf_count":  a.PoolSize(),
		"latest_root": a.PoolRoot(),
	})
}

// GetNullifiersRequest asks whether each listed nullifier is spent.
type GetNullifiersRequest struct {
	Nullifiers []string `json:"nullifiers" validate:"required,min=1,max=64"`
}

// GetNullifiers reports spent-ness per queried nullifier.
func (a *Account) GetNullifiers(ctx *context.ReadContext) {
	req := new(GetNullifiersRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := Validator.Struct(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	spent := make([]bool, len(req.Nullifiers))
	for i, nf := range req.Nullifiers {
		s, err := a.NullifierSpent(nf)
		if err != nil {
			ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		spent[i] = s
	}
	ctx.JsonOk(map[string]any{"spent": spent})
}

// GetNoteByCmRequest looks up a commitment's leaf index. Recovery flows
// only: the query reveals the caller's interest in that cm to the queried
// node (same leak class as the legacy cash-id probe).
type GetNoteByCmRequest struct {
	Cm string `json:"cm" validate:"required,len=64"`
}

// GetNoteByCm returns the smallest leaf index holding `cm`, or -1.
func (a *Account) GetNoteByCm(ctx *context.ReadContext) {
	req := new(GetNoteByCmRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := Validator.Struct(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	idx, err := a.FindNoteByCm(req.Cm)
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ctx.JsonOk(map[string]any{"leaf_index": idx})
}

// ────────────────────── Genesis seeding ──────────────────────

// seedGenesisNotes appends the configured genesis leaves as a verified
// prefix extension. InitChain runs on EVERY boot (yu behavior), so this
// must be idempotent: existing leaves 0..n are checked against the config
// (panic on drift — the operator changed history), and only the missing
// suffix is appended. Deterministic leaf indices 0..len-1; crash-safe.
func (a *Account) seedGenesisNotes(height uint64) {
	want := a.cfg.GenesisNote
	if len(want) == 0 {
		return
	}
	existing, err := a.FindNotes(0, len(want))
	if err != nil {
		panic(fmt.Sprintf("genesis notes: reading existing leaves: %v", err))
	}
	for i, row := range existing {
		if i >= len(want) {
			break
		}
		if row.Cm != want[i].Cm {
			panic(fmt.Sprintf(
				"genesis note %d drifted: chain has %s, config says %s — refusing to start",
				i, row.Cm, want[i].Cm))
		}
	}
	if len(existing) >= len(want) {
		return
	}
	cms := make([]*big.Int, 0, len(want)-len(existing))
	for _, gn := range want[len(existing):] {
		cm, ok := new(big.Int).SetString(gn.Cm, 16)
		if !ok {
			panic(fmt.Sprintf("genesis note cm is not hex: %q", gn.Cm))
		}
		cms = append(cms, cm)
	}
	indices, err := a.ApplyPoolMutation(PoolMutation{
		NoteCms: cms,
		Height:  height,
		Source:  "genesis",
		By:      "genesis",
	})
	if err != nil {
		panic(fmt.Sprintf("genesis notes: appending: %v", err))
	}
	fmt.Printf("genesis notes: seeded leaves %d..%d root=%s\n",
		indices[0], indices[len(indices)-1], a.PoolRoot())
}
