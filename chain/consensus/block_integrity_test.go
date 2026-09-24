package consensus

import (
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/types"
)

// txnsWithHashes builds transactions that differ only in their hash, which is
// all MakeTxnRoot reads.
func txnsWithHashes(hashes ...string) types.SignedTxns {
	txns := make(types.SignedTxns, 0, len(hashes))
	for _, h := range hashes {
		txns = append(txns, &types.SignedTxn{TxnHash: common.HexToHash(h)})
	}
	return txns
}

// signBlock produces a block through the very function produceBlock uses.
//
// Calling SealBlock rather than reproducing its steps is deliberate: a test
// that copied the sealing order would go on passing after the producer's own
// order broke, and would be asserting about itself rather than about the code
// that ships.
func signBlock(t *testing.T, pub keypair.PubKey, priv keypair.PrivKey, txns types.SignedTxns) *types.Block {
	t.Helper()

	block := &types.Block{Header: &types.Header{
		Height:   7,
		PrevHash: common.HexToHash("0xparent"),
	}}
	if err := SealBlock(block, txns, &ConsensusData{BlockScore: "100"}, pub, priv); err != nil {
		t.Fatalf("sealing the block: %v", err)
	}
	return block
}

// minerA is the honest producer used throughout.
func minerA(t *testing.T) (keypair.PubKey, keypair.PrivKey) {
	t.Helper()
	pub, priv := keypair.GenSecpKeyWithSecret([]byte("miner-a"))
	return pub, priv
}

func TestVerifyBlockIntegrityAcceptsAProperlySignedBlock(t *testing.T) {
	pub, priv := minerA(t)

	block := signBlock(t, pub, priv, txnsWithHashes("0xaa", "0xbb"))

	if err := VerifyBlockIntegrity(block); err != nil {
		t.Fatalf("a block signed by its producer must verify, got %v", err)
	}
}

// ① The attack this check exists for: the entire header is lifted from a real
// block — hash and signature both still valid — and only the transactions are
// swapped. The hash never covers the transactions themselves, only their
// root, so ② and ③ both pass here and nothing else would catch it.
func TestVerifyBlockIntegrityRejectsSwappedTransactions(t *testing.T) {
	pub, priv := minerA(t)
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa", "0xbb"))

	block.SetTxns(txnsWithHashes("0xevil"))

	err := VerifyBlockIntegrity(block)
	if !errors.Is(err, ErrTxnRootMismatch) {
		t.Fatalf("expected ErrTxnRootMismatch, got %v", err)
	}
}

// ② Tampering with the consensus data — where the VRF proof and the payment
// live — without recomputing the hash.
func TestVerifyBlockIntegrityRejectsTamperedExtra(t *testing.T) {
	pub, priv := minerA(t)
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa"))

	block.Extra = []byte(`{"block_score":"999999"}`)

	err := VerifyBlockIntegrity(block)
	if !errors.Is(err, ErrBlockHashMismatch) {
		t.Fatalf("expected ErrBlockHashMismatch, got %v", err)
	}
}

// ④ Relabelling a block with another miner's key. This is caught only because
// MinerPubkey is inside the hash; were it excluded, the hash would be
// undisturbed and this would fall through to the signature check and rely on
// that alone.
func TestVerifyBlockIntegrityRejectsARelabelledProducer(t *testing.T) {
	pub, priv := minerA(t)
	other, _ := keypair.GenSecpKeyWithSecret([]byte("miner-b"))
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa"))

	block.MinerPubkey = other.Bytes()

	err := VerifyBlockIntegrity(block)
	if !errors.Is(err, ErrBlockHashMismatch) {
		t.Fatalf("expected the hash to cover the producer's key, got %v", err)
	}
}

// ③ A signature from the wrong key.
func TestVerifyBlockIntegrityRejectsAForeignSignature(t *testing.T) {
	pub, priv := minerA(t)
	_, otherPriv := keypair.GenSecpKeyWithSecret([]byte("miner-b"))
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa"))

	sig, err := otherPriv.SignData(block.Hash.Bytes())
	if err != nil {
		t.Fatalf("signing with the other key: %v", err)
	}
	block.MinerSignature = sig

	if err := VerifyBlockIntegrity(block); !errors.Is(err, ErrBlockUnsigned) {
		t.Fatalf("expected ErrBlockUnsigned, got %v", err)
	}
}

func TestVerifyBlockIntegrityRejectsAMissingSignature(t *testing.T) {
	pub, priv := minerA(t)
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa"))

	block.MinerSignature = nil

	if err := VerifyBlockIntegrity(block); !errors.Is(err, ErrBlockUnsigned) {
		t.Fatalf("expected ErrBlockUnsigned, got %v", err)
	}
}

// The whole attack end to end, played out the way it actually would be: the
// attacker takes A's published VRF proof and payment (both public after the
// reveal, and both carried in Extra here), attaches transactions of its own,
// and recomputes a self-consistent hash. Everything lines up except the one
// thing it cannot produce — A's signature over that new hash.
func TestVerifyBlockIntegrityRejectsARebuiltBlockCarryingAnothersCredentials(t *testing.T) {
	pub, priv := minerA(t)
	honest := signBlock(t, pub, priv, txnsWithHashes("0xaa", "0xbb"))

	// Same producer, same consensus data — different transactions.
	forgedTxns := txnsWithHashes("0xevil")
	root, err := types.MakeTxnRoot(forgedTxns)
	if err != nil {
		t.Fatalf("making the forged txn root: %v", err)
	}
	forged := &types.Block{Header: &types.Header{
		Height:   honest.Height,
		PrevHash: honest.PrevHash,
		TxnRoot:  root,
		Extra:    honest.Extra,
	}}
	forged.MinerPubkey = honest.MinerPubkey
	if forged.Hash, err = ComputeBlockHash(forged); err != nil {
		t.Fatalf("hashing the forged block: %v", err)
	}
	// The attacker has no key of A's to sign with, so this is the best it can
	// do: something shaped like a signature.
	forged.MinerSignature = make([]byte, 65)
	forged.SetTxns(forgedTxns)

	err = VerifyBlockIntegrity(forged)
	if !errors.Is(err, ErrBlockUnsigned) {
		t.Fatalf("a block rebuilt around another miner's credentials must be "+
			"refused for its signature, got %v", err)
	}
}

// Hashing must not disturb the block it reads. Block embeds *Header, so a
// copy that is too shallow would clear the caller's signature as a side
// effect — and the block would then fail to verify after being hashed.
func TestComputeBlockHashLeavesTheBlockAlone(t *testing.T) {
	pub, priv := minerA(t)
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa"))
	before := block.MinerSignature

	if _, err := ComputeBlockHash(block); err != nil {
		t.Fatalf("ComputeBlockHash: %v", err)
	}

	if block.MinerSignature == nil {
		t.Fatal("hashing cleared the block's signature")
	}
	if &before[0] != &block.MinerSignature[0] {
		t.Fatal("hashing replaced the block's signature")
	}
	if err := VerifyBlockIntegrity(block); err != nil {
		t.Fatalf("the block must still verify after being hashed, got %v", err)
	}
}

// The signature cannot be inside what it signs, so changing it must not
// change the hash — otherwise producing a block would never terminate.
func TestComputeBlockHashIgnoresTheSignature(t *testing.T) {
	pub, priv := minerA(t)
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa"))

	first, err := ComputeBlockHash(block)
	if err != nil {
		t.Fatalf("ComputeBlockHash: %v", err)
	}
	block.MinerSignature = []byte("something else entirely")
	second, err := ComputeBlockHash(block)
	if err != nil {
		t.Fatalf("ComputeBlockHash: %v", err)
	}

	if first != second {
		t.Fatalf("the signature must not affect the hash: %s vs %s", first, second)
	}
}

// The hash is a field of the header, so it travels through Encode like any
// other. A producer hashes while that field is still zero and never notices;
// a verifier hashes a block that already carries its hash. Unless the field
// is cleared first the two disagree by construction and nothing verifies.
func TestComputeBlockHashIgnoresTheHashFieldItself(t *testing.T) {
	pub, priv := minerA(t)
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa"))

	// The block already carries its hash at this point.
	withHash, err := ComputeBlockHash(block)
	if err != nil {
		t.Fatalf("ComputeBlockHash: %v", err)
	}

	block.Hash = common.Hash{}
	withoutHash, err := ComputeBlockHash(block)
	if err != nil {
		t.Fatalf("ComputeBlockHash: %v", err)
	}

	if withHash != withoutHash {
		t.Fatalf("the hash field must not feed into the hash: %s vs %s",
			withHash, withoutHash)
	}
}

// MinerPubkey arrives from a peer, so it has to survive arbitrary bytes: a
// key that is not a valid curve point must be refused, not crash the
// verifier. The hash is recomputed first so the block stays self-consistent
// up to ③ — otherwise ② would catch it and the key would never be parsed.
func TestVerifyBlockIntegrityRejectsAMalformedProducerKey(t *testing.T) {
	pub, priv := minerA(t)
	block := signBlock(t, pub, priv, txnsWithHashes("0xaa"))

	block.MinerPubkey = []byte{0x02, 0x03}
	var err error
	if block.Hash, err = ComputeBlockHash(block); err != nil {
		t.Fatalf("ComputeBlockHash: %v", err)
	}

	if err := VerifyBlockIntegrity(block); !errors.Is(err, ErrBlockUnsigned) {
		t.Fatalf("expected ErrBlockUnsigned, got %v", err)
	}
}

func TestVerifyBlockIntegrityRejectsAHeaderlessBlock(t *testing.T) {
	if err := VerifyBlockIntegrity(&types.Block{}); err == nil {
		t.Fatal("a block with no header must be refused")
	}
	if err := VerifyBlockIntegrity(nil); err == nil {
		t.Fatal("a nil block must be refused")
	}
}

// wellFormedRival builds a candidate that clears every check verifyCandidate
// applies: a real VRF proof over its parent, a payment backed by an
// allocation on `verifier`, a score consistent with both, and its producer's
// signature over the whole block.
//
// It has to be genuinely valid. A rival that fails something else anyway
// would be rejected either way, and a test built on one could not tell
// whether the integrity check had any part in it.
func wellFormedRival(t *testing.T, verifier *MockL1PaymentVerifier) (*types.Block, []byte) {
	t.Helper()
	block, vrfInput, _, _ := sealedRival(t, verifier)
	return block, vrfInput
}

// sealedRival is wellFormedRival plus the keys that sealed the block.
//
// A test that tampers with a block has to re-seal it, or VerifyBlockIntegrity
// fires on the broken hash and hides whatever the test meant to exercise.
func sealedRival(t *testing.T, verifier *MockL1PaymentVerifier) (*types.Block, []byte, keypair.PubKey, keypair.PrivKey) {
	t.Helper()

	pub, priv, err := keypair.GenKeyPairWithSecret(keypair.Secp256k1, []byte("rival-miner"))
	if err != nil {
		t.Fatalf("generating the rival's key: %v", err)
	}
	producer := hex.EncodeToString(pub.Bytes())

	const height common.BlockNum = 7
	// Built from bytes, not parsed from hex: "0xparent" is not valid hex and
	// would quietly decode to the zero hash, which makes any two such
	// "different" parents identical.
	prevHash := common.BytesToHash([]byte("parent"))
	vrfInput := prevHash.Bytes()
	vrfResult := mustProve(t, priv.Bytes(), vrfInput)

	amount := big.NewInt(500)
	if err := verifier.Allocate("0xprepay", producer, height, amount, randA, 0); err != nil {
		t.Fatalf("seeding the rival's allocation: %v", err)
	}

	block := &types.Block{Header: &types.Header{
		Height:   height,
		PrevHash: prevHash,
	}}
	cdata := &ConsensusData{
		VRFResult:  vrfResult,
		L1Payment:  NewL1Payment("0xprepay", amount, randA, producer, ""),
		BlockScore: CalcBlockScore(amount, vrfResult.Output).String(),
	}
	if err := SealBlock(block, txnsWithHashes("0xaa", "0xbb"), cdata, pub, priv); err != nil {
		t.Fatalf("sealing the rival's block: %v", err)
	}

	return block, vrfInput, pub, priv
}

func TestVerifyBlockAcceptsAWellFormedBlock(t *testing.T) {
	block, _ := wellFormedRival(t, &MockL1PaymentVerifier{})

	if err := (&ProofOfBuy{}).VerifyBlock(block); err != nil {
		t.Fatalf("a well-formed block must verify, got %v", err)
	}
}

// The hook exists for the synchronizer's path: a block fetched during
// catch-up is verified, appended and executed, and nothing else on that path
// looks at it. Without this check its transactions could be anyone's.
func TestVerifyBlockRejectsSwappedTransactions(t *testing.T) {
	block, _ := wellFormedRival(t, &MockL1PaymentVerifier{})

	block.SetTxns(txnsWithHashes("0xevil"))

	if err := (&ProofOfBuy{}).VerifyBlock(block); !errors.Is(err, ErrTxnRootMismatch) {
		t.Fatalf("expected ErrTxnRootMismatch, got %v", err)
	}
}

// A VRF proof is bound to the block's own parent, so re-parenting a block
// invalidates it. The block is re-sealed first, otherwise the integrity check
// would fire on the stale hash and the VRF check would never run.
func TestVerifyBlockRejectsAVRFProofMadeForAnotherParent(t *testing.T) {
	block, _, pub, priv := sealedRival(t, &MockL1PaymentVerifier{})
	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		t.Fatalf("decoding the consensus data: %v", err)
	}

	block.PrevHash = common.BytesToHash([]byte("a different parent"))
	if err := SealBlock(block, block.Txns, cdata, pub, priv); err != nil {
		t.Fatalf("re-sealing: %v", err)
	}

	if err := (&ProofOfBuy{}).VerifyBlock(block); err == nil {
		t.Fatal("a VRF proof made for another parent must not verify")
	}
}

func TestVerifyBlockAcceptsGenesis(t *testing.T) {
	// Genesis has no consensus data and no signature — it is where the chain
	// starts, not a bid for a height.
	genesis := &types.Block{Header: &types.Header{Height: 0}}

	if err := (&ProofOfBuy{}).VerifyBlock(genesis); err != nil {
		t.Fatalf("genesis must pass, got %v", err)
	}
}

func TestVerifyBlockRejectsAHeaderlessBlock(t *testing.T) {
	if err := (&ProofOfBuy{}).VerifyBlock(&types.Block{}); err == nil {
		t.Fatal("a block with no header must be refused")
	}
	if err := (&ProofOfBuy{}).VerifyBlock(nil); err == nil {
		t.Fatal("a nil block must be refused")
	}
}

func TestVerifyCandidateAcceptsAWellFormedRival(t *testing.T) {
	verifier := &MockL1PaymentVerifier{}
	block, vrfInput := wellFormedRival(t, verifier)

	score, ok := (&ProofOfBuy{l1Verifier: verifier}).verifyCandidate(block, vrfInput)

	if !ok {
		t.Fatal("a rival satisfying every check must be accepted")
	}
	if score == nil || score.Sign() <= 0 {
		t.Fatalf("score = %v, want a positive score", score)
	}
}

// Wiring, not existence: the integrity check has to sit on the path that
// accepts other miners' blocks. This rival is valid in every other respect,
// so were verifyCandidate to stop calling VerifyBlockIntegrity it would adopt
// a block carrying transactions its producer never signed.
func TestVerifyCandidateRejectsARivalWhoseTransactionsWereSwapped(t *testing.T) {
	verifier := &MockL1PaymentVerifier{}
	block, vrfInput := wellFormedRival(t, verifier)

	block.SetTxns(txnsWithHashes("0xevil"))

	if _, ok := (&ProofOfBuy{l1Verifier: verifier}).verifyCandidate(block, vrfInput); ok {
		t.Fatal("a rival whose transactions do not match its root must be rejected")
	}
}
