package consensus

import (
	"math/big"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
)

// ProofOfBuy implements the Proof-of-Buying consensus as a yu tripod.
// Phase 1: single-node mode with VDF + mock L1 payment + score calculation.
type ProofOfBuy struct {
	*tripod.Tripod

	cfg       *Config
	myPubkey  keypair.PubKey
	myPrivKey keypair.PrivKey
}

// NewProofOfBuy constructs a ProofOfBuy tripod with the given config and keypair.
// `cfg` must not be nil.
func NewProofOfBuy(cfg *Config, pubkey keypair.PubKey, privkey keypair.PrivKey) *ProofOfBuy {
	tri := tripod.NewTripod()
	return &ProofOfBuy{
		Tripod:    tri,
		cfg:       cfg,
		myPubkey:  pubkey,
		myPrivKey: privkey,
	}
}

// StartBlock runs at the beginning of each block:
//  1. Packs transactions from pool
//  2. Computes VDF from the previous block hash
//  3. Constructs a mock L1 payment
//  4. Calculates the block score
//  5. Encodes consensus data into block.Extra
//  6. Signs the block
func (p *ProofOfBuy) StartBlock(block *types.Block) {
	now := time.Now()
	defer func() {
		elapsed := time.Since(now)
		remaining := time.Duration(p.cfg.BlockInterval)*time.Millisecond - elapsed
		if remaining > 0 {
			time.Sleep(remaining)
		}
	}()

	logrus.Infof("PoB: start block height=%d", block.Height)

	// Pack transactions from pool
	txns, err := p.Pool.Pack(p.cfg.PackNum)
	if err != nil {
		logrus.Panic("pack txns from pool: ", err)
	}

	txnRoot, err := types.MakeTxnRoot(txns)
	if err != nil {
		logrus.Panic("make txn-root failed: ", err)
	}
	block.TxnRoot = txnRoot

	// Compute VDF using previous block hash as input
	vdfInput := block.PrevHash.Bytes()
	vdfResult := Compute(vdfInput, p.cfg.VDFDifficulty)
	logrus.Infof("PoB: VDF computed, difficulty=%d", p.cfg.VDFDifficulty)

	// Construct mock L1 payment
	paymentAmount, ok := new(big.Int).SetString(p.cfg.MinPayment, 10)
	if !ok {
		paymentAmount = big.NewInt(100)
	}
	payment := MockL1Payment(paymentAmount)

	// Calculate block score
	score := CalcBlockScore(payment.Amount, vdfResult.Output)

	// Encode consensus data into block.Extra
	cdata := &ConsensusData{
		VDFResult:  vdfResult,
		L1Payment:  payment,
		BlockScore: score.String(),
	}
	extra, err := EncodeConsensusData(cdata)
	if err != nil {
		logrus.Panic("encode consensus data: ", err)
	}
	block.Extra = extra

	// Compute block hash and sign
	byt, _ := block.Encode()
	block.Hash = common.BytesToHash(common.Sha256(byt))

	block.MinerSignature, err = p.myPrivKey.SignData(block.Hash.Bytes())
	if err != nil {
		logrus.Panic("sign block failed: ", err)
	}
	block.MinerPubkey = p.myPubkey.BytesWithType()

	block.SetTxns(txns)

	// Initialize state snapshot for this block
	p.State.StartBlock(block)

	// Broadcast block via P2P
	blockByt, err := block.Encode()
	if err != nil {
		logrus.Panic("encode block for p2p: ", err)
	}
	if err = p.P2pNetwork.PubP2P(common.StartBlockTopic, blockByt); err != nil {
		logrus.Panic("publish block to p2p: ", err)
	}
}

// EndBlock runs after StartBlock:
//  1. Decodes and verifies consensus data from block.Extra
//  2. Verifies VDF proof
//  3. Verifies L1 payment (mock)
//  4. Recalculates and checks the block score
//  5. Executes all transactions
//  6. Persists the block and finalizes state
func (p *ProofOfBuy) EndBlock(block *types.Block) {
	logrus.Infof("PoB: EndBlock height=%d", block.Height)

	// Decode consensus data from Extra
	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		logrus.Panic("decode consensus data: ", err)
	}

	// Verify VDF proof
	vdfInput := block.PrevHash.Bytes()
	if !Verify(vdfInput, cdata.VDFResult, p.cfg.VDFDifficulty) {
		logrus.Panic("VDF verification failed")
	}

	// Verify L1 payment (mock — always passes)
	if !VerifyL1Payment(cdata.L1Payment) {
		logrus.Panic("L1 payment verification failed")
	}

	// Recalculate score and compare with claimed score
	expectedScore := CalcBlockScore(cdata.L1Payment.Amount, cdata.VDFResult.Output)
	claimedScore, ok := new(big.Int).SetString(cdata.BlockScore, 10)
	if !ok {
		logrus.Panic("invalid block score in consensus data")
	}
	if expectedScore.Cmp(claimedScore) != 0 {
		logrus.Panicf("block score mismatch: expected %s, got %s", expectedScore, claimedScore)
	}

	// Execute all transactions in the block
	logrus.Infof("PoB: executing block %d", block.Height)
	if err = p.Execute(block); err != nil {
		logrus.Panic("execute block failed: ", err)
	}

	// Persist block to chain storage
	if err = p.Chain.AppendBlock(block); err != nil {
		logrus.Panic("append block failed: ", err)
	}

	// Reset txpool with executed transactions
	if err = p.Pool.Reset(block.Txns); err != nil {
		logrus.Panic("reset pool failed: ", err)
	}

	// Finalize state changes for this block
	p.State.FinalizeBlock(block)
}

// FinalizeBlock marks the block as finalized in chain storage.
// Phase 2 will extend this with finality period and fork choice.
func (p *ProofOfBuy) FinalizeBlock(block *types.Block) {
	logrus.Infof("PoB: finalize block height=%d, hash=%s", block.Height, block.Hash.String())
	if err := p.Chain.Finalize(block); err != nil {
		logrus.Error("finalize block failed: ", err)
	}
}
