package consensus

import (
	"context"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
)

// ProofOfBuy implements the Proof-of-Buying consensus as a yu tripod.
// Phase 1: single-node mode with VDF + mock L1 payment + score-based block competition.
type ProofOfBuy struct {
	*tripod.Tripod

	cfg        *Config
	myPubkey   keypair.PubKey
	myPrivKey  keypair.PrivKey
	l1Verifier L1PaymentVerifier

	// blockCh receives blocks broadcast by other miners via P2P.
	blockCh chan *types.Block
	// cancelFunc cancels the background goroutines' context.
	cancelFunc context.CancelFunc
}

// NewProofOfBuy constructs a ProofOfBuy tripod with the given config, keypair
// and L1 verifier.
// `cfg` must not be nil.
func NewProofOfBuy(cfg *Config, pubkey keypair.PubKey, privkey keypair.PrivKey, l1Verifier L1PaymentVerifier) *ProofOfBuy {
	tri := tripod.NewTripod()
	return &ProofOfBuy{
		Tripod:     tri,
		cfg:        cfg,
		myPubkey:   pubkey,
		myPrivKey:  privkey,
		l1Verifier: l1Verifier,
		blockCh:    make(chan *types.Block, 16),
	}
}

// InitChain starts the block listener goroutine that receives blocks
// from other miners via P2P.
func (p *ProofOfBuy) InitChain(_ *types.Block) {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancelFunc = cancel

	go p.blockListener(ctx)
}

// blockListener subscribes to the P2P block topic and forwards
// blocks from other miners to blockCh.
func (p *ProofOfBuy) blockListener(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		raw, err := p.P2pNetwork.SubP2P(common.StartBlockTopic)
		if err != nil {
			logrus.Warnf("PoB: subscribe block failed: %v", err)
			continue
		}
		block, err := types.DecodeBlock(raw)
		if err != nil {
			logrus.Warnf("PoB: decode p2p block failed: %v", err)
			continue
		}
		// Skip blocks produced by ourselves.
		if hex.EncodeToString(block.MinerPubkey) == hex.EncodeToString(p.myPubkey.BytesWithType()) {
			continue
		}

		select {
		case p.blockCh <- block:
		default:
			logrus.Warn("PoB: blockCh full, dropping block")
		}
	}
}

// myPubkeyHex returns the hex-encoded public key of this node.
func (p *ProofOfBuy) myPubkeyHex() string {
	return hex.EncodeToString(p.myPubkey.BytesWithType())
}

// StartBlock runs at the beginning of each block:
//  1. Computes local VDF from the previous block hash
//  2. Calculates this node's score using its own L1 payment
//  3. Packs transactions, signs and broadcasts the block
//  4. Collects candidate blocks from other miners during BlockInterval
//  5. For each candidate: verifies VDF, verifies L1 payment, compares score
//  6. If another miner wins, replaces this block with the winner's
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

	// Step 1: Fetch this node's L1 payment.
	myPayment, err := p.l1Verifier.FetchMyPayment(context.Background())
	if err != nil {
		logrus.Panicf("PoB: fetch my L1 payment failed: %v", err)
	}

	// Step 2: Compute local VDF.
	vdfInput := block.PrevHash.Bytes()
	vdfResult := Compute(vdfInput, p.cfg.VDFDifficulty)
	logrus.Infof("PoB: VDF computed, difficulty=%d", p.cfg.VDFDifficulty)

	// Step 3: Calculate this node's score.
	myScore := CalcBlockScore(myPayment.Amount, VDFOutput(vdfResult))

	// Step 4: Produce, sign and broadcast our block.
	p.produceBlock(block, vdfResult, myPayment, myScore)

	// Step 5: Collect candidate blocks during the remaining block interval.
	candidates := p.collectCandidateBlocks()

	// Step 6: Verify each candidate and find the highest-scoring block.
	bestBlock := block
	bestScore := myScore

	for _, candidate := range candidates {
		// Decode consensus data from candidate's Extra field.
		cdata, err := DecodeConsensusData(candidate.Extra)
		if err != nil {
			logrus.Warnf("PoB: decode candidate consensus data failed: %v", err)
			continue
		}

		// Verify VDF proof.
		if !Verify(vdfInput, cdata.VDFResult, p.cfg.VDFDifficulty) {
			logrus.Warn("PoB: candidate VDF verification failed, skipping")
			continue
		}

		// Verify L1 payment existence.
		if !p.l1Verifier.VerifyPayment(context.Background(), cdata.L1Payment) {
			logrus.Warn("PoB: candidate L1 payment verification failed, skipping")
			continue
		}

		// Recalculate candidate's score.
		candidateScore := CalcBlockScore(cdata.L1Payment.Amount, VDFOutput(cdata.VDFResult))
		if candidateScore.Cmp(bestScore) > 0 {
			bestBlock = candidate
			bestScore = candidateScore
		}
	}

	// Step 7: If another miner won, replace our block with theirs.
	if bestBlock != block {
		logrus.Infof("PoB: another miner won with score=%s, replacing block", bestScore)
		*block = *bestBlock
	}
}

// collectCandidateBlocks drains all pending blocks from blockCh.
// Returns all candidate blocks received from other miners.
func (p *ProofOfBuy) collectCandidateBlocks() []*types.Block {
	var candidates []*types.Block
	for {
		select {
		case candidate := <-p.blockCh:
			candidates = append(candidates, candidate)
		default:
			return candidates
		}
	}
}

// produceBlock packs transactions, encodes consensus data, signs and broadcasts the block.
func (p *ProofOfBuy) produceBlock(block *types.Block, vdfResult *VDFResult, payment *L1Payment, score *big.Int) {
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
//  3. Recalculates and checks the block score
//  4. Executes all transactions
//  5. Persists the block and finalizes state
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

	// Recalculate score and compare with claimed score
	expectedScore := CalcBlockScore(cdata.L1Payment.Amount, VDFOutput(cdata.VDFResult))
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
