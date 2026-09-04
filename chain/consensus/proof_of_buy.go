package consensus

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"sort"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
)

// ProofOfBuy implements the Proof-of-Buy consensus as a yu tripod.
// Phase 1: single-node mode with VRF + mock L1 payment + score-based block competition.
type ProofOfBuy struct {
	*tripod.Tripod

	cfg        *Config
	myPubkey   keypair.PubKey
	myPrivKey  keypair.PrivKey
	l1Verifier L1PaymentVerifier

	// vrfPrivKey is the miner's secp256k1 key in ecdsa form. It is the same
	// key as myPrivKey — block signing and VRF evaluation share one identity.
	vrfPrivKey *ecdsa.PrivateKey

	// lastPaymentInput holds the most recent payment input received from
	// PendingPaymentCh by the paymentListener goroutine.
	lastPaymentInput *L1PaymentInput
	// blockCh receives blocks broadcast by other miners via P2P.
	blockCh chan *types.Block

	// l1Submitter submits block headers to L1 and polls for confirmation.
	l1Submitter L1HeaderSubmitter
	// pendingFinalizations is a buffered channel for blocks awaiting L1 finalization.
	pendingFinalizations chan *pendingFinalization
}

// NewProofOfBuy constructs a ProofOfBuy tripod with the given config, keypair,
// L1 verifier, VRF private key, and L1 header submitter.
// `cfg` must not be nil; `pubkey`/`privkey` must be a secp256k1 keypair and
// `vrfPrivKey` must be the same key in ecdsa form (see SecpPrivKeyToECDSA).
func NewProofOfBuy(cfg *Config, pubkey keypair.PubKey, privkey keypair.PrivKey, l1Verifier L1PaymentVerifier, vrfPrivKey *ecdsa.PrivateKey, l1Submitter L1HeaderSubmitter) *ProofOfBuy {
	tri := tripod.NewTripod()
	p := &ProofOfBuy{
		Tripod:               tri,
		cfg:                  cfg,
		myPubkey:             pubkey,
		myPrivKey:            privkey,
		l1Verifier:           l1Verifier,
		vrfPrivKey:           vrfPrivKey,
		blockCh:              make(chan *types.Block, 16),
		l1Submitter:          l1Submitter,
		pendingFinalizations: make(chan *pendingFinalization, 100),
	}
	return p
}

// InitChain starts the block listener, payment listener, and finality worker goroutines.
func (p *ProofOfBuy) InitChain(_ *types.Block) {
	go p.blockListener()
	go p.paymentListener()
	go p.finalityWorker()
}

// paymentListener reads from the global PendingPaymentCh and stores
// the latest payment input for StartBlock to consume.
func (p *ProofOfBuy) paymentListener() {
	for {
		select {
		case input := <-PendingPaymentCh:
			p.lastPaymentInput = input
			logrus.Infof("PoB: paymentListener received payment_hash=%s", input.PaymentHash)
		}
	}
}

// blockListener subscribes to the P2P block topic and forwards
// blocks from other miners to blockCh.
func (p *ProofOfBuy) blockListener() {
	for {
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
		if hex.EncodeToString(block.MinerPubkey) == p.myPubkeyHex() {
			continue
		}

		select {
		case p.blockCh <- block:
		default:
			logrus.Warn("PoB: blockCh full, dropping block")
		}
	}
}

// myPubkeyHex returns this node's compressed secp256k1 public key as hex.
// The raw 33-byte encoding is used rather than yu's BytesWithType, whose
// secp256k1 branch tags the key as sr25519, and because it is exactly the
// byte string CKB blake160-hashes into a lock's args.
func (p *ProofOfBuy) myPubkeyHex() string {
	return hex.EncodeToString(p.myPubkey.Bytes())
}

// StartBlock runs at the beginning of each block:
//  1. Consumes the latest external L1 payment input
//  2. Computes VRF from the previous block hash using this node's VRF key
//  3. Calculates this node's score using L1 payment amount and VRF output
//  4. Packs transactions, signs and broadcasts the block
//  5. Collects candidate blocks from other miners during BlockInterval
//  6. For each candidate: verifies VRF, verifies L1 payment, compares score
//  7. If another miner wins, replaces this block with the winner's
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

	// Step 1: Consume the latest external payment input.
	var myPayment *L1Payment
	if p.lastPaymentInput != nil {
		logrus.Infof("PoB: using payment_hash=%s", p.lastPaymentInput.PaymentHash)
		amount, ok := new(big.Int).SetString(p.lastPaymentInput.Amount, 10)
		if !ok {
			logrus.Warnf("PoB: invalid payment amount %q, falling back to MinPayment", p.lastPaymentInput.Amount)
			amount, _ = new(big.Int).SetString(p.cfg.MinPayment, 10)
		}
		myPayment = MockL1Payment(amount, p.myPubkeyHex())
		p.lastPaymentInput = nil
	} else {
		logrus.Info("PoB: no external payment input, using fallback mock payment")
		fallback, _ := new(big.Int).SetString(p.cfg.MinPayment, 10)
		myPayment = MockL1Payment(fallback, p.myPubkeyHex())
	}

	// Step 2: Compute VRF from previous block hash, using the miner key.
	vrfInput := block.PrevHash.Bytes()
	vrfResult, err := VRFProve(p.vrfPrivKey, vrfInput)
	if err != nil {
		logrus.Panic("VRF prove failed: ", err)
	}
	logrus.Infof("PoB: VRF computed, pubkey=%s", p.myPubkeyHex())

	// Step 3: Calculate this node's score.
	myScore := CalcBlockScore(myPayment.Amount, vrfResult.Output)

	// Step 4: Produce, sign and broadcast our block.
	p.produceBlock(block, vrfResult, myPayment, myScore)

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

		// Verify the VRF proof against the candidate's own block key. Because
		// that key also owns the L1 payment, a miner can neither grind VRF
		// keys nor borrow another miner's randomness.
		if !VRFVerify(candidate.MinerPubkey, vrfInput, cdata.VRFResult) {
			logrus.Warn("PoB: candidate VRF verification failed, skipping")
			continue
		}

		// The payment must have been made by the same identity that produced
		// the block, otherwise a miner could claim someone else's payment.
		if cdata.L1Payment == nil || cdata.L1Payment.MinerPubkey != hex.EncodeToString(candidate.MinerPubkey) {
			logrus.Warn("PoB: candidate payment not bound to its miner key, skipping")
			continue
		}

		// Verify L1 payment existence.
		if !p.l1Verifier.VerifyPayment(context.Background(), cdata.L1Payment) {
			logrus.Warn("PoB: candidate L1 payment verification failed, skipping")
			continue
		}

		// Recalculate candidate's score.
		candidateScore := CalcBlockScore(cdata.L1Payment.Amount, cdata.VRFResult.Output)
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
func (p *ProofOfBuy) produceBlock(block *types.Block, vrfResult *VRFResult, payment *L1Payment, score *big.Int) {
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
		VRFResult:  vrfResult,
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
	block.MinerPubkey = p.myPubkey.Bytes()

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
//  2. Verifies VRF proof
//  3. Executes all transactions
//  4. Persists the block and finalizes state
func (p *ProofOfBuy) EndBlock(block *types.Block) {
	logrus.Infof("PoB: EndBlock height=%d", block.Height)

	// Decode consensus data from Extra
	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		logrus.Panic("decode consensus data: ", err)
	}

	// Verify VRF proof against the block producer's key
	vrfInput := block.PrevHash.Bytes()
	if !VRFVerify(block.MinerPubkey, vrfInput, cdata.VRFResult) {
		logrus.Panic("VRF verification failed")
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

// FinalizeBlock enqueues the block for asynchronous L1-driven finalization.
// The actual finalization happens in the finalityWorker goroutine after
// the block header is submitted to and confirmed on L1.
func (p *ProofOfBuy) FinalizeBlock(block *types.Block) {
	logrus.Infof("PoB: queuing block for L1 finalization height=%d, hash=%s", block.Height, block.Hash.String())
	p.pendingFinalizations <- &pendingFinalization{block: block}
}

// finalityWorker runs as a background goroutine. It receives blocks from
// pendingFinalizations, submits their headers to L1, then polls for
// confirmation. Blocks are finalized strictly in height order.
func (p *ProofOfBuy) finalityWorker() {
	pollInterval := time.Duration(p.cfg.L1PollInterval) * time.Millisecond
	// pending holds blocks that have been submitted to L1 but not yet confirmed.
	var pending []*pendingFinalization

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case pf := <-p.pendingFinalizations:
			// Submit block header to L1.
			header := &BlockHeaderSubmission{
				L2BlockHeight: pf.block.Height,
				L2BlockHash:   pf.block.Hash,
				TxnRoot:       pf.block.TxnRoot,
				MinerPubkey:   hex.EncodeToString(pf.block.MinerPubkey),
			}
			l1TxHash, err := p.l1Submitter.SubmitBlockHeader(context.Background(), header)
			if err != nil {
				logrus.Errorf("PoB: failed to submit block header to L1 height=%d: %v", pf.block.Height, err)
				continue
			}
			pf.l1TxHash = l1TxHash
			pf.submittedAt = time.Now()
			pending = append(pending, pf)
			logrus.Infof("PoB: submitted block header to L1 height=%d, l1_tx=%s", pf.block.Height, l1TxHash)

		case <-ticker.C:
			if len(pending) == 0 {
				continue
			}
			// Sort by height to ensure strict ordering.
			sort.Slice(pending, func(i, j int) bool {
				return pending[i].block.Height < pending[j].block.Height
			})
			// Finalize confirmed blocks in height order. Stop at the first
			// unconfirmed block to preserve strict ordering.
			confirmed := 0
			for _, pf := range pending {
				ok, err := p.l1Submitter.IsConfirmed(context.Background(), pf.l1TxHash)
				if err != nil {
					logrus.Errorf("PoB: L1 confirmation check failed height=%d: %v", pf.block.Height, err)
					break
				}
				if !ok {
					break
				}
				// L1 confirmed — finalize the block locally.
				if err := p.Chain.Finalize(pf.block); err != nil {
					logrus.Errorf("PoB: finalize block failed height=%d: %v", pf.block.Height, err)
				} else {
					logrus.Infof("PoB: L1-confirmed finalization height=%d, l1_tx=%s", pf.block.Height, pf.l1TxHash)
				}
				confirmed++
			}
			// Remove finalized entries.
			if confirmed > 0 {
				pending = pending[confirmed:]
			}
		}
	}
}
