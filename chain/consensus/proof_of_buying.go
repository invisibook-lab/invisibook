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

	// paymentCh receives L1 payments fetched by the background fetcher goroutine.
	paymentCh chan []*L1Payment
	// vdfMsgCh receives VDF messages from other miners via P2P.
	vdfMsgCh chan *VDFMessage
	// blockCh receives blocks broadcast by the winning miner via P2P.
	blockCh chan *types.Block
	// cancelFunc cancels the background goroutines' context.
	cancelFunc context.CancelFunc
}

// NewProofOfBuy constructs a ProofOfBuy tripod with the given config and keypair.
// `cfg` must not be nil.
func NewProofOfBuy(cfg *Config, pubkey keypair.PubKey, privkey keypair.PrivKey, l1Verifier L1PaymentVerifier) *ProofOfBuy {
	tri := tripod.NewTripod()
	return &ProofOfBuy{
		Tripod:     tri,
		cfg:        cfg,
		myPubkey:   pubkey,
		myPrivKey:  privkey,
		l1Verifier: l1Verifier,
		paymentCh:  make(chan []*L1Payment, 1),
		vdfMsgCh:   make(chan *VDFMessage, 64),
		blockCh:    make(chan *types.Block, 1),
	}
}

// InitChain starts 3 background goroutines:
//  1. L1 payment fetcher: periodically polls L1 for miner payments.
//  2. VDF listener: subscribes to VDFMessageTopic for other miners' VDF results.
//  3. Block listener: subscribes to StartBlockTopic for blocks from the winning miner.
func (p *ProofOfBuy) InitChain(_ *types.Block) {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancelFunc = cancel

	// Register custom VDF message topic
	p.P2pNetwork.AddTopic(VDFMessageTopic)

	go p.l1PaymentFetcher(ctx)
	go p.vdfListener(ctx)
	go p.blockListener(ctx)
}

// l1PaymentFetcher periodically calls FetchAndVerifyPayments and sends
// the results to paymentCh. The channel is non-blocking: if StartBlock
// hasn't consumed the previous batch, it is replaced.
func (p *ProofOfBuy) l1PaymentFetcher(ctx context.Context) {
	// Fetch interval is half the block interval so payments are ready
	// before StartBlock needs them.
	interval := time.Duration(p.cfg.BlockInterval/2) * time.Millisecond
	if interval <= 0 {
		interval = 1 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			payments, err := p.l1Verifier.FetchAndVerifyPayments(ctx)
			if err != nil {
				logrus.Warnf("PoB: fetch L1 payments failed: %v", err)
				continue
			}
			// Non-blocking send: replace stale data if not consumed yet.
			select {
			case p.paymentCh <- payments:
			default:
				// Drain old value and push new one.
				select {
				case <-p.paymentCh:
				default:
				}
				p.paymentCh <- payments
			}
		}
	}
}

// vdfListener subscribes to the VDF P2P topic and forwards validated
// messages to vdfMsgCh for StartBlock to collect.
func (p *ProofOfBuy) vdfListener(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		raw, err := p.P2pNetwork.SubP2P(VDFMessageTopic)
		if err != nil {
			logrus.Warnf("PoB: subscribe VDF message failed: %v", err)
			continue
		}
		msg, err := DecodeVDFMessage(raw)
		if err != nil {
			logrus.Warnf("PoB: decode VDF message failed: %v", err)
			continue
		}

		// TODO(phase2): verify signature and VDF proof before forwarding.

		select {
		case p.vdfMsgCh <- msg:
		default:
			logrus.Warn("PoB: vdfMsgCh full, dropping VDF message")
		}
	}
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
//  1. Fetches latest L1 payments from paymentCh
//  2. Computes local VDF from the previous block hash
//  3. Signs and broadcasts VDF to VDFMessageTopic
//  4. Collects other miners' VDFs during BlockInterval
//  5. Matches VDFs with payments to compute scores
//  6. If this node has the highest score: packs transactions, signs and broadcasts block
//  7. Otherwise: waits for the winning miner's block from blockCh
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

	// Step 1: Get the latest L1 payments (non-blocking with fallback).
	payments := p.drainPayments()

	// Step 2: Compute local VDF.
	vdfInput := block.PrevHash.Bytes()
	vdfResult := Compute(vdfInput, p.cfg.VDFDifficulty)
	logrus.Infof("PoB: VDF computed, difficulty=%d", p.cfg.VDFDifficulty)

	// Step 3: Sign and broadcast VDF message.
	signPayload := append(vdfInput, vdfResult.ProofBlob...)
	sig, err := p.myPrivKey.SignData(signPayload)
	if err != nil {
		logrus.Panic("PoB: sign VDF message failed: ", err)
	}
	vdfMsg := &VDFMessage{
		VDFResult: vdfResult,
		Input:     vdfInput,
		Signature: sig,
	}
	vdfBytes, err := EncodeVDFMessage(vdfMsg)
	if err != nil {
		logrus.Panic("PoB: encode VDF message failed: ", err)
	}
	if err = p.P2pNetwork.PubP2P(VDFMessageTopic, vdfBytes); err != nil {
		logrus.Warnf("PoB: publish VDF message failed: %v", err)
	}

	// Step 4: Collect other miners' VDFs during a short collection window.
	// Phase 1: no other miners, so this immediately returns empty.
	_ = p.collectVDFMessages()

	// Step 5: Find this node's payment and compute score.
	myPayment := p.findMyPayment(payments)
	if myPayment == nil {
		logrus.Warn("PoB: no payment found for this miner, using MinPayment fallback")
		amount, ok := new(big.Int).SetString(p.cfg.MinPayment, 10)
		if !ok {
			amount = big.NewInt(100)
		}
		myPayment = MockL1Payment(amount, p.myPubkeyHex())
	}
	myScore := CalcBlockScore(myPayment.Amount, VDFOutput(vdfResult))

	// Step 6: Determine if we are the highest-scoring miner.
	// Phase 1: single node, always highest score.
	iAmHighest := true

	if iAmHighest {
		p.produceBlock(block, vdfResult, myPayment, myScore)
	} else {
		// Step 7: Wait for the winning miner's block.
		p.waitForWinnerBlock(block)
	}
}

// drainPayments returns the latest L1 payments from paymentCh.
// Returns nil if no payments are available.
func (p *ProofOfBuy) drainPayments() []*L1Payment {
	select {
	case payments := <-p.paymentCh:
		return payments
	default:
		return nil
	}
}

// collectVDFMessages drains all pending VDF messages from vdfMsgCh.
// In Phase 1 this returns an empty slice since there are no other miners.
func (p *ProofOfBuy) collectVDFMessages() []*VDFMessage {
	var msgs []*VDFMessage
	for {
		select {
		case msg := <-p.vdfMsgCh:
			msgs = append(msgs, msg)
		default:
			return msgs
		}
	}
}

// findMyPayment looks up this node's payment from the fetched list.
func (p *ProofOfBuy) findMyPayment(payments []*L1Payment) *L1Payment {
	myPub := p.myPubkeyHex()
	for _, pay := range payments {
		if pay.MinerPubkey == myPub {
			return pay
		}
	}
	return nil
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

// waitForWinnerBlock waits for the winning miner's block from blockCh.
// If no block arrives within BlockInterval, the round is skipped.
func (p *ProofOfBuy) waitForWinnerBlock(block *types.Block) {
	timeout := time.Duration(p.cfg.BlockInterval) * time.Millisecond
	select {
	case winner := <-p.blockCh:
		logrus.Infof("PoB: received winner block height=%d hash=%s", winner.Height, winner.Hash.String())
		// Copy winner block data into current block frame.
		*block = *winner
	case <-time.After(timeout):
		logrus.Warn("PoB: timeout waiting for winner block, skipping round")
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
