package consensus

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"

	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/store"
)

// ProofOfBuy implements the Proof-of-Buy consensus as a yu tripod.
// Phase 1: single-node mode with VRF + mock L1 payment + score-based block competition.
type ProofOfBuy struct {
	*tripod.Tripod

	cfg        *Config
	myPubkey   keypair.PubKey
	myPrivKey  keypair.PrivKey
	l1Verifier L1PaymentVerifier
	// l1Reader reads back what was written to L1: whether a commitment is
	// anchored, when, and who owns an allocation table. V1, V4 and V7's first
	// item all rest on it.
	l1Reader L1Reader

	// vrfPrivKey is the miner's secp256k1 key in ecdsa form. It is the same
	// key as myPrivKey — block signing and VRF evaluation share one identity.
	vrfPrivKey *ecdsa.PrivateKey

	// paymentBook holds the per-height payment declarations submitted by the
	// miner through the HTTP endpoint.
	paymentBook *PaymentBook
	// blockCh receives blocks broadcast by other miners via P2P.
	blockCh chan *types.Block

	// Account is injected by the kernel (yu's `tripod` struct tag). Block
	// rewards are minted as cash on it.
	Account *account.Account `tripod:"account"`

	// l1Submitter posts block commitments to L1 and reports their depth.
	l1Submitter L1CommitmentSubmitter
	// bids holds the opening of every commitment this node posted. L1 carries
	// only the commitment, so losing an opening forfeits that bid outright.
	bids *store.Bids
	// reveals holds the openings the whole network has published, this node's
	// own included. Fork choice reads them: without the opening, a block's
	// goal cannot be tied to any commitment on L1.
	reveals *store.Reveals
	// revealSyncer catches up on the openings this node missed while it was
	// down. Gossip cannot: a topic carries only what is published after you
	// subscribe.
	revealSyncer *RevealSyncer
	// pending stages each block's writes until its commitment is deep enough
	// on L1 to be treated as irreversible.
	pending *store.Pending

	// pendingFinalizations is a buffered channel for blocks awaiting L1 depth.
	pendingFinalizations chan *pendingFinalization
}

// NewProofOfBuy constructs a ProofOfBuy tripod with the given config, keypair,
// L1 verifier, VRF private key, L1 commitment submitter, bid store and payment
// book.
// `cfg` must not be nil; `pubkey`/`privkey` must be a secp256k1 keypair and
// `vrfPrivKey` must be the same key in ecdsa form (see SecpPrivKeyToECDSA);
// `paymentBook` must be the same instance the HTTP endpoint writes into;
// `bids` must be backed by the chain database, since an opening that is lost
// cannot be reconstructed.
func NewProofOfBuy(cfg *Config, pubkey keypair.PubKey, privkey keypair.PrivKey, l1Verifier L1PaymentVerifier, l1Reader L1Reader, vrfPrivKey *ecdsa.PrivateKey, l1Submitter L1CommitmentSubmitter, bids *store.Bids, reveals *store.Reveals, paymentBook *PaymentBook, pending *store.Pending) *ProofOfBuy {
	tri := tripod.NewTripod()
	p := &ProofOfBuy{
		Tripod:               tri,
		cfg:                  cfg,
		myPubkey:             pubkey,
		myPrivKey:            privkey,
		l1Verifier:           l1Verifier,
		l1Reader:             l1Reader,
		vrfPrivKey:           vrfPrivKey,
		paymentBook:          paymentBook,
		blockCh:              make(chan *types.Block, 16),
		l1Submitter:          l1Submitter,
		bids:                 bids,
		reveals:              reveals,
		pending:              pending,
		pendingFinalizations: make(chan *pendingFinalization, 100),
	}

	// The handler is registered here, not in InitChain: the kernel collects
	// every tripod's p2p handlers while it is being constructed, which is
	// finished long before InitChain runs. Registering any later would leave
	// RevealSyncCode unanswered for the whole life of the node.
	p.revealSyncer = NewRevealSyncer(reveals)
	p.SetP2pHandler(RevealSyncCode, p.revealSyncer.HandleRequest)

	return p
}

// InitChain reconciles the stores after a restart, then starts the block
// listener, the reveal listener and the finality worker goroutines.
func (p *ProofOfBuy) InitChain(_ *types.Block) {
	p.reconcile()
	// Ours is not one of yu's built-in topics, and both PubP2P and SubP2P
	// refuse an unregistered one outright — without this call every reveal
	// would fail to send and none would ever arrive.
	p.P2pNetwork.AddTopic(RevealTopic)

	// Catching up runs on its own rather than inside block sync: openings and
	// blocks travel separately, and an opening whose block has not arrived
	// yet simply waits in the store. Doing it here keeps this out of yu's
	// sync path entirely. This is also the first point at which the kernel
	// has given us a network to ask.
	go p.catchUpReveals()

	go p.blockListener()
	go p.revealListener()
	go p.finalityWorker()
}

// catchUpReveals pulls the openings this node missed, once, at startup.
//
// Failures are logged rather than retried: the gossip topic keeps this node
// current from here on, and the next restart will ask again for whatever is
// still missing.
func (p *ProofOfBuy) catchUpReveals() {
	stored, err := p.revealSyncer.CatchUp(p.P2pNetwork)
	if err != nil {
		logrus.Errorf("PoB: catching up on reveals: %v", err)
		return
	}
	if stored > 0 {
		logrus.Infof("PoB: caught up on %d reveals from peers", stored)
	}
}

// reconcile brings the chain and the staged writes back into agreement after a
// restart, which is the only time they can disagree.
//
// The promoted height is the boundary, not yu's finalized marker: it is
// written with the state it describes, so it is exactly how far the tables
// got. Everything at or below it was settled by L1 and is already in the
// tables; everything above it was never promised to anyone and goes.
//
// Three things can be out of place, and all three are idempotent to fix:
//
//   - A block whose state was promoted but whose finalized marker was not
//     written — the crash window between the two. Marking it finalized costs
//     nothing: L1 had already ruled for it before the promotion ran.
//   - Staged rows of blocks above the boundary. The finality worker's queue
//     lives in memory, so after a restart nothing would ever rule on them; left
//     alone they would overlay every read forever.
//   - The blocks themselves, above the boundary, still on the chain.
func (p *ProofOfBuy) reconcile() {
	applied, err := p.pending.AppliedHeight()
	if err != nil {
		logrus.Errorf("PoB: reading the promoted height: %v — skipping reconciliation", err)
		return
	}

	p.finalizeThrough(applied)

	if err := p.pending.DropFrom(applied + 1); err != nil {
		logrus.Errorf("PoB: dropping staged writes above height=%d: %v", applied, err)
		return
	}
	// Pruning by the promoted height rather than by Prune()'s own boundary:
	// yu's marker may still lag it, and pruning to a lagging boundary would
	// delete blocks whose state is already in the tables.
	if err := p.Chain.PruneAfter(applied + 1); err != nil {
		logrus.Errorf("PoB: pruning blocks above height=%d: %v", applied, err)
		return
	}

	logrus.Infof("PoB: reconciled to height=%d", applied)
}

// finalizeThrough marks every block up to `height` finalized, catching up the
// chain when a crash landed between promoting a block's state and recording
// that it was final.
func (p *ProofOfBuy) finalizeThrough(height common.BlockNum) {
	for h := common.BlockNum(1); h <= height; h++ {
		// Asked per height rather than from LastFinalized: that reads an
		// in-memory pointer the kernel has not populated this early, so on a
		// fresh process it reports nothing finalized and every height would be
		// marked again.
		if done, err := p.Chain.GetFinalizedCompactBlockByHeight(h); err == nil && done != nil {
			continue
		}

		block, err := p.Chain.GetBlockByHeight(h)
		if err != nil {
			logrus.Errorf("PoB: reading block %d to finalize it: %v", h, err)
			return
		}
		if err := p.Chain.Finalize(block); err != nil {
			logrus.Errorf("PoB: finalizing block %d: %v", h, err)
			return
		}
		p.State.FinalizeBlock(block)
		logrus.Infof("PoB: marked height=%d finalized, its state was already promoted", h)
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
func (p *ProofOfBuy) myPubkeyHex() string {
	return MinerPubkeyHex(p.myPubkey)
}

// StartBlock runs at the beginning of each block:
//  1. Takes this height's declared L1 payment (already confirmed on L1)
//  2. Computes VRF from the previous block hash using this node's VRF key
//  3. Calculates this node's score using L1 payment amount and VRF output
//  4. Packs transactions, signs and broadcasts the block
//  5. Collects rival blocks for the rest of the block interval
//  6. For each candidate: verifies VRF, confirms the payment, compares score
//  7. Settles on the highest-scoring block
//
// A node that declared no payment has no way to win the height and nothing
// worth broadcasting, so it takes none of those steps: it parks on the P2P
// channel and waits for a block from a miner that did pay. That wait has no
// deadline — an idle miner simply stops here until the network moves the chain
// forward. StartBlock therefore always returns with a block in hand, which is
// what EndBlock and FinalizeBlock rely on.
func (p *ProofOfBuy) StartBlock(block *types.Block) {
	deadline := time.Now().Add(time.Duration(p.cfg.BlockInterval) * time.Millisecond)

	logrus.Infof("PoB: start block height=%d", block.Height)

	vrfInput := block.PrevHash.Bytes()

	// Step 1: take this height's L1-confirmed payment declaration.
	myPayment := p.resolvePayment(block.Height)
	if myPayment == nil {
		p.awaitRivalBlock(block, vrfInput)
		p.paymentBook.Settle(block.Height)
		return
	}

	// Steps 2-4: compete for the height.
	vrfResult, err := VRFProve(p.vrfPrivKey, vrfInput)
	if err != nil {
		// Without a VRF output there is no score to compete with.
		logrus.Errorf("PoB: VRF prove failed at height=%d: %v, standing down", block.Height, err)
		p.awaitRivalBlock(block, vrfInput)
		p.paymentBook.Settle(block.Height)
		return
	}
	logrus.Infof("PoB: VRF computed, pubkey=%s", p.myPubkeyHex())

	bestScore := CalcBlockScore(myPayment.Amount, vrfResult.Output)
	if err := p.produceBlock(block, vrfResult, myPayment, bestScore); err != nil {
		logrus.Errorf("PoB: building block at height=%d: %v, standing down", block.Height, err)
		p.awaitRivalBlock(block, vrfInput)
		p.paymentBook.Settle(block.Height)
		return
	}

	// Steps 5-6: give rivals the rest of the interval to broadcast, and keep
	// the best block among theirs and ours.
	var bestRival *types.Block
	for _, candidate := range p.collectCandidateBlocks(block.Height, deadline) {
		score, ok := p.verifyCandidate(candidate, vrfInput)
		if !ok {
			continue
		}
		if score.Cmp(bestScore) > 0 {
			bestRival, bestScore = candidate, score
		}
	}

	// Step 7: adopt a rival's block if it outbid us.
	if bestRival != nil {
		logrus.Infof("PoB: another miner won height=%d with score=%s, adopting their block",
			block.Height, bestScore)
		*block = *bestRival
	}

	// The chain has a block for this height now: close it off so stale
	// declarations at or below it are dropped.
	p.paymentBook.Settle(block.Height)
}

// awaitRivalBlock blocks until a miner that paid for this height broadcasts a
// block this node can verify, then adopts it into `block`.
//
// Nothing else depends on this goroutine making progress — the payment
// endpoint, the P2P listener and the finality worker all run on their own — so
// parking here costs nothing but this node's participation in a height it
// cannot win anyway. `vrfInput` must be the VRF input for `block`'s height.
func (p *ProofOfBuy) awaitRivalBlock(block *types.Block, vrfInput []byte) {
	logrus.Infof("PoB: waiting for a block from a miner that paid for height=%d", block.Height)

	for candidate := range p.blockCh {
		if candidate.Height != block.Height {
			logrus.Warnf("PoB: ignoring block for height=%d while waiting on height=%d",
				candidate.Height, block.Height)
			continue
		}
		score, ok := p.verifyCandidate(candidate, vrfInput)
		if !ok {
			continue
		}

		logrus.Infof("PoB: adopting block for height=%d from another miner, score=%s",
			block.Height, score)
		*block = *candidate
		// produceBlock never ran, so open the state snapshot EndBlock's
		// execution needs.
		p.State.StartBlock(block)
		return
	}
}

// VerifyBlock checks a block that arrived from elsewhere, before the chain
// takes it in.
//
// yu calls this on the synchronizer's path, which fetches blocks from a peer
// and then verifies, appends and executes each one. This hook is the only
// examination on that path: without it, blocks pulled during catch-up reach
// the chain — and the staging layer — entirely unchecked, while blocks
// arriving over the block topic go through verifyCandidate.
//
// It checks what a block can be judged on by itself: that its producer
// authored the transactions it carries, and that its VRF proof stands against
// its own parent. Both read nothing outside the block.
//
// It deliberately does not confirm the payment. That means asking L1, and the
// synchronizer runs this over every block it fetches — a round trip apiece
// would make catching up impossible. Whether a block's payment is real, and
// so whether the block counts towards a branch, is settled later by the
// V1–V8 checks.
func (p *ProofOfBuy) VerifyBlock(block *types.Block) error {
	if block == nil || block.Header == nil {
		return errors.New("block has no header")
	}
	// Genesis carries no consensus data and nobody signed it: it is where the
	// chain starts, not a bid for a height.
	if block.Height == 0 {
		return nil
	}

	if err := VerifyBlockIntegrity(block); err != nil {
		return fmt.Errorf("block %s: %w", block.Hash, err)
	}

	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		return fmt.Errorf("block %s: decoding consensus data: %w", block.Hash, err)
	}
	// The VRF input is the block's own parent, so this stands on its own —
	// no need to know which height this node is currently building.
	if !VRFVerify(block.MinerPubkey, block.PrevHash.Bytes(), cdata.VRFResult) {
		return fmt.Errorf("block %s: VRF proof does not verify against its parent", block.Hash)
	}
	return nil
}

// verifyCandidate checks a rival's block and returns its score.
// Both the competing path and the waiting path judge candidates through here,
// so a block this node adopts has passed exactly the checks it would have
// applied to its own. `vrfInput` must be the VRF input for the candidate's
// height. Returns false when the candidate must be discarded.
func (p *ProofOfBuy) verifyCandidate(candidate *types.Block, vrfInput []byte) (*big.Int, bool) {
	// First, and before anything that reads the candidate's claims: the block
	// has to be the producer's own work. Both the VRF proof and the payment
	// checked below are public once revealed, so a block that skips this
	// could carry someone else's proof and payment over transactions the
	// attacker chose.
	if err := VerifyBlockIntegrity(candidate); err != nil {
		logrus.Warnf("PoB: candidate failed its integrity checks: %v, skipping", err)
		return nil, false
	}

	cdata, err := DecodeConsensusData(candidate.Extra)
	if err != nil {
		logrus.Warnf("PoB: decode candidate consensus data failed: %v", err)
		return nil, false
	}

	// Verify the VRF proof against the candidate's own block key. Because that
	// key also owns the L1 payment, a miner can neither grind VRF keys nor
	// borrow another miner's randomness.
	if !VRFVerify(candidate.MinerPubkey, vrfInput, cdata.VRFResult) {
		logrus.Warn("PoB: candidate VRF verification failed, skipping")
		return nil, false
	}

	// Confirm the candidate's payment the same way this node's own
	// declarations were confirmed: bound to the block producer, backed by an
	// allocation on L1, and opening that allocation's commitment.
	producer := hex.EncodeToString(candidate.MinerPubkey)
	if _, err := ConfirmPayment(context.Background(), p.l1Verifier, cdata.L1Payment, producer, candidate.Height); err != nil {
		logrus.Warnf("PoB: candidate payment rejected: %v, skipping", err)
		return nil, false
	}

	return CalcBlockScore(cdata.L1Payment.Amount, cdata.VRFResult.Output), true
}

// resolvePayment returns the L1 payment this node competes with at `height`,
// or nil when it has no business competing for it.
//
// The miner declares payments per height through POST /pay_l1_token, and that
// endpoint has already confirmed each one against L1 — anything sitting in the
// book is known to be backed by an allocation there. No L1 round-trip happens
// here, so block production never blocks on the L1 node.
//
// A height with no declaration yields nil: paying nothing buys nothing, and a
// block carrying a payment L1 cannot confirm would be discarded by every peer
// anyway. `require_declared_payment = false` relaxes this for development
// against a mock L1, falling back to `min_payment` so a lone node keeps
// producing blocks.
func (p *ProofOfBuy) resolvePayment(height common.BlockNum) *L1Payment {
	declared := p.paymentBook.Take(height)
	if declared == nil {
		if p.cfg.RequireDeclaredPayment {
			logrus.Infof("PoB: no payment declared for height=%d, standing down", height)
			return nil
		}
		logrus.Infof("PoB: no payment declared for height=%d, using min payment (dev mode)", height)
		return p.minPayment()
	}

	logrus.Infof("PoB: using declared payment height=%d amount=%s tx_hash=%s",
		height, declared.Amount, declared.TxHash)
	return NewL1Payment(declared.TxHash, declared.Amount, declared.Random, p.myPubkeyHex(), declared.BudgetProof)
}

// minPayment builds the fallback bid used in development mode, when this node
// has no declaration for the current height. A malformed `min_payment` in the
// config degrades to zero rather than a nil amount, which would panic scoring.
func (p *ProofOfBuy) minPayment() *L1Payment {
	amount, ok := new(big.Int).SetString(p.cfg.MinPayment, 10)
	if !ok {
		logrus.Warnf("PoB: invalid min_payment %q in config, using 0", p.cfg.MinPayment)
		amount = new(big.Int)
	}
	return MockL1Payment(amount, p.myPubkeyHex())
}

// collectCandidateBlocks gathers rival blocks for `height` until `deadline`.
// Waiting out the interval is what gives rivals a chance to be heard at all —
// draining only what has already arrived would mostly collect blocks from the
// previous height. Blocks for any other height are dropped.
func (p *ProofOfBuy) collectCandidateBlocks(height common.BlockNum, deadline time.Time) []*types.Block {
	var candidates []*types.Block
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	for {
		select {
		case candidate := <-p.blockCh:
			if candidate.Height != height {
				logrus.Warnf("PoB: ignoring block for height=%d while building height=%d",
					candidate.Height, height)
				continue
			}
			candidates = append(candidates, candidate)
		case <-timer.C:
			return candidates
		}
	}
}

// produceBlock packs transactions, encodes consensus data, signs `block` and
// broadcasts it, returning an error if the block could not be built.
//
// A returned error leaves no state snapshot open, so the caller is free to
// abandon the round and adopt someone else's block instead. Failing to gossip
// a block that was otherwise built correctly is not an error: the block stands
// locally and only loses its chance of being adopted elsewhere.
func (p *ProofOfBuy) produceBlock(block *types.Block, vrfResult *VRFResult, payment *L1Payment, score *big.Int) error {
	txns, err := p.Pool.Pack(p.cfg.PackNum)
	if err != nil {
		return fmt.Errorf("packing txns from pool: %w", err)
	}

	// Sealing goes through the same function verifiers read back, so what a
	// peer checks is by construction what was written here.
	cdata := &ConsensusData{
		VRFResult:  vrfResult,
		L1Payment:  payment,
		BlockScore: score.String(),
	}
	if err := SealBlock(block, txns, cdata, p.myPubkey, p.myPrivKey); err != nil {
		return fmt.Errorf("sealing block: %w", err)
	}

	// Broadcast the block. A failure here costs this node the round elsewhere
	// but does not invalidate the block, so it is logged rather than returned.
	if blockByt, err := block.Encode(); err != nil {
		logrus.Errorf("PoB: encoding block for p2p at height=%d: %v", block.Height, err)
	} else if err = p.P2pNetwork.PubP2P(common.StartBlockTopic, blockByt); err != nil {
		logrus.Errorf("PoB: publishing block to p2p at height=%d: %v", block.Height, err)
	}

	// Open the state snapshot last: every error above returns without one.
	p.State.StartBlock(block)
	return nil
}

// EndBlock runs after StartBlock:
//  1. Decodes and verifies consensus data from block.Extra
//  2. Verifies VRF proof
//  3. Executes all transactions
//  4. Persists the block and finalizes state
//
// Any failure here leaves the block unappended and the chain tip where it was.
// The kernel then rebuilds the same height on the next round, which gives a
// transient fault a chance to clear and keeps a permanent one loud in the log
// rather than killing the node.
func (p *ProofOfBuy) EndBlock(block *types.Block) {
	logrus.Infof("PoB: EndBlock height=%d", block.Height)

	// Decode consensus data from Extra
	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		logrus.Errorf("PoB: decoding consensus data at height=%d: %v", block.Height, err)
		return
	}

	// Verify VRF proof against the block producer's key
	vrfInput := block.PrevHash.Bytes()
	if !VRFVerify(block.MinerPubkey, vrfInput, cdata.VRFResult) {
		logrus.Errorf("PoB: VRF verification failed at height=%d, discarding the block", block.Height)
		return
	}

	// Everything the block writes is staged under its height, so a block L1
	// later rules against can be undone by dropping that height.
	p.pending.SetBlock(block.Height, block.Hash.String())

	// Execute all transactions in the block
	logrus.Infof("PoB: executing block %d", block.Height)
	if err = p.Execute(block); err != nil {
		logrus.Errorf("PoB: executing block at height=%d: %v", block.Height, err)
		return
	}

	// Persist block to chain storage
	if err = p.Chain.AppendBlock(block); err != nil {
		logrus.Errorf("PoB: appending block at height=%d: %v", block.Height, err)
		return
	}

	// Reset txpool with executed transactions. The block is already on the
	// chain at this point, so a stale pool is logged and carried on with.
	if err = p.Pool.Reset(block.Txns); err != nil {
		logrus.Errorf("PoB: resetting txpool after height=%d: %v", block.Height, err)
	}

	// Pay the producer now that the block is on the chain. Every node runs
	// this for every block, so the payout is part of the agreed state.
	p.payBlockReward(block)

	// Nothing is finalized here. A block is only executed and appended at this
	// point; whether it belongs on the canonical chain is L1's call, and that
	// answer arrives later. The finality worker calls Chain.Finalize and
	// State.FinalizeBlock once — and only once — L1 has ruled for this block.
}

// FinalizeBlock enqueues the block for asynchronous L1-driven finalization.
// The actual finalization happens in the finalityWorker goroutine, once the
// block's commitment has been buried deep enough on L1.
//
// A block EndBlock failed to append must not be committed to L1, so the chain
// tip is consulted rather than assumed.
func (p *ProofOfBuy) FinalizeBlock(block *types.Block) {
	tip, err := p.Chain.GetEndCompactBlock()
	if err != nil {
		logrus.Errorf("PoB: reading chain tip before finalizing height=%d: %v", block.Height, err)
		return
	}
	if tip.Hash != block.Hash {
		logrus.Warnf("PoB: height=%d was not appended, skipping L1 finalization", block.Height)
		return
	}

	logrus.Infof("PoB: queuing block for L1 finalization height=%d, hash=%s", block.Height, block.Hash.String())
	p.pendingFinalizations <- &pendingFinalization{block: block}
}

// finalityWorker runs as a background goroutine. It receives blocks from
// pendingFinalizations, posts each block's commitment to L1, and promotes the
// block's staged writes once that commitment is on chain. Blocks are promoted
// strictly in height order.
//
// Finality in PoB comes from fork choice — the heaviest continuous fork by
// cumulative goal — with L1 holding a tamper-proof record of when each
// commitment appeared, which is what exposes a fork bought after the fact.
func (p *ProofOfBuy) finalityWorker() {
	pollInterval := time.Duration(p.cfg.L1PollInterval) * time.Millisecond
	// pending holds blocks whose commitment has been sent but not yet seen on
	// chain.
	var pending []*pendingFinalization

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case pf := <-p.pendingFinalizations:
			if err := p.submitCommitment(pf); err != nil {
				logrus.Errorf("PoB: committing block height=%d to L1: %v", pf.block.Height, err)
				continue
			}
			pending = append(pending, pf)
			logrus.Infof("PoB: committed block to L1 height=%d, l1_tx=%s", pf.block.Height, pf.l1TxHash)

		case <-ticker.C:
			// Two separate jobs, deliberately not one loop. Revealing is about
			// this node's own blocks and follows each commitment to L1.
			// Promoting is about the canonical chain, whoever produced it.
			p.revealAnchored(&pending)
			p.promoteSettled()
		}
	}
}

// revealAnchored publishes the opening for every submitted commitment that
// has reached an L1 block, and drops those entries from `pending`.
//
// The wait is not incidental. An opening published before its commitment is
// packed would show the L1 miner currently building a block exactly which L2
// blocks to drop (proof_of_buy.md §9.6). Entries are handled in height order
// and the run stops at the first one not yet on chain, so a commitment that
// is lagging does not let later ones overtake it.
func (p *ProofOfBuy) revealAnchored(pending *[]*pendingFinalization) {
	if len(*pending) == 0 {
		return
	}
	sort.Slice(*pending, func(i, j int) bool {
		return (*pending)[i].block.Height < (*pending)[j].block.Height
	})

	revealed := 0
	for _, pf := range *pending {
		loc, err := p.l1Submitter.CommitmentOnChain(context.Background(), pf.l1TxHash)
		if err != nil {
			logrus.Errorf("PoB: checking L1 for height=%d: %v", pf.block.Height, err)
			break
		}
		if loc == nil {
			// Not on chain at all — dropped from the mempool, or lost with an
			// L1 reorg. Waiting cannot fix that, so send the same commitment
			// again.
			logrus.Warnf("PoB: commitment for height=%d is not on L1 (l1_tx=%s), resubmitting",
				pf.block.Height, pf.l1TxHash)
			if err := p.resubmitCommitment(pf); err != nil {
				logrus.Errorf("PoB: resubmitting the commitment for height=%d: %v",
					pf.block.Height, err)
			}
			break
		}

		// Where it landed is what lets a verifier find this commitment later
		// without scanning L1, and what dates the anchoring. Failing to note
		// it costs only that, so it is logged rather than treated as fatal.
		if err := p.bids.RecordLocation(pf.block.Hash.String(), loc.BlockHash, loc.TxIdx); err != nil {
			logrus.Errorf("PoB: recording the L1 location of height=%d: %v",
				pf.block.Height, err)
		}
		p.revealOnce(pf, loc)
		revealed++
	}
	*pending = (*pending)[revealed:]
}

// promoteSettled writes down whatever fork choice and the openings have
// settled between them.
//
// This is where a block stops being provisional, and the two halves of that
// decision come from different places. Which branch to follow is a matter of
// cumulative goal (ChooseFork). When following it becomes irreversible is a
// matter of L1's record: a block is settled once its commitment is anchored
// there and its opening is out (FinalizableCount).
//
// It works from the candidate tree rather than this node's own queue, so a
// block adopted from another miner settles exactly as one of this node's own
// would — the queue only ever held blocks this node produced.
func (p *ProofOfBuy) promoteSettled() {
	forks, err := p.Chain.CandidateForks()
	if err != nil {
		logrus.Errorf("PoB: enumerating candidate forks: %v", err)
		return
	}
	best := ChooseFork(forks)
	if best == nil || len(best.Blocks) == 0 {
		return
	}

	settled, staged := settledBlocks(best, p.verifiedOpenings(context.Background(), best.Blocks))
	if len(settled) == 0 {
		return
	}
	through := settled[len(settled)-1]

	// The state goes in first: it is the part that matters and it records how
	// far it got, so a crash before the markers below costs nothing that
	// startup cannot rebuild from that record.
	if err := p.pending.ApplyBlocks(staged); err != nil {
		logrus.Errorf("PoB: promoting staged writes through height=%d: %v", through.Height, err)
		return
	}
	if err := p.Chain.FinalizeFork(&types.Fork{Blocks: settled}); err != nil {
		logrus.Errorf("PoB: finalizing the settled fork through height=%d: %v", through.Height, err)
		return
	}
	p.State.FinalizeBlock(through)
	logrus.Infof("PoB: settled %d block(s) through height=%d", len(settled), through.Height)
}

// verifiedOpenings returns the hashes of the blocks at the front of `blocks`
// that are settled: opened on the L2 network, and backed by L1 — commitment
// anchored where the opening says (V1), allocation table owned by the
// producer (V7's first item), and that allocation written far enough ahead
// (V4).
//
// It stops at the first block that is not, instead of checking the rest.
// Finality is a run from the front, so nothing past a gap can settle anyway,
// and every block examined costs reads against L1.
//
// Nothing is remembered between calls. V1 asks whether the anchoring block is
// still on L1's canonical chain, and a reorg can turn that yes into a no — a
// cached yes would be a stale answer driving a write that cannot be undone.
// The blocks in question are the few above the last finalized one, so the
// cost of asking again is small and the cost of being wrong is not.
func (p *ProofOfBuy) verifiedOpenings(ctx context.Context, blocks []*types.Block) map[string]bool {
	opened := make(map[string]bool, len(blocks))
	for _, block := range blocks {
		if block == nil || block.Header == nil {
			break
		}
		hash := block.Hash.String()

		row, err := p.reveals.Get(hash)
		if err != nil {
			logrus.Errorf("PoB: reading the opening of %s: %v", hash, err)
			break
		}
		if row == nil {
			// Not revealed yet, which is the ordinary state: an opening
			// cannot go out before its commitment is in an L1 block.
			break
		}
		if err := VerifyAgainstL1(ctx, p.l1Reader, p.l1Verifier, block, RevealFromRow(row)); err != nil {
			logrus.Warnf("PoB: holding at %s, not backed by L1: %v", hash, err)
			break
		}
		opened[hash] = true
	}
	return opened
}

// submitCommitment draws a blinding factor, records the opening, and posts the
// commitment for `pf`'s block to L1.
//
// The opening is written to disk *before* the submission goes out. Only the
// commitment reaches L1, so an opening lost to a crash would leave a
// commitment that nobody — this node included — can ever open: the L1 tokens
// spent on it would buy nothing. Writing first costs one row; getting the
// order wrong costs the bid.
func (p *ProofOfBuy) submitCommitment(pf *pendingFinalization) error {
	// The score is recorded alongside the opening for diagnostics; the block
	// hash already commits to it, so it takes no part in the commitment.
	cdata, err := DecodeConsensusData(pf.block.Extra)
	if err != nil {
		return fmt.Errorf("decoding consensus data: %w", err)
	}

	random, err := NewRandomHex()
	if err != nil {
		return err
	}
	commitment, err := CommitBlockHash(pf.block.Hash, random)
	if err != nil {
		return fmt.Errorf("committing to the block hash: %w", err)
	}

	blockHash := pf.block.Hash.String()
	if err := p.bids.Save(&store.BlockBid{
		BlockHash:  blockHash,
		Height:     pf.block.Height,
		Goal:       cdata.BlockScore,
		Random:     random,
		Commitment: commitment,
	}); err != nil {
		return err
	}

	l1TxHash, err := p.l1Submitter.SubmitCommitment(context.Background(), &BlockCommitment{
		L2BlockHeight: pf.block.Height,
		Commitment:    commitment,
	})
	if err != nil {
		return fmt.Errorf("submitting the commitment: %w", err)
	}

	// The opening is already safe; failing to note which transaction carried
	// it only costs the ability to look the submission up later.
	if err := p.bids.RecordSubmission(blockHash, l1TxHash); err != nil {
		logrus.Errorf("PoB: recording the L1 submission of height=%d: %v", pf.block.Height, err)
	}

	pf.l1TxHash = l1TxHash
	pf.submittedAt = time.Now()
	return nil
}

// resubmitCommitment posts the recorded commitment for `pf`'s block again,
// after an earlier submission failed to stay on chain.
//
// It deliberately reuses the stored opening rather than drawing a fresh one: a
// new blinding factor would produce a different commitment, and the opening
// already on disk would then match nothing.
func (p *ProofOfBuy) resubmitCommitment(pf *pendingFinalization) error {
	blockHash := pf.block.Hash.String()
	bid, err := p.bids.Get(blockHash)
	if err != nil {
		return err
	}
	if bid == nil {
		return fmt.Errorf("no opening recorded for block %s", blockHash)
	}

	l1TxHash, err := p.l1Submitter.SubmitCommitment(context.Background(), &BlockCommitment{
		L2BlockHeight: bid.Height,
		Commitment:    bid.Commitment,
	})
	if err != nil {
		return fmt.Errorf("submitting the commitment: %w", err)
	}
	if err := p.bids.RecordSubmission(blockHash, l1TxHash); err != nil {
		logrus.Errorf("PoB: recording the L1 resubmission of height=%d: %v", pf.block.Height, err)
	}

	pf.l1TxHash = l1TxHash
	pf.submittedAt = time.Now()
	return nil
}
