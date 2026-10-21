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

// candidateForksSlow is how long the chain may take to enumerate candidate
// forks before it is worth saying so.
const candidateForksSlow = 250 * time.Millisecond

// ProofOfBuy implements the Proof-of-Buy consensus as a yu tripod.
// Phase 1: single-node mode with VRF + mock L1 payment + score-based block competition.
type ProofOfBuy struct {
	*tripod.Tripod

	cfg        *Config
	myPubkey   keypair.PubKey
	myPrivKey  keypair.PrivKey
	l1Verifier L1PaymentVerifier
	// l1Reader reads back what was written to L1: when a block's header was
	// anchored, and who owns an allocation table. V1, V4 and V7's first item
	// all rest on it.
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

	// l1Submitter posts block headers to L1 and reports whether they landed.
	l1Submitter L1HeaderSubmitter
	// schedule says which L1 window each batch of L2 heights is anchored in.
	schedule AnchorSchedule
	// pending stages each block's writes until its batch is decided.
	pending *store.Pending

	// pendingFinalizations is a buffered channel for blocks whose header is
	// yet to be submitted to L1.
	pendingFinalizations chan *pendingFinalization
}

// NewProofOfBuy constructs a ProofOfBuy tripod with the given config, keypair,
// L1 verifier and reader, VRF private key, L1 header submitter, payment book
// and staging layer.
// `cfg` must not be nil; `pubkey`/`privkey` must be a secp256k1 keypair and
// `vrfPrivKey` must be the same key in ecdsa form (see SecpPrivKeyToECDSA);
// `paymentBook` must be the same instance the HTTP endpoint writes into.
func NewProofOfBuy(cfg *Config, pubkey keypair.PubKey, privkey keypair.PrivKey, l1Verifier L1PaymentVerifier, l1Reader L1Reader, vrfPrivKey *ecdsa.PrivateKey, l1Submitter L1HeaderSubmitter, paymentBook *PaymentBook, pending *store.Pending) *ProofOfBuy {
	schedule, err := NewAnchorSchedule(cfg)
	if err != nil {
		// A startup failure: without a schedule nothing can ever be finalized.
		logrus.Fatalf("PoB: %v", err)
	}
	tri := tripod.NewTripod()
	return &ProofOfBuy{
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
		pending:              pending,
		schedule:             schedule,
		pendingFinalizations: make(chan *pendingFinalization, 100),
	}
}

// InitChain checks the stored genesis, reconciles the stores after a restart,
// then starts the block listener and the finality worker goroutines. The
// kernel has written the genesis block by now: it asks DefineGenesis for one
// before any tripod's InitChain runs.
func (p *ProofOfBuy) InitChain() {
	// A database carrying another chain's genesis cannot be run against:
	// every block links back to genesis by hash.
	p.checkGenesis()

	p.reconcile()

	go p.blockListener()
	go p.finalityWorker()
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
//     written — the crash window between the two. Nothing is done about it
//     here. The finality worker decides batches from L1's record starting
//     after the last marker, so it decides that batch again; promotion finds
//     its staged rows already gone, and the block gets its marker.
//     Recovering it by height instead would mean picking one block out of a
//     height that may hold several, and marking the wrong one would point
//     `LastFinalized` at a branch this node does not follow — every later
//     enumeration would start from there.
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

	// The payment book lives in memory and starts out believing nothing has
	// been produced. Left that way it would take declarations for heights the
	// chain already has, and anything reading it would report the chain at
	// zero, so it is told where the chain resumes from.
	p.paymentBook.Settle(applied)

	logrus.Infof("PoB: reconciled to height=%d", applied)
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
		// Nothing declared *yet*. Park, but keep watching the book: a miner
		// declares whenever it gets round to it, and what a declaration
		// carries is the opening of a commitment that has been sitting on L1
		// since long before this height (V4 sees to that). So a declaration
		// arriving now is this node learning something, not a payment being
		// made late, and there is no reason to sit out a height it can still
		// legitimately win.
		myPayment = p.awaitPaymentOrRivalBlock(block, vrfInput)
		if myPayment == nil {
			p.paymentBook.Settle(block.Height)
			return
		}
		// Rivals get their window measured from here; the old one elapsed
		// while this node had nothing to compete with.
		deadline = time.Now().Add(time.Duration(p.cfg.BlockInterval) * time.Millisecond)
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
		if p.adoptRival(block, candidate, vrfInput) {
			return
		}
	}
}

// awaitPaymentOrRivalBlock parks until either this node has something to bid
// with at this height, or another miner settles the height for it.
//
// It returns the payment when one turns up, leaving the caller to compete,
// and nil when a rival's block was adopted instead.
//
// **Waiting here is the ordinary case, not a fallback.** A block may only be
// produced against an allocation already committed on L1 — and committed 24
// L1 blocks earlier at that (V4) — so a node with nothing declared for a
// height has no business producing one. That is true of every height, and
// unavoidably true of the first: the endpoint a miner's declarations arrive
// through is served by the node itself, so the node necessarily reaches
// height one before anything has been declared for it. It waits rather than
// races.
//
// Both wake-ups are events, not polls. The network delivers rival blocks on
// blockCh, and the payment book signals when declarations are stored; a
// signal only says something arrived, so the book is re-read to see whether
// it was for this height.
func (p *ProofOfBuy) awaitPaymentOrRivalBlock(block *types.Block, vrfInput []byte) *L1Payment {
	logrus.Infof("PoB: nothing declared for height=%d; waiting for a declaration of our own or a rival's block",
		block.Height)

	for {
		// Read before waiting, and again after every wake-up. A declaration
		// stored between the two would otherwise leave this parked with the
		// answer already in the book.
		if declared := p.paymentBook.Take(block.Height); declared != nil {
			logrus.Infof("PoB: a declaration for height=%d arrived; competing after all", block.Height)
			return p.confirmDeclared(block.Height, declared)
		}

		select {
		case candidate, ok := <-p.blockCh:
			if !ok {
				return nil
			}
			if p.adoptRival(block, candidate, vrfInput) {
				return nil
			}
		case <-p.paymentBook.Updated():
		}
	}
}

// adoptRival verifies a candidate for this height and, if it stands, adopts
// it into `block`. It reports whether the height is now settled.
//
// `vrfInput` must be the VRF input for `block`'s height.
func (p *ProofOfBuy) adoptRival(block *types.Block, candidate *types.Block, vrfInput []byte) bool {
	if candidate.Height != block.Height {
		logrus.Warnf("PoB: ignoring block for height=%d while waiting on height=%d",
			candidate.Height, block.Height)
		return false
	}
	score, ok := p.verifyCandidate(candidate, vrfInput)
	if !ok {
		return false
	}

	logrus.Infof("PoB: adopting block for height=%d from another miner, score=%s",
		block.Height, score)
	*block = *candidate
	// produceBlock never ran, so open the state snapshot EndBlock's
	// execution needs.
	p.State.StartBlock(block)
	return true
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
	// checked below are public once broadcast, so a block that skips this
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
// anyway. The caller then waits for one rather than producing a block it has
// not bought — see awaitPaymentOrRivalBlock.
//
// `require_declared_payment = false` relaxes this for development against a
// mock L1, where no declaration can ever be confirmed: it falls back to
// `min_payment` so a lone node keeps producing. That fallback is the only
// path on which this node produces a block it has not paid L1 for, which is
// why it is off by default.
func (p *ProofOfBuy) resolvePayment(height common.BlockNum) *L1Payment {
	declared := p.paymentBook.Take(height)
	if declared == nil {
		if p.cfg.RequireDeclaredPayment {
			// Said by the caller, which is the one that knows what it does
			// next — and it waits rather than stands down.
			return nil
		}
		logrus.Infof("PoB: no payment declared for height=%d, using min payment (dev mode)", height)
		return p.minPayment()
	}

	return p.confirmDeclared(height, declared)
}

// confirmDeclared turns a declaration taken out of the book into the payment
// this node bids with.
//
// Split out so that the wait in awaitPaymentOrRivalBlock, which takes from
// the book itself, builds the payment exactly the way the ordinary path does.
func (p *ProofOfBuy) confirmDeclared(height common.BlockNum, declared *L1PaymentInput) *L1Payment {
	if declared == nil {
		return nil
	}
	logrus.Infof("PoB: using declared payment height=%d amount=%s tx_hash=%s",
		height, declared.Amount, declared.TxHash)
	return NewL1Payment(declared.TxHash, declared.Amount, declared.Random, p.myPubkeyHex())
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
// The finalityWorker goroutine submits the block's header to L1; the block is
// finalized once its batch's L1 window has closed and decideBatch picks it.
//
// A block EndBlock failed to append must not be submitted to L1, so the chain
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

// finalityWorker runs as a background goroutine. It submits the header of
// every block taken from pendingFinalizations to L1 once its batch's window
// is open, follows each submission until it lands, and decides every batch
// whose window has closed.
func (p *ProofOfBuy) finalityWorker() {
	pollInterval := time.Duration(p.cfg.L1PollInterval) * time.Millisecond
	// queued holds blocks whose window has not opened yet; pending holds
	// blocks whose header has been sent but not yet seen on chain.
	var queued, pending []*pendingFinalization

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		// Submissions go out before anything else this loop does. A header
		// has to land inside its batch's window to count, and the periodic
		// work below talks to L1 at length, so a pass that runs long would
		// otherwise keep the queue waiting behind it.
		p.drainFinalizations(&queued)
		p.submitOpen(&queued, &pending)

		select {
		case pf := <-p.pendingFinalizations:
			queued = append(queued, pf)

		case <-ticker.C:
			// Two separate jobs. Following submissions is about the headers
			// this node sent. Deciding is about the canonical chain, whoever
			// produced or submitted it.
			p.followSubmissions(&pending)
			p.decideBatches()
		}
	}
}

// drainFinalizations moves every block already waiting on the channel into
// `queued`, without blocking when none is.
func (p *ProofOfBuy) drainFinalizations(queued *[]*pendingFinalization) {
	for {
		select {
		case pf := <-p.pendingFinalizations:
			*queued = append(*queued, pf)
		default:
			return
		}
	}
}

// submitOpen submits the header of every queued block whose window is open,
// moving it to `pending`, and drops those whose window has already closed.
//
// A header sent before its window opens would land before n+i, where no node
// looks, and the batch could then never be decided — so an L2 running ahead
// of L1 waits here rather than submitting early. A header whose window has
// closed would land after it, equally unseen, and is not worth the L1 fee.
// A failed submission stays queued and is tried again next pass.
func (p *ProofOfBuy) submitOpen(queued, pending *[]*pendingFinalization) {
	if len(*queued) == 0 {
		return
	}
	tip, err := p.l1Reader.Tip(context.Background())
	if err != nil {
		logrus.Warnf("PoB: reading L1's tip: %v", err)
		return
	}

	kept := (*queued)[:0]
	for _, pf := range *queued {
		batch := p.schedule.BatchOf(pf.block.Height)
		switch {
		case p.schedule.WindowClosed(batch, tip):
			logrus.Warnf("PoB: window for height=%d has closed, not submitting its header", pf.block.Height)
		case !p.schedule.WindowOpen(batch, tip):
			kept = append(kept, pf)
		default:
			if err := p.submitHeader(pf); err != nil {
				logrus.Errorf("PoB: submitting header of height=%d to L1: %v", pf.block.Height, err)
				kept = append(kept, pf)
				continue
			}
			logrus.Infof("PoB: submitted header to L1 height=%d, l1_tx=%s", pf.block.Height, pf.l1TxHash)
			*pending = append(*pending, pf)
		}
	}
	*queued = kept
}

// windowClosed reports whether the L1 window for `height`'s batch has
// closed. An L1 that cannot be reached is treated as open, so a transient
// error does not cost a submission.
func (p *ProofOfBuy) windowClosed(height common.BlockNum) bool {
	tip, err := p.l1Reader.Tip(context.Background())
	if err != nil {
		logrus.Warnf("PoB: reading L1's tip: %v", err)
		return false
	}
	return p.schedule.WindowClosed(p.schedule.BatchOf(height), tip)
}

// followSubmissions checks every submitted header against L1, drops those
// that landed from `pending`, and resubmits those L1 has lost while their
// window is still open.
//
// Entries are handled in height order and the run stops at the first one
// still waiting, so the per-tick cost stays bounded by what is in flight.
func (p *ProofOfBuy) followSubmissions(pending *[]*pendingFinalization) {
	if len(*pending) == 0 {
		return
	}
	sort.Slice(*pending, func(i, j int) bool {
		return (*pending)[i].block.Height < (*pending)[j].block.Height
	})

	done := 0
	for _, pf := range *pending {
		onChain, err := p.l1Submitter.HeaderOnChain(context.Background(), pf.l1TxHash)
		if errors.Is(err, ErrSubmissionPending) {
			// Sent and accepted, just not mined yet. Nothing to do but wait.
			break
		}
		if err != nil {
			logrus.Errorf("PoB: checking L1 for height=%d: %v", pf.block.Height, err)
			break
		}
		if !onChain {
			// Not on chain at all — dropped from the mempool, or lost with an
			// L1 reorg. Send it again while it can still land in its window.
			if p.windowClosed(pf.block.Height) {
				logrus.Warnf("PoB: header of height=%d was lost and its window has closed", pf.block.Height)
				done++
				continue
			}
			logrus.Warnf("PoB: header of height=%d is not on L1 (l1_tx=%s), resubmitting",
				pf.block.Height, pf.l1TxHash)
			if err := p.submitHeader(pf); err != nil {
				logrus.Errorf("PoB: resubmitting the header of height=%d: %v", pf.block.Height, err)
			}
			break
		}
		done++
	}
	*pending = (*pending)[done:]
}

// decideBatches decides, in order, every batch whose L1 window has closed
// and been buried deep enough, and finalizes the winning blocks.
//
// The decision is made from the headers on L1, not from this node's block
// tree. Every node reads the same window, so every honest node picks the same
// run — including a node that was following another fork locally. The blocks
// themselves are only needed to apply their state; when the winner has not
// reached this node yet, deciding waits for it.
func (p *ProofOfBuy) decideBatches() {
	ctx := context.Background()
	tip, err := p.l1Reader.Tip(ctx)
	if err != nil {
		logrus.Errorf("PoB: reading L1's tip: %v", err)
		return
	}
	for {
		decided, err := p.decideBatch(ctx, tip)
		if err != nil {
			logrus.Errorf("PoB: %v", err)
			return
		}
		if !decided {
			return
		}
	}
}

// decideBatch decides the batch right after the last finalized block, if its
// window is decidable at L1 height `l1Tip`. It reports whether a batch was
// finalized.
func (p *ProofOfBuy) decideBatch(ctx context.Context, l1Tip uint64) (bool, error) {
	last, err := p.Chain.LastFinalized()
	if err != nil {
		return false, fmt.Errorf("reading the last finalized block: %w", err)
	}
	size := p.schedule.BatchSize
	// Batches are finalized whole, so the last finalized height is always a
	// batch boundary. Anything else means anchor_batch_size changed under an
	// existing chain.
	if uint64(last.Height)%size != 0 {
		return false, fmt.Errorf("last finalized height %d is not a multiple of anchor_batch_size %d",
			last.Height, size)
	}
	batch := uint64(last.Height) / size
	if !p.schedule.Decidable(batch, l1Tip) {
		return false, nil
	}

	from, to := p.schedule.WindowOf(batch)
	anchored, err := p.l1Reader.AnchoredIn(ctx, from, to)
	if err != nil {
		return false, fmt.Errorf("reading batch %d's window [%d, %d]: %w", batch, from, to, err)
	}
	first := p.schedule.FirstHeight(batch)
	candidates := p.scoreAnchored(ctx, anchored, first, first+common.BlockNum(size)-1)

	winner := ChooseBatch(last.Hash, first, size, candidates)
	if winner == nil {
		return false, fmt.Errorf("batch %d: no complete run of %d headers off %s in L1 [%d, %d]",
			batch, size, last.Hash, from, to)
	}

	blocks := make([]*types.Block, len(winner))
	staged := make([]store.Block, len(winner))
	for i, header := range winner {
		block, err := p.Chain.GetBlock(header.Hash)
		if err != nil || block == nil {
			logrus.Warnf("PoB: batch %d chose block %s at height=%d, waiting for it to arrive",
				batch, header.Hash, header.Height)
			return false, nil
		}
		blocks[i] = block
		staged[i] = store.Block{Height: block.Height, Hash: block.Hash.String()}
	}
	through := blocks[len(blocks)-1]

	// The state goes in first: it is the part that matters and it records how
	// far it got, so a crash before the markers below costs nothing that
	// startup cannot rebuild from that record.
	if err := p.pending.ApplyBlocks(staged); err != nil {
		return false, fmt.Errorf("promoting staged writes through height=%d: %w", through.Height, err)
	}
	if err := p.Chain.FinalizeFork(&types.Fork{Blocks: blocks}); err != nil {
		return false, fmt.Errorf("finalizing batch %d through height=%d: %w", batch, through.Height, err)
	}
	p.State.FinalizeBlock(through)
	logrus.Infof("PoB: decided batch %d, settled through height=%d", batch, through.Height)
	return true, nil
}

// scoreAnchored verifies the headers in `anchored` whose heights fall in
// [lo, hi] and returns the ones that pass, with their goals.
//
// A header submitted more than once is judged at its earliest landing in the
// window: that is when it was demonstrably there, and V4 measures the payment
// against it. A header that fails is dropped with a warning — anyone may
// write a submit cell, so failures are expected and decide nothing.
func (p *ProofOfBuy) scoreAnchored(ctx context.Context, anchored []*AnchoredHeader, lo, hi common.BlockNum) []*ScoredHeader {
	earliest := make(map[common.Hash]*AnchoredHeader)
	for _, a := range anchored {
		if a == nil || a.Header == nil || a.Header.Height < lo || a.Header.Height > hi {
			continue
		}
		if prev, ok := earliest[a.Header.Hash]; !ok || a.L1Height < prev.L1Height {
			earliest[a.Header.Hash] = a
		}
	}

	scored := make([]*ScoredHeader, 0, len(earliest))
	for _, a := range earliest {
		goal, err := VerifyAnchoredHeader(ctx, p.l1Reader, p.l1Verifier, a)
		if err != nil {
			logrus.Warnf("PoB: discarding anchored header at height=%d: %v", a.Header.Height, err)
			continue
		}
		scored = append(scored, &ScoredHeader{Header: a.Header, Goal: goal})
	}
	return scored
}

// submitHeader posts `pf`'s block header to L1 and records the transaction
// carrying it. Used both for the first submission and for resubmitting a
// header L1 lost: the header is fixed by the block, so there is nothing to
// keep between the two.
func (p *ProofOfBuy) submitHeader(pf *pendingFinalization) error {
	l1TxHash, err := p.l1Submitter.SubmitHeader(context.Background(), pf.block.Header)
	if err != nil {
		return fmt.Errorf("submitting the header: %w", err)
	}
	pf.l1TxHash = l1TxHash
	pf.submittedAt = time.Now()
	return nil
}
