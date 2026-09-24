package consensus

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"

	"github.com/invisibook-lab/invisibook/store"
)

// revealResubscribeDelay is how long the listener waits before retrying after
// a failed subscribe, so a persistent failure cannot become a busy loop.
const revealResubscribeDelay = time.Second

// RevealTopic carries block commitment openings across the L2 network.
//
// A topic of our own rather than one of yu's: openings travel on a different
// schedule from blocks. A block is broadcast the moment it is produced, while
// its opening cannot go out until the commitment has made it into an L1 block
// — revealing earlier would hand the L1 miner currently packing transactions
// exactly what it needs to drop rivals selectively (proof_of_buy.md §9.6).
const RevealTopic = "pob-reveal"

// BlockReveal is the message published on RevealTopic: the opening of one
// block's commitment, plus where on L1 that commitment landed.
//
// The block itself is not included. It travelled on the block topic already,
// and anyone who does not have it cannot use the opening anyway — the opening
// only proves which on-L1 commitment that block belongs to.
type BlockReveal struct {
	// L2BlockHeight is the height of the block being revealed.
	L2BlockHeight common.BlockNum `json:"l2_block_height"`
	// L2BlockHash identifies the block.
	L2BlockHash string `json:"l2_block_hash"`
	// Random is the 64-char hex blinding factor opening the commitment.
	Random string `json:"random"`
	// L1BlockHash is the L1 block the commitment landed in.
	L1BlockHash string `json:"l1_block_hash"`
	// TxIdx is the transaction's index inside that L1 block.
	TxIdx uint32 `json:"tx_idx"`
	// MinerPubkey is the hex-encoded compressed key of the block's producer.
	MinerPubkey string `json:"miner_pubkey"`
}

// Validate checks the shape of a reveal before it is stored or acted on.
//
// Shape only: whether the opening actually opens the commitment on L1 is V1's
// job, and that needs an L1 client this check does not have. Rejecting
// malformed messages here keeps obvious junk out of the store and out of the
// fork-choice path.
func (r *BlockReveal) Validate() error {
	if r == nil {
		return fmt.Errorf("reveal is missing")
	}
	if r.L2BlockHash == "" {
		return fmt.Errorf("reveal names no block")
	}
	if len(r.Random) != RandomHexLen {
		return fmt.Errorf("random must be %d hex chars, got %d", RandomHexLen, len(r.Random))
	}
	if r.L1BlockHash == "" {
		return fmt.Errorf("reveal for block %s names no L1 block", r.L2BlockHash)
	}
	if r.MinerPubkey == "" {
		return fmt.Errorf("reveal for block %s names no producer", r.L2BlockHash)
	}
	return nil
}

// ToRow converts a received reveal into the row the store keeps.
func (r *BlockReveal) ToRow() *store.Reveal {
	return &store.Reveal{
		BlockHash:   r.L2BlockHash,
		Height:      r.L2BlockHeight,
		Random:      r.Random,
		L1BlockHash: r.L1BlockHash,
		TxIdx:       r.TxIdx,
		MinerPubkey: r.MinerPubkey,
	}
}

// RevealFromRow rebuilds a broadcastable reveal from a stored row, which is
// how a node answers a peer catching up.
func RevealFromRow(row *store.Reveal) *BlockReveal {
	return &BlockReveal{
		L2BlockHeight: row.Height,
		L2BlockHash:   row.BlockHash,
		Random:        row.Random,
		L1BlockHash:   row.L1BlockHash,
		TxIdx:         row.TxIdx,
		MinerPubkey:   row.MinerPubkey,
	}
}

// EncodeReveal serialises a reveal for the wire.
func EncodeReveal(reveal *BlockReveal) ([]byte, error) {
	raw, err := json.Marshal(reveal)
	if err != nil {
		return nil, fmt.Errorf("encoding reveal: %w", err)
	}
	return raw, nil
}

// DecodeReveal parses a reveal off the wire and checks its shape.
func DecodeReveal(raw []byte) (*BlockReveal, error) {
	var reveal BlockReveal
	if err := json.Unmarshal(raw, &reveal); err != nil {
		return nil, fmt.Errorf("decoding reveal: %w", err)
	}
	if err := reveal.Validate(); err != nil {
		return nil, err
	}
	return &reveal, nil
}

// broadcastReveal publishes one opening to the network and keeps a copy.
//
// Called only once the commitment is known to be on L1 — before that there is
// nothing to reveal, and revealing early is precisely what §9.6 forbids.
func (p *ProofOfBuy) broadcastReveal(reveal *BlockReveal) {
	if err := p.reveals.Put(reveal.ToRow()); err != nil {
		// Storing our own reveal matters more than sending it: a peer can ask
		// for it later, but only if it is here.
		logrus.Errorf("PoB: storing our reveal for height=%d: %v", reveal.L2BlockHeight, err)
	}

	raw, err := EncodeReveal(reveal)
	if err != nil {
		logrus.Errorf("PoB: encoding reveal for height=%d: %v", reveal.L2BlockHeight, err)
		return
	}
	if err := p.P2pNetwork.PubP2P(RevealTopic, raw); err != nil {
		logrus.Errorf("PoB: publishing reveal for height=%d: %v", reveal.L2BlockHeight, err)
		return
	}
	logrus.Infof("PoB: revealed height=%d, commitment in l1_block=%s",
		reveal.L2BlockHeight, reveal.L1BlockHash)
}

// revealOnce publishes the opening for `pf`'s block, at most once.
//
// The finality worker polls, so this is reached on every tick once the
// commitment has landed; the store is what remembers that the job is done.
func (p *ProofOfBuy) revealOnce(pf *pendingFinalization, loc *L1Location) {
	blockHash := pf.block.Hash.String()

	if existing, err := p.reveals.Get(blockHash); err != nil {
		logrus.Errorf("PoB: checking whether height=%d was revealed: %v", pf.block.Height, err)
		return
	} else if existing != nil {
		return
	}

	bid, err := p.bids.Get(blockHash)
	if err != nil {
		logrus.Errorf("PoB: reading the opening of height=%d: %v", pf.block.Height, err)
		return
	}
	if bid == nil {
		logrus.Errorf("PoB: no opening recorded for height=%d, cannot reveal", pf.block.Height)
		return
	}

	p.broadcastReveal(newBlockReveal(pf.block, bid.Random, loc))
}

// newBlockReveal builds the opening message for `block`, whose commitment
// landed at `loc` and was blinded with `random`.
//
// MinerPubkey names the block's producer, never this node. Submitting a
// commitment takes no identity at all — anyone may anchor anyone's block, and
// this node routinely does exactly that for blocks it adopted from other
// miners (proof_of_buy.md §8.1). Naming ourselves would relabel another
// miner's block as ours, and every check that reads the producer — the VRF
// proof, the payment binding — would then be aimed at the wrong key.
//
// It is a plain function so that this mapping can be tested on its own,
// without a store, a network or a running node.
func newBlockReveal(block *types.Block, random string, loc *L1Location) *BlockReveal {
	return &BlockReveal{
		L2BlockHeight: block.Height,
		L2BlockHash:   block.Hash.String(),
		Random:        random,
		L1BlockHash:   loc.BlockHash,
		TxIdx:         loc.TxIdx,
		MinerPubkey:   hex.EncodeToString(block.MinerPubkey),
	}
}

// revealListener subscribes to the reveal topic and stores what arrives.
//
// Openings are accepted from anyone: a reveal is only useful alongside the
// block it opens, and a bogus one is thrown out when it fails to open the
// commitment on L1. Storing first and judging later keeps this loop from
// needing an L1 round-trip per message.
func (p *ProofOfBuy) revealListener() {
	for {
		raw, err := p.P2pNetwork.SubP2P(RevealTopic)
		if err != nil {
			// Backing off matters here: a topic that failed to register makes
			// this return immediately every time, and a bare `continue` would
			// spin the CPU while filling the log.
			logrus.Warnf("PoB: subscribing to reveals failed: %v", err)
			time.Sleep(revealResubscribeDelay)
			continue
		}
		reveal, err := DecodeReveal(raw)
		if err != nil {
			logrus.Warnf("PoB: discarding a malformed reveal: %v", err)
			continue
		}
		if err := p.reveals.Put(reveal.ToRow()); err != nil {
			logrus.Errorf("PoB: storing a reveal for height=%d: %v", reveal.L2BlockHeight, err)
		}
	}
}
