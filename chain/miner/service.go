package miner

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yu-org/yu/common"

	"github.com/invisibook-lab/invisibook/budgetproof"
	"github.com/invisibook-lab/invisibook/ckb"
	"github.com/invisibook-lab/invisibook/consensus"
)

const (
	// defaultL1BlockInterval is CKB's mainnet block time, assumed until L1 has
	// been watched long enough to measure its own.
	defaultL1BlockInterval = 10 * time.Second
	// minL1Sample is how many L1 blocks must pass under observation before
	// the measured interval replaces the default.
	minL1Sample = 5
	// leadSlackBlocks pads the lead for the blocks the prepayment itself takes
	// to be committed, and for the L2 block to be anchored after it is made.
	leadSlackBlocks = 6
	// sendTimeout bounds building and broadcasting the prepayment.
	sendTimeout = 2 * time.Minute
	// commitTimeout bounds the wait for the prepayment to be committed.
	commitTimeout = 10 * time.Minute
	// declareTimeout bounds confirming a batch of declarations against L1.
	declareTimeout = time.Minute
	// balanceTimeout bounds the balance lookup a status request makes.
	balanceTimeout = 5 * time.Second
	// defaultMaturePoll is how often a prepayment waiting out the payment
	// lead asks L1 for its tip.
	defaultMaturePoll = time.Second
	// maturePollFailures is how many tip lookups in a row may fail before an
	// auto-declaration gives up and leaves the miner to declare by hand.
	maturePollFailures = 60
	// minStallWindow is the least time the chain must sit at one height
	// before it is taken to be stalled rather than between blocks.
	minStallWindow = 10 * time.Second
)

// ErrNoL1 is returned when an operation needs a CKB wallet and the node runs
// against the mock L1.
var ErrNoL1 = errors.New("this node has no [ckb] section, so it has no L1 wallet to prepay from")

// Wallet is the slice of the CKB client the console spends through.
type Wallet interface {
	// CreateBudget pays `prepaid` shannon and writes the allocation table.
	// `proof` shows the table balances and goes into the witness.
	CreateBudget(ctx context.Context, prepaid uint64, allocations []ckb.BudgetEntry, proof []byte) (string, error)
	// AwaitCommitted blocks until the transaction is in an L1 block and
	// returns that block's number.
	AwaitCommitted(ctx context.Context, txHash string) (uint64, error)
	// Balance is the spendable capacity in shannon.
	Balance(ctx context.Context) (uint64, error)
	// Address is the miner's CKB address.
	Address() (string, error)
	// TipNumber is the number of L1's current tip.
	TipNumber(ctx context.Context) (uint64, error)
}

// Declarer puts declarations into the node's payment book.
type Declarer interface {
	Declare(ctx context.Context, payments []consensus.PaymentDeclaration) consensus.PayL1TokenResponse
}

// Book is the part of the payment book the console reads.
type Book interface {
	Consumed() common.BlockNum
	Pending() int
}

// Info is what the console shows about this node that does not change.
type Info struct {
	// MinerPubkey is the hex-encoded compressed miner key.
	MinerPubkey string
	// Network names the L1, e.g. "devnet".
	Network string
	// BlockIntervalMs is the L2 block time.
	BlockIntervalMs int
}

// Service runs the miner's operations. `Wallet` may be nil when the node has
// no CKB section; everything that spends then reports ErrNoL1.
type Service struct {
	wallet   Wallet
	declarer Declarer
	book     Book
	store    *Store
	info     Info
	// rnd is where blinding factors and random shares come from.
	rnd io.Reader
	// prove makes the balance proof a budget cell needs (R3.2).
	prove Prover
	// maturePoll is how often a maturing prepayment checks L1's tip.
	maturePoll time.Duration
	// sendMu serialises prepayments, so two of them never pick the same
	// cells to spend.
	sendMu sync.Mutex
	// background tracks the goroutines following prepayments to L1.
	background sync.WaitGroup

	// heightMu guards the record of when the chain last moved, which is how
	// the console tells a live chain from one waiting on this miner.
	heightMu     sync.Mutex
	lastHeight   common.BlockNum
	lastMovedAt  time.Time
	seenMovement bool

	// l1Mu guards the first L1 tip seen and when, from which L1's actual
	// block time is measured: a devnet mines far faster than mainnet.
	l1Mu        sync.Mutex
	firstTip    uint64
	firstTipAt  time.Time
	l1BlockTime time.Duration
}

// NewService builds a Service. `wallet` may be nil; the rest must not be.
func NewService(wallet Wallet, declarer Declarer, book Book, store *Store, info Info) *Service {
	return &Service{
		wallet: wallet, declarer: declarer, book: book, store: store, info: info,
		rnd: rand.Reader, prove: budgetproof.Prove, maturePoll: defaultMaturePoll,
	}
}

// NodeStatus is a snapshot of the node's mining state.
type NodeStatus struct {
	MinerPubkey string `json:"miner_pubkey"`
	Network     string `json:"network"`
	L1Enabled   bool   `json:"l1_enabled"`
	// Address is the miner's CKB address; empty without a wallet.
	Address string `json:"address,omitempty"`
	// BalanceShannon is the spendable balance; nil when unknown.
	BalanceShannon *string `json:"balance_shannon,omitempty"`
	BalanceCKB     *string `json:"balance_ckb,omitempty"`
	// L1Error says why the balance could not be read.
	L1Error string `json:"l1_error,omitempty"`
	// L1Tip is L1's current block number; zero when unknown.
	L1Tip uint64 `json:"l1_tip,omitempty"`
	// ConsumedHeight is the highest L2 height already settled; declarations
	// must be above it.
	ConsumedHeight uint64 `json:"consumed_height"`
	// ChainAdvancing reports whether the L2 has moved recently. A chain that
	// is not moving is waiting on a declaration, possibly this miner's.
	ChainAdvancing bool `json:"chain_advancing"`
	// SuggestedFrom is the earliest height a prepayment made now can be
	// expected to be usable at.
	SuggestedFrom       uint64 `json:"suggested_from"`
	PendingDeclarations int    `json:"pending_declarations"`
	PaymentLeadBlocks   int    `json:"payment_lead_blocks"`
	BlockIntervalMs     int    `json:"block_interval_ms"`
}

// Status reports the node's mining state. A wallet that cannot be reached
// degrades to an L1Error rather than failing the whole snapshot.
func (s *Service) Status(ctx context.Context) NodeStatus {
	consumed, advancing := s.observeHeight()
	st := NodeStatus{
		MinerPubkey:         s.info.MinerPubkey,
		Network:             s.info.Network,
		L1Enabled:           s.wallet != nil,
		ConsumedHeight:      uint64(consumed),
		ChainAdvancing:      advancing,
		SuggestedFrom:       s.suggestedFrom(consumed, advancing),
		PendingDeclarations: s.book.Pending(),
		PaymentLeadBlocks:   consensus.PaymentLeadBlocks,
		BlockIntervalMs:     s.info.BlockIntervalMs,
	}
	if s.wallet == nil {
		return st
	}

	addr, err := s.wallet.Address()
	if err != nil {
		st.L1Error = err.Error()
		return st
	}
	st.Address = addr

	ctx, cancel := context.WithTimeout(ctx, balanceTimeout)
	defer cancel()
	tip, err := s.wallet.TipNumber(ctx)
	if err != nil {
		st.L1Error = err.Error()
		return st
	}
	st.L1Tip = tip
	s.observeTip(tip)
	st.SuggestedFrom = s.suggestedFrom(consumed, advancing)
	balance, err := s.wallet.Balance(ctx)
	if err != nil {
		st.L1Error = err.Error()
		return st
	}
	shannon := new(big.Int).SetUint64(balance)
	str, ckbStr := shannon.String(), FormatCKB(shannon)
	st.BalanceShannon, st.BalanceCKB = &str, &ckbStr
	return st
}

// observeHeight reads the settled height and reports whether the chain has
// moved within the last few block intervals.
//
// A chain not yet seen to move counts as stalled. The two mistakes are not
// equally bad: suggesting too early a height to a live chain wastes the first
// few allocations, which pass before they mature; suggesting a height far
// ahead of a chain that is waiting on this miner leaves every height in
// between with no one to produce it, and the chain never gets there.
func (s *Service) observeHeight() (common.BlockNum, bool) {
	consumed := s.book.Consumed()
	now := time.Now()

	s.heightMu.Lock()
	defer s.heightMu.Unlock()
	if consumed != s.lastHeight {
		if !s.lastMovedAt.IsZero() {
			s.seenMovement = true
		}
		s.lastHeight, s.lastMovedAt = consumed, now
	}
	if s.lastMovedAt.IsZero() {
		s.lastMovedAt = now
	}

	window := 3 * time.Duration(s.info.BlockIntervalMs) * time.Millisecond
	if window < minStallWindow {
		window = minStallWindow
	}
	return consumed, s.seenMovement && now.Sub(s.lastMovedAt) < window
}

// suggestedFrom is the first height worth allocating to.
//
// It continues straight on from this miner's last allocation whenever that
// is still ahead, because for a miner the chain is waiting on, a gap between
// two prepayments is a height nobody produces: the chain stops there for
// good. Otherwise it is the next height when the chain is waiting, or far
// enough ahead to outlast the payment lead when it is moving without us.
func (s *Service) suggestedFrom(consumed common.BlockNum, advancing bool) uint64 {
	earliest := uint64(consumed) + 1
	if advancing {
		earliest += s.leadHeights()
	}
	if next := uint64(s.store.LastHeight()) + 1; next > earliest {
		return next
	}
	return earliest
}

// observeTip records an L1 tip reading, measuring L1's block time once enough
// blocks have gone by.
func (s *Service) observeTip(tip uint64) {
	now := time.Now()
	s.l1Mu.Lock()
	defer s.l1Mu.Unlock()
	if s.firstTipAt.IsZero() || tip < s.firstTip {
		s.firstTip, s.firstTipAt = tip, now
		return
	}
	if blocks := tip - s.firstTip; blocks >= minL1Sample {
		s.l1BlockTime = now.Sub(s.firstTipAt) / time.Duration(blocks)
	}
}

// leadHeights is how many L2 heights a prepayment has to sit out before a
// block can spend it: the payment lead plus slack, converted from L1 time to
// L2 blocks at L1's measured pace, or mainnet's until it is measured.
func (s *Service) leadHeights() uint64 {
	if s.info.BlockIntervalMs <= 0 {
		return 0
	}
	s.l1Mu.Lock()
	l1Block := s.l1BlockTime
	s.l1Mu.Unlock()
	if l1Block <= 0 {
		l1Block = defaultL1BlockInterval
	}
	lead := time.Duration(consensus.PaymentLeadBlocks+leadSlackBlocks) * l1Block
	interval := time.Duration(s.info.BlockIntervalMs) * time.Millisecond
	return uint64((lead + interval - 1) / interval)
}

// Plan divides a prepayment without sending anything, so the miner can look
// at the table before paying for it.
func (s *Service) Plan(req PlanRequest) ([]Allocation, error) {
	plan, err := BuildPlan(req, s.rnd)
	if err != nil {
		return nil, err
	}
	return plan, s.checkHeights(plan)
}

// checkHeights rejects a plan that reaches into the past or reuses a height
// an earlier prepayment already covers. Both would leave the miner having
// paid for allocations that can never be declared.
func (s *Service) checkHeights(plan []Allocation) error {
	consumed := s.book.Consumed()
	for _, a := range plan {
		if common.BlockNum(a.Height) <= consumed {
			return fmt.Errorf("height %d has already been produced (the chain is at %d)", a.Height, consumed)
		}
		if s.store.HeightTaken(a.Height) {
			return fmt.Errorf("height %d is already covered by an earlier prepayment", a.Height)
		}
	}
	return nil
}

// Prepay pays for `plan` on L1. The openings are saved before anything is
// broadcast; the L1 transaction is then sent and awaited in the background,
// and the returned prepayment is the state at the moment it was accepted.
// When `autoDeclare` is set the openings are declared as soon as the budget
// cell is committed.
func (s *Service) Prepay(plan []Allocation, autoDeclare bool) (Prepayment, error) {
	if s.wallet == nil {
		return Prepayment{}, ErrNoL1
	}
	if err := s.checkHeights(plan); err != nil {
		return Prepayment{}, err
	}

	total := PlanTotal(plan)
	if !total.IsUint64() {
		return Prepayment{}, fmt.Errorf("a prepayment of %s shannon does not fit in a cell's capacity", total)
	}

	bids, entries, proof, err := Seal(plan, s.rnd, s.prove)
	if err != nil {
		return Prepayment{}, err
	}

	id, err := BlindingFactor(s.rnd)
	if err != nil {
		return Prepayment{}, err
	}
	p := &Prepayment{
		ID:          id[:16],
		CreatedAt:   time.Now().UTC(),
		Status:      StatusBroadcasting,
		Total:       total.String(),
		AutoDeclare: autoDeclare,
		Bids:        bids,
	}
	// Saved before the transaction goes out: a crash in between would
	// otherwise leave commitments on L1 that nobody can ever open.
	if err := s.store.Add(p); err != nil {
		return Prepayment{}, err
	}

	s.background.Add(1)
	go func() {
		defer s.background.Done()
		s.send(p.ID, total.Uint64(), entries, proof)
	}()
	out, _ := s.store.Get(p.ID)
	return out, nil
}

// send broadcasts prepayment `id` and follows it to a commitment, recording
// each step. It runs in the background.
func (s *Service) send(id string, total uint64, entries []ckb.BudgetEntry, proof []byte) {
	s.sendMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	txHash, err := s.wallet.CreateBudget(ctx, total, entries, proof)
	cancel()
	s.sendMu.Unlock()

	if err != nil {
		// Nothing left the wallet, so the heights are free again.
		s.fail(id, StatusFailed, err)
		return
	}
	s.update(id, func(p *Prepayment) {
		p.TxHash = txHash
		p.Status = StatusConfirming
	})
	s.await(id, txHash)
}

// await waits for the prepayment's transaction to be committed and, if the
// miner asked for it, declares the openings.
func (s *Service) await(id, txHash string) {
	ctx, cancel := context.WithTimeout(context.Background(), commitTimeout)
	defer cancel()

	block, err := s.wallet.AwaitCommitted(ctx, txHash)
	if err != nil {
		// The transaction went out, so the money may be gone: keep the
		// openings and the hash.
		s.fail(id, StatusUnconfirmed, err)
		return
	}
	p, ok := s.update(id, func(p *Prepayment) {
		p.L1Block = block
		p.Status = StatusConfirmed
		p.Error = ""
	})
	if ok && p.AutoDeclare {
		s.declareWhenMature(id, block)
	}
}

// MaturesAt is the first L1 block at whose tip a prepayment committed in
// `l1Block` may be declared. A block spending it is anchored after that tip,
// so it clears V4's lead; declared any earlier, the node would produce a block
// at once whose anchor can never clear it, and that block would never settle.
func MaturesAt(l1Block uint64) uint64 {
	return l1Block + consensus.PaymentLeadBlocks
}

// declareWhenMature waits for prepayment `id`, committed in `l1Block`, to clear
// the payment lead and then declares it. Giving up only costs the automation:
// the openings stay stored and the miner can still declare by hand.
func (s *Service) declareWhenMature(id string, l1Block uint64) {
	target := MaturesAt(l1Block)
	failures := 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), balanceTimeout)
		tip, err := s.wallet.TipNumber(ctx)
		cancel()
		if err != nil {
			failures++
			if failures >= maturePollFailures {
				logrus.Errorf("miner: prepayment %s: giving up on auto-declaring: %v", id, err)
				return
			}
		} else if tip >= target {
			break
		} else {
			failures = 0
		}
		time.Sleep(s.maturePoll)
	}

	if _, err := s.Declare(id, 0); err != nil {
		logrus.Errorf("miner: auto-declaring prepayment %s: %v", id, err)
	}
}

// Wait blocks until every prepayment being followed to L1 has settled into a
// final state or timed out.
func (s *Service) Wait() {
	s.background.Wait()
}

// Resume picks up prepayments a restart interrupted: those whose transaction
// was sent are awaited again, and those that never got as far as a hash are
// marked as interrupted, since there is no telling whether they went out.
func (s *Service) Resume() {
	for _, p := range s.store.List() {
		switch p.Status {
		case StatusBroadcasting:
			s.fail(p.ID, StatusInterrupted, errors.New("the node stopped before this prepayment's transaction hash was recorded"))
		case StatusConfirmed:
			if s.wallet != nil && p.AutoDeclare && hasUndeclared(p) {
				s.background.Add(1)
				go func() {
					defer s.background.Done()
					s.declareWhenMature(p.ID, p.L1Block)
				}()
			}
		case StatusConfirming:
			if s.wallet != nil {
				s.background.Add(1)
				go func() {
					defer s.background.Done()
					s.await(p.ID, p.TxHash)
				}()
			}
		}
	}
}

// hasUndeclared reports whether any of a prepayment's openings is still to be
// declared.
func hasUndeclared(p Prepayment) bool {
	for _, b := range p.Bids {
		if !b.Declared {
			return true
		}
	}
	return false
}

// update applies `change` to a stored prepayment, logging rather than
// returning a failure to persist: the callers are background steps with no
// one to hand the error to.
func (s *Service) update(id string, change func(*Prepayment)) (Prepayment, bool) {
	p, err := s.store.Update(id, change)
	if err != nil {
		logrus.Errorf("miner: updating prepayment %s: %v", id, err)
		return p, false
	}
	return p, true
}

// fail records that a prepayment stopped at `status` because of `cause`.
func (s *Service) fail(id string, status PrepayStatus, cause error) {
	logrus.Errorf("miner: prepayment %s: %v", id, cause)
	s.update(id, func(p *Prepayment) {
		p.Status = status
		p.Error = cause.Error()
	})
}

// Declare hands the not-yet-declared openings of prepayment `id`, at heights
// `from` and above, to the node. Heights the chain has already passed are
// skipped: they can no longer be bid on. The batch is all-or-nothing, as it
// is for the node's own endpoint.
func (s *Service) Declare(id string, from uint32) (consensus.PayL1TokenResponse, error) {
	p, ok := s.store.Get(id)
	if !ok {
		return consensus.PayL1TokenResponse{}, fmt.Errorf("no prepayment %q", id)
	}
	if p.Status != StatusConfirmed {
		return consensus.PayL1TokenResponse{}, fmt.Errorf("prepayment %s is %s; only a confirmed one can be declared", id, p.Status)
	}

	if err := s.checkMature(p); err != nil {
		return consensus.PayL1TokenResponse{}, err
	}

	consumed := s.book.Consumed()
	var payments []consensus.PaymentDeclaration
	for _, b := range p.Bids {
		if b.Declared || b.Height < from || common.BlockNum(b.Height) <= consumed {
			continue
		}
		payments = append(payments, consensus.PaymentDeclaration{
			BlockHeight: common.BlockNum(b.Height),
			Amount:      b.Amount,
			Random:      b.Random,
			TxHash:      p.TxHash,
		})
	}
	if len(payments) == 0 {
		return consensus.PayL1TokenResponse{}, errors.New("nothing left to declare: every height is declared or already past")
	}

	ctx, cancel := context.WithTimeout(context.Background(), declareTimeout)
	defer cancel()
	resp := s.declarer.Declare(ctx, payments)
	if len(resp.Rejected) > 0 {
		return resp, nil
	}

	accepted := make(map[uint32]bool, len(resp.Accepted))
	for _, h := range resp.Accepted {
		accepted[uint32(h)] = true
	}
	_, err := s.store.Update(id, func(p *Prepayment) {
		for i := range p.Bids {
			if accepted[p.Bids[i].Height] {
				p.Bids[i].Declared = true
			}
		}
	})
	return resp, err
}

// checkMature refuses to declare a prepayment that has not cleared the
// payment lead; see MaturesAt.
func (s *Service) checkMature(p Prepayment) error {
	if s.wallet == nil {
		// Only a wallet makes prepayments, so this one came from elsewhere;
		// the node's own confirmation is all there is to go on.
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), balanceTimeout)
	defer cancel()
	tip, err := s.wallet.TipNumber(ctx)
	if err != nil {
		return err
	}
	if target := MaturesAt(p.L1Block); tip < target {
		return fmt.Errorf("prepayment %s matures at L1 block %d (tip is %d); a block spending it any earlier could never settle",
			p.ID, target, tip)
	}
	return nil
}

// L1Tip is L1's current block number, or false when there is no wallet or L1
// cannot be reached.
func (s *Service) L1Tip(ctx context.Context) (uint64, bool) {
	if s.wallet == nil {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(ctx, balanceTimeout)
	defer cancel()
	tip, err := s.wallet.TipNumber(ctx)
	return tip, err == nil
}

// Prepayments lists every prepayment, oldest first.
func (s *Service) Prepayments() []Prepayment {
	return s.store.List()
}
