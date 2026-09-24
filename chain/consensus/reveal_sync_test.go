package consensus

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/yu-org/yu/common"

	"github.com/invisibook-lab/invisibook/store"
)

// fakeRevealStore is an in-memory RevealStore, which is the whole point of
// that interface being narrow.
type fakeRevealStore struct {
	rows   map[string]*store.Reveal
	putErr error
}

func newFakeRevealStore() *fakeRevealStore {
	return &fakeRevealStore{rows: make(map[string]*store.Reveal)}
}

func (f *fakeRevealStore) HighestHeight() (common.BlockNum, error) {
	var highest common.BlockNum
	for _, row := range f.rows {
		if row.Height > highest {
			highest = row.Height
		}
	}
	return highest, nil
}

func (f *fakeRevealStore) SinceHeight(height common.BlockNum, limit int) ([]*store.Reveal, error) {
	var out []*store.Reveal
	for _, row := range f.rows {
		if row.Height >= height {
			out = append(out, row)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeRevealStore) Put(reveal *store.Reveal) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.rows[reveal.BlockHash] = reveal
	return nil
}

// fakePeers answers RequestPeer from a canned table.
type fakePeers struct {
	nodes     []peer.ID
	responses map[peer.ID][]byte
	failures  map[peer.ID]error
	asked     []peer.ID
	// requests keeps what was actually sent, so tests can check the range
	// asked for rather than trusting the syncer's word for it.
	requests [][]byte
}

func (f *fakePeers) GetBootNodes() []peer.ID { return f.nodes }

func (f *fakePeers) RequestPeer(peerID peer.ID, _ int, request []byte) ([]byte, error) {
	f.asked = append(f.asked, peerID)
	f.requests = append(f.requests, request)
	if err, ok := f.failures[peerID]; ok {
		return nil, err
	}
	return f.responses[peerID], nil
}

// revealAt builds a well-formed reveal message.
func revealAt(hash string, height common.BlockNum) *BlockReveal {
	return &BlockReveal{
		L2BlockHeight: height,
		L2BlockHash:   hash,
		Random:        strings.Repeat("ab", 32),
		L1BlockHash:   "0xl1block",
		TxIdx:         1,
		MinerPubkey:   "0xminer",
	}
}

// respondWith packs reveals the way a peer would.
func respondWith(t *testing.T, reveals ...*BlockReveal) []byte {
	t.Helper()
	raw, err := json.Marshal(&RevealSyncResponse{Reveals: reveals})
	if err != nil {
		t.Fatalf("encoding a canned response: %v", err)
	}
	return raw
}

func TestCatchUpStoresWhatPeersOffer(t *testing.T) {
	revealStore := newFakeRevealStore()
	node := peer.ID("peer-a")
	peers := &fakePeers{
		nodes:     []peer.ID{node},
		responses: map[peer.ID][]byte{node: respondWith(t, revealAt("0xa", 4), revealAt("0xb", 5))},
	}

	stored, err := NewRevealSyncer(revealStore).CatchUp(peers)
	if err != nil {
		t.Fatalf("CatchUp: %v", err)
	}
	if stored != 2 {
		t.Fatalf("stored = %d, want 2", stored)
	}
	if _, ok := revealStore.rows["0xa"]; !ok {
		t.Fatal("the first reveal was not stored")
	}
}

// One unreachable peer must not end the catch-up: any single honest peer is
// enough, and a node that stopped at the first failure would never recover
// from one bad address in its boot list.
func TestCatchUpSkipsAFailingPeer(t *testing.T) {
	revealStore := newFakeRevealStore()
	bad, good := peer.ID("peer-bad"), peer.ID("peer-good")
	peers := &fakePeers{
		nodes:     []peer.ID{bad, good},
		failures:  map[peer.ID]error{bad: errors.New("dial failed")},
		responses: map[peer.ID][]byte{good: respondWith(t, revealAt("0xa", 7))},
	}

	stored, err := NewRevealSyncer(revealStore).CatchUp(peers)
	if err != nil {
		t.Fatalf("CatchUp must not fail when one peer does: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored = %d, want 1 from the reachable peer", stored)
	}
	if len(peers.asked) != 2 {
		t.Fatalf("asked %d peers, want both tried", len(peers.asked))
	}
}

// Peers are not trusted. A malformed opening is dropped rather than stored,
// or it would sit in the store forever failing to open anything.
func TestCatchUpDiscardsMalformedReveals(t *testing.T) {
	revealStore := newFakeRevealStore()
	node := peer.ID("peer-a")

	bad := revealAt("0xbad", 4)
	bad.Random = "too-short"
	peers := &fakePeers{
		nodes:     []peer.ID{node},
		responses: map[peer.ID][]byte{node: respondWith(t, bad, revealAt("0xgood", 5))},
	}

	stored, err := NewRevealSyncer(revealStore).CatchUp(peers)
	if err != nil {
		t.Fatalf("CatchUp: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored = %d, want only the well-formed one", stored)
	}
	if _, ok := revealStore.rows["0xbad"]; ok {
		t.Fatal("a malformed reveal reached the store")
	}
}

func TestCatchUpWithNoPeersIsNotAnError(t *testing.T) {
	stored, err := NewRevealSyncer(newFakeRevealStore()).CatchUp(&fakePeers{})
	if err != nil {
		t.Fatalf("a node with no peers must not error, got %v", err)
	}
	if stored != 0 {
		t.Fatalf("stored = %d, want 0", stored)
	}
}

// The asked-for range starts at the highest height already held, not one
// above it: a height can carry several competing blocks, and stopping short
// would permanently miss the rivals of whichever one arrived first.
func TestCatchUpReasksForTheHighestHeldHeight(t *testing.T) {
	revealStore := newFakeRevealStore()
	if err := revealStore.Put(revealAt("0xheld", 9).ToRow()); err != nil {
		t.Fatalf("seeding the store: %v", err)
	}
	node := peer.ID("peer-a")
	peers := &fakePeers{
		nodes:     []peer.ID{node},
		responses: map[peer.ID][]byte{node: respondWith(t)},
	}

	if _, err := NewRevealSyncer(revealStore).CatchUp(peers); err != nil {
		t.Fatalf("CatchUp: %v", err)
	}

	if len(peers.requests) != 1 {
		t.Fatalf("sent %d requests, want 1", len(peers.requests))
	}
	var sent RevealSyncRequest
	if err := json.Unmarshal(peers.requests[0], &sent); err != nil {
		t.Fatalf("decoding the request actually sent: %v", err)
	}
	if sent.FromHeight != 9 {
		t.Fatalf("FromHeight = %d, want 9 — the highest height already held", sent.FromHeight)
	}
}

// A store that refuses a row must not be counted as having taken it, or a
// node would report itself caught up on openings it never kept.
func TestCatchUpDoesNotCountRevealsTheStoreRefused(t *testing.T) {
	revealStore := newFakeRevealStore()
	revealStore.putErr = errors.New("disk full")
	node := peer.ID("peer-a")
	peers := &fakePeers{
		nodes:     []peer.ID{node},
		responses: map[peer.ID][]byte{node: respondWith(t, revealAt("0xa", 4))},
	}

	stored, err := NewRevealSyncer(revealStore).CatchUp(peers)
	if err != nil {
		t.Fatalf("CatchUp: %v", err)
	}
	if stored != 0 {
		t.Fatalf("stored = %d, want 0 — the store refused the row", stored)
	}
}

func TestHandleRequestServesStoredReveals(t *testing.T) {
	revealStore := newFakeRevealStore()
	for _, r := range []*BlockReveal{revealAt("0xa", 3), revealAt("0xb", 8)} {
		if err := revealStore.Put(r.ToRow()); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}
	syncer := NewRevealSyncer(revealStore)

	req, err := json.Marshal(&RevealSyncRequest{FromHeight: 5})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	raw, err := syncer.HandleRequest(req)
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	var resp RevealSyncResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if len(resp.Reveals) != 1 || resp.Reveals[0].L2BlockHash != "0xb" {
		t.Fatalf("response = %+v, want only the reveal at height 8", resp.Reveals)
	}
}

func TestHandleRequestRejectsGarbage(t *testing.T) {
	syncer := NewRevealSyncer(newFakeRevealStore())

	if _, err := syncer.HandleRequest([]byte("not json")); err == nil {
		t.Fatal("a malformed request must be refused")
	}
}
