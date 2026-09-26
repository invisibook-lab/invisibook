package consensus

import (
	"encoding/json"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
)

// RevealSyncCode is the p2p request code for catching up on openings.
//
// yu's own synchronizer occupies 100 and 101, so this sits clear of them.
const RevealSyncCode = 200

// revealSyncBatch caps how many openings one response carries, so a node far
// behind catches up over several rounds instead of asking for one enormous
// message.
const revealSyncBatch = 500

// RevealStore is the slice of reveal storage the syncer needs.
//
// Narrow on purpose: the syncer neither knows nor cares that the real store is
// SQL-backed, which is what lets it be tested against a map.
type RevealStore interface {
	// HighestHeight reports the greatest height an opening is held for, 0 when
	// none is.
	HighestHeight() (common.BlockNum, error)
	// SinceHeight returns openings at or above `height`, in ascending order,
	// at most `limit` of them when `limit` is positive.
	SinceHeight(height common.BlockNum, limit int) ([]*Reveal, error)
	// Put records one opening.
	Put(reveal *Reveal) error
}

// PeerRequester is the slice of the p2p network the syncer needs: ask one
// peer a question, and know which peers to ask.
type PeerRequester interface {
	RequestPeer(peerID peer.ID, code int, request []byte) ([]byte, error)
	GetBootNodes() []peer.ID
}

// RevealSyncRequest asks a peer for every opening it holds from `FromHeight`.
type RevealSyncRequest struct {
	// FromHeight is the first height the asker still needs.
	FromHeight common.BlockNum `json:"from_height"`
	// Limit caps the response; zero means the responder decides.
	Limit int `json:"limit"`
}

// RevealSyncResponse carries the openings a peer had to offer.
type RevealSyncResponse struct {
	Reveals []*BlockReveal `json:"reveals"`
}

// RevealSyncer brings a starting node's openings up to date.
//
// Gossip alone cannot do this: a topic delivers what is published after you
// subscribe and nothing from before, so a node that was down misses exactly
// the openings it needs most. Without them it holds blocks whose goal cannot
// be tied to any commitment on L1, and fork choice has nothing to weigh.
// It holds no network reference: the serving half needs only the store, and
// the asking half takes its peers as an argument. That split is what lets the
// handler be registered at construction time, before the kernel has injected
// a network to talk to.
type RevealSyncer struct {
	store RevealStore
}

// NewRevealSyncer wires a syncer to the store it serves from and fills.
func NewRevealSyncer(revealStore RevealStore) *RevealSyncer {
	return &RevealSyncer{store: revealStore}
}

// HandleRequest answers a peer catching up. It is the server half, registered
// under RevealSyncCode.
//
// Serving openings gives nothing away: they are public by the time they are
// broadcast, and a node that withholds them only makes its own view harder to
// agree with.
func (s *RevealSyncer) HandleRequest(raw []byte) ([]byte, error) {
	var req RevealSyncRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("decoding a reveal sync request: %w", err)
	}

	limit := req.Limit
	if limit <= 0 || limit > revealSyncBatch {
		limit = revealSyncBatch
	}

	rows, err := s.store.SinceHeight(req.FromHeight, limit)
	if err != nil {
		return nil, err
	}

	resp := RevealSyncResponse{Reveals: make([]*BlockReveal, 0, len(rows))}
	for _, row := range rows {
		resp.Reveals = append(resp.Reveals, RevealFromRow(row))
	}
	encoded, err := json.Marshal(&resp)
	if err != nil {
		return nil, fmt.Errorf("encoding a reveal sync response: %w", err)
	}
	return encoded, nil
}

// CatchUp asks peers for the openings this node is missing and stores them.
//
// It returns the number stored. Peers are tried in turn and a failing one is
// skipped rather than fatal: catching up from any single honest peer is
// enough, and an unreachable one says nothing about the rest.
func (s *RevealSyncer) CatchUp(peerSource PeerRequester) (int, error) {
	highest, err := s.store.HighestHeight()
	if err != nil {
		return 0, fmt.Errorf("reading how far our reveals go: %w", err)
	}
	// Re-asking for the highest height we already hold costs one row and
	// covers the case where that height had several competing blocks and we
	// only caught one of them.
	from := highest

	req, err := json.Marshal(&RevealSyncRequest{FromHeight: from, Limit: revealSyncBatch})
	if err != nil {
		return 0, fmt.Errorf("encoding a reveal sync request: %w", err)
	}

	peers := peerSource.GetBootNodes()
	if len(peers) == 0 {
		return 0, nil
	}

	stored := 0
	for _, peerID := range peers {
		raw, err := peerSource.RequestPeer(peerID, RevealSyncCode, req)
		if err != nil {
			logrus.Warnf("PoB: asking %s for reveals failed: %v", peerID, err)
			continue
		}

		var resp RevealSyncResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			logrus.Warnf("PoB: a reveal sync response from %s was malformed: %v", peerID, err)
			continue
		}

		for _, reveal := range resp.Reveals {
			// Peers are not trusted: a malformed opening is dropped here, and
			// a well-formed but wrong one is caught later when it fails to
			// open the commitment on L1.
			if err := reveal.Validate(); err != nil {
				logrus.Warnf("PoB: discarding a reveal from %s: %v", peerID, err)
				continue
			}
			if err := s.store.Put(reveal.ToRow()); err != nil {
				logrus.Errorf("PoB: storing a synced reveal: %v", err)
				continue
			}
			stored++
		}
	}
	return stored, nil
}
