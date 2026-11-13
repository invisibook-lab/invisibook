package ckb

import (
	"context"
	"fmt"

	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
	"github.com/sirupsen/logrus"

	"github.com/invisibook-lab/invisibook/consensus"
)

// anchorScanPage is how many indexer entries one request asks for.
const anchorScanPage = 200

// AnchoredIn returns every decodable L2 header in submit cells created in L1
// blocks `from` through `to`, inclusive.
//
// Nothing is kept between calls. The anchoring schedule tells the caller
// exactly which window to read for a batch, and a batch is only decided once
// that window is buried deep enough that its contents no longer change, so
// there is nothing worth remembering afterwards.
//
// Each transaction is re-read with the committed-only filter and its block
// number taken from that answer, so a submission the indexer still lists but
// a reorg has moved or dropped is placed where it now is, or left out.
func (c *Client) AnchoredIn(ctx context.Context, from, to uint64) ([]*consensus.AnchoredHeader, error) {
	if from > to {
		return nil, nil
	}
	key := &indexer.SearchKey{
		Script:           c.set.commitScript,
		ScriptType:       ckbtypes.ScriptTypeType,
		ScriptSearchMode: ckbtypes.ScriptSearchModeExact,
		// The range end is exclusive.
		Filter: &indexer.Filter{BlockRange: &[2]uint64{from, to + 1}},
	}

	var out []*consensus.AnchoredHeader
	read := make(map[ckbtypes.Hash]bool)
	cursor := ""
	for {
		page, err := c.rpc.GetTransactions(ctx, key, indexer.SearchOrderAsc, anchorScanPage, cursor)
		if err != nil {
			return nil, fmt.Errorf("listing submit cells in L1 [%d, %d]: %w", from, to, err)
		}
		for _, entry := range page.Objects {
			// Inputs are submit cells being reclaimed; their creation is
			// listed as an output of an earlier transaction.
			if entry.IoType != indexer.IOTypeOut || read[entry.TxHash] {
				continue
			}
			read[entry.TxHash] = true
			headers, err := c.headersIn(ctx, entry.TxHash, from, to)
			if err != nil {
				return nil, err
			}
			out = append(out, headers...)
		}
		if len(page.Objects) < anchorScanPage {
			return out, nil
		}
		cursor = page.LastCursor
	}
}

// headersIn decodes the header of every submit cell `txHash` created, when
// the transaction is committed in L1 [from, to].
//
// A cell whose data is not a decodable header is skipped: the script only
// bounds its length, so anyone can write one, and it anchors nothing.
func (c *Client) headersIn(ctx context.Context, txHash ckbtypes.Hash, from, to uint64) ([]*consensus.AnchoredHeader, error) {
	tx, err := c.fetchTx(ctx, txHash.String())
	if err != nil {
		return nil, err
	}
	if tx == nil || tx.TxStatus.BlockNumber == nil {
		return nil, nil
	}
	height := *tx.TxStatus.BlockNumber
	if height < from || height > to {
		return nil, nil
	}

	var out []*consensus.AnchoredHeader
	want := c.set.commitScript.Hash()
	for i, output := range tx.Transaction.Outputs {
		if output.Type == nil || output.Type.Hash() != want || i >= len(tx.Transaction.OutputsData) {
			continue
		}
		header, err := consensus.DecodeAnchoredHeader(tx.Transaction.OutputsData[i])
		if err != nil {
			logrus.Debugf("PoB: submit cell %s#%d carries no usable header: %v", txHash, i, err)
			continue
		}
		out = append(out, &consensus.AnchoredHeader{Header: header, L1Height: height})
	}
	return out, nil
}

// Tip returns the height of L1's canonical tip.
func (c *Client) Tip(ctx context.Context) (uint64, error) {
	tip, err := c.rpc.GetTipBlockNumber(ctx)
	if err != nil {
		return 0, fmt.Errorf("reading L1's tip: %w", err)
	}
	return tip, nil
}
