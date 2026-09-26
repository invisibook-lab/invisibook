package ckb

import (
	"context"
	"math/big"
	"testing"

	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

func TestCreateBudget(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	fund(client, node, 100_000_00000000)

	const prepaid = 5_000_00000000
	first, err := Allocate(100, big.NewInt(3_000_00000000), repeatHex("aa", 32))
	if err != nil {
		t.Fatalf("committing to an allocation: %v", err)
	}
	second, err := Allocate(101, big.NewInt(2_000_00000000), repeatHex("bb", 32))
	if err != nil {
		t.Fatalf("committing to an allocation: %v", err)
	}

	if _, err := client.CreateBudget(context.Background(), prepaid, []BudgetEntry{first, second}); err != nil {
		t.Fatalf("creating the budget cell: %v", err)
	}
	if len(node.sent) != 1 {
		t.Fatalf("broadcast %d transactions, want 1", len(node.sent))
	}
	tx := node.sent[0]

	// R3.3: the declared total has to equal the capacity this same
	// transaction moves into the mining addr, or a miner could claim to have
	// paid whatever it liked. The script sums every output under that lock.
	var paid uint64
	for _, output := range tx.Outputs {
		if output.Lock.Hash() == client.set.miningAddrLockHash {
			paid += output.Capacity
			// Without the vault script on it, this capacity would be money
			// the operator could later spend with no mark attached — R4.0
			// governs cells the vault guards, and this is how one comes to
			// be guarded.
			if output.Type == nil || output.Type.Hash() != client.set.vaultScript.Hash() {
				t.Fatal("the prepayment does not carry the vault script")
			}
		}
	}
	if paid != prepaid {
		t.Fatalf("moved %d shannon into the mining addr, declared %d", paid, uint64(prepaid))
	}

	// The budget cell itself: the miner's, carrying the table and nothing of
	// the money, which is already gone.
	budgetIdx := -1
	for i, output := range tx.Outputs {
		if output.Type != nil && output.Type.Hash() == client.set.budgetScript.Hash() {
			budgetIdx = i
		}
	}
	if budgetIdx < 0 {
		t.Fatal("the transaction creates no budget cell")
	}
	if tx.Outputs[budgetIdx].Lock.Hash() != client.minerLock().Hash() {
		t.Fatal("the budget cell is not locked to the miner that created it")
	}

	data, err := DecodeBudgetData(tx.OutputsData[budgetIdx])
	if err != nil {
		t.Fatalf("reading back the budget cell's data: %v", err)
	}
	if data.Prepaid != prepaid {
		t.Fatalf("the cell declares %d, want %d", data.Prepaid, uint64(prepaid))
	}
	if len(data.Allocations) != 2 || data.Allocations[0] != first || data.Allocations[1] != second {
		t.Fatalf("the table reads back as %+v", data.Allocations)
	}

	// A type script runs when its cell is created, not only when it is spent,
	// so both scripts have to be findable in this very transaction.
	if !hasDep(tx, client.set.budgetDep) || !hasDep(tx, client.set.vaultDep) {
		t.Fatal("a script this transaction creates a cell under has no cell dep")
	}
}

// R3.4: a token marked by spent_type_script must never fund a prepayment.
// Without it the whole marking scheme of §4 is idle — the operator would
// spend out of the mining addr, have the tokens marked, and turn straight
// around to mine with them.
//
// The same filter keeps the miner's own budget and commit cells, which live
// under the same lock, from being swept up as change and destroyed.
func TestCreateBudgetIgnoresCellsCarryingScripts(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	marked := &ckbtypes.OutPoint{TxHash: ckbtypes.HexToHash(hashOf(0x91)), Index: 0}
	node.cells = append(node.cells, &indexer.LiveCell{
		BlockNumber: 1,
		OutPoint:    marked,
		Output: &ckbtypes.CellOutput{
			Capacity: 1_000_000_00000000,
			Lock:     client.minerLock(),
			Type:     client.set.spentScript,
		},
	})
	fund(client, node, 100_000_00000000)

	if _, err := client.CreateBudget(context.Background(), 5_000_00000000, nil); err != nil {
		t.Fatalf("creating the budget cell: %v", err)
	}
	for _, input := range node.sent[0].Inputs {
		if input.PreviousOutput.TxHash == marked.TxHash && input.PreviousOutput.Index == marked.Index {
			t.Fatal("funded a prepayment with a marked token")
		}
	}
}

// A prepayment smaller than the cell holding it cannot exist on CKB. Saying
// so here costs a round trip less than learning it from the node.
func TestCreateBudgetRejectsPrepaymentBelowTheCellFloor(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	fund(client, node, 100_000_00000000)

	if _, err := client.CreateBudget(context.Background(), 1, nil); err == nil {
		t.Fatal("accepted a prepayment too small to occupy its own cell")
	}
	if len(node.sent) != 0 {
		t.Fatal("broadcast a transaction that could not be valid")
	}
}

// The table is written once and can never be corrected (R3.1), so a table
// that would encode wrong is stopped before any money moves.
func TestCreateBudgetRejectsMalformedTable(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	fund(client, node, 100_000_00000000)

	_, err := client.CreateBudget(context.Background(), 5_000_00000000, []BudgetEntry{
		entry(9, "a"), entry(2, "b"),
	})
	if err == nil {
		t.Fatal("accepted a table that is not ascending by height")
	}
	if len(node.sent) != 0 {
		t.Fatal("spent a prepayment on a table that cannot be read back")
	}
}
