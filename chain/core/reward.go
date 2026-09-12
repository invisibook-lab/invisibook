package core

import (
	"fmt"
	"math/big"

	"github.com/yu-org/yu/common"
)

// RewardAdapter lets the consensus tripod pay block rewards without reaching
// into either core tripod directly: fees are an orderbook fact, minting is an
// account fact, and consensus wants one thing that does both.
type RewardAdapter struct {
	orderBook *OrderBook
	account   *Account
}

// NewRewardAdapter builds the adapter over the two core tripods.
// Both must be non-nil.
func NewRewardAdapter(orderBook *OrderBook, account *Account) *RewardAdapter {
	return &RewardAdapter{orderBook: orderBook, account: account}
}

// HandlingFees returns the total handling fee declared by the orders that
// entered the chain at `height`.
func (r *RewardAdapter) HandlingFees(height common.BlockNum) (*big.Int, error) {
	return r.orderBook.HandlingFeesAtHeight(height)
}

// CreditReward mints a native-token Cash holding `commitment` for `pubkey`.
//
// `blockHash` is mixed into the Cash ID so that two blocks paying the same
// account the same amount stay two distinct records. The reward is Active on
// creation: unlike bridged cash there is nothing to prove about where it came
// from, the block itself is the proof.
func (r *RewardAdapter) CreditReward(pubkey, commitment string, blockHash common.Hash) error {
	cash := &Cash{
		ID:      computeRewardCashID(pubkey, NativeToken.Name, CipherText(commitment), blockHash),
		Pubkey:  pubkey,
		Token:   NativeToken.Name,
		Amount:  CipherText(commitment),
		ZkProof: fmt.Sprintf("coinbase:%s", blockHash.String()),
		Status:  Active,
	}
	return r.account.CreateCash(cash)
}
