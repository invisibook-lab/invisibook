package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"

	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/core"
)

// rewardRandomDomain separates the coinbase blinding factor from every other
// value derived from a block hash.
const rewardRandomDomain = "invisibook/pob/coinbase"

// CalcBlockReward returns what the producer of a block earns: a fixed coinbase
// plus every handling fee the block collected.
// Both arguments must be non-nil.
func CalcBlockReward(coinbase, fees *big.Int) *big.Int {
	return new(big.Int).Add(coinbase, fees)
}

// RewardRandomHex derives the blinding factor for a block's coinbase
// commitment from the pre-execution reward identity.
//
// It has to be derived rather than sampled: every node executes the block and
// must arrive at byte-identical state, so a random draw would fork the chain.
// The consequence is that the reward's opening is public — anyone can
// recompute (amount, random) — but the reward amount is public anyway. Only
// the owner's key can spend it.
func RewardRandomHex(identity common.Hash) string {
	h := sha256.New()
	h.Write(identity.Bytes())
	h.Write([]byte(rewardRandomDomain))
	return hex.EncodeToString(h.Sum(nil))
}

// handlingFees returns the total handling fee carried by the writings in
// `block`.
//
// The fees are read out of the block's own transactions rather than looked up
// in orderbook state. A block's reward has to be computable from the block
// alone: every node must arrive at the same figure from the same bytes,
// before and independently of whatever state executing it happens to produce.
func handlingFees(block *types.Block) (*big.Int, error) {
	total := new(big.Int)
	for i, txn := range block.Txns {
		if txn.Raw == nil || txn.Raw.WrCall == nil {
			continue
		}
		call := txn.Raw.WrCall
		if call.TripodName != core.OrderBookTripodName || call.FuncName != core.SendOrderFuncName {
			continue
		}

		var req core.SendOrderRequest
		if err := json.Unmarshal([]byte(call.Params), &req); err != nil {
			return nil, fmt.Errorf("decoding %s params of txn %d (%s): %w",
				core.SendOrderFuncName, i, txn.TxnHash.String(), err)
		}
		total.Add(total, new(big.Int).SetUint64(core.TotalFee(req.HandlingFee)))
	}
	return total, nil
}

// creditReward mints native-token cash holding `commitment` for `owner`.
//
// The pre-execution identity is mixed into the cash ID so different heights paying the same
// owner the same amount stay two distinct records. The reward is Active on
// creation: unlike bridged cash there is nothing to prove about where it came
// from, the block itself is the proof.
func (p *ProofOfBuy) creditReward(owner, commitment string, identity common.Hash) error {
	return p.Account.CreateCash(&account.Cash{
		ID:      account.ComputeRewardCashID(owner, account.NativeToken.Name, account.CipherText(commitment), identity),
		Pubkey:  owner,
		Token:   account.NativeToken.Name,
		Amount:  account.CipherText(commitment),
		ZkProof: fmt.Sprintf("coinbase:%s", identity.String()),
		Status:  account.Active,
	})
}

// payBlockReward credits the block's producer with the coinbase plus this
// block's handling fees.
//
// The recipient is the producer's own block-signing key. Owner keys and miner
// keys live on the same curve, so a miner owns what it earns under the very
// identity it mined with — there is no payout account to declare, nothing to
// register, and every node executing the block credits the same owner by
// construction.
//
// TODO: compensate the miners who paid L1 token for this height and lost. The
// protocol pays them a share of the L2 native token so that competing is not
// an all-or-nothing bet (docs/proof_of_buy.md §10.2) — that requires knowing
// which rivals bid, which means their losing blocks have to be retained and
// their payments confirmed, none of which happens yet.
func (p *ProofOfBuy) payBlockReward(block *types.Block) error {
	if p.Account == nil {
		return nil
	}
	if len(block.MinerPubkey) == 0 {
		return fmt.Errorf("reward has no producer key")
	}
	owner := hex.EncodeToString(block.MinerPubkey)
	coinbase, ok := new(big.Int).SetString(p.cfg.CoinbaseReward, 10)
	if !ok || coinbase.Sign() < 0 {
		return fmt.Errorf("invalid coinbase_reward %q", p.cfg.CoinbaseReward)
	}
	fees, err := handlingFees(block)
	if err != nil {
		return err
	}
	reward := CalcBlockReward(coinbase, fees)
	if reward.Sign() <= 0 {
		return nil
	}
	identity := rewardIdentity(block)
	commitment, err := PoseidonCommit(reward, RewardRandomHex(identity))
	if err != nil {
		return err
	}
	if err := p.creditReward(owner, commitment, identity); err != nil {
		return err
	}
	logrus.Infof("PoB: block reward height=%d coinbase=%s fees=%s total=%s to %s", block.Height, coinbase, fees, reward, shortHex(owner))
	return nil
}

// shortHex trims a long hex string down to something readable in a log line.
func shortHex(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// rewardIdentity binds rewards to the parent, height, producer and transaction root without a circular StateRoot dependency.
func rewardIdentity(block *types.Block) common.Hash {
	raw := append([]byte("pob-reward-v2"), block.PrevHash.Bytes()...)
	raw = append(raw, []byte(fmt.Sprintf(":%d:", block.Height))...)
	raw = append(raw, block.MinerPubkey...)
	raw = append(raw, block.TxnRoot.Bytes()...)
	return common.BytesToHash(common.Sha256(raw))
}
