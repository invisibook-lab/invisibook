package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// rewardRandomDomain separates the coinbase blinding factor from every other
// value derived from a block hash.
const rewardRandomDomain = "invisibook/pob/coinbase"

// BlockRewarder pays out what a block earned its producer. The consensus
// tripod decides the amount; the account and orderbook state behind this
// interface is owned by the core tripods.
type BlockRewarder interface {
	// HandlingFees returns the total handling fee declared by the orders that
	// entered the chain at `height`.
	HandlingFees(height common.BlockNum) (*big.Int, error)

	// CreditReward mints native-token cash holding `commitment` for `pubkey`.
	// `blockHash` is what makes the record unique: two blocks paying the same
	// miner the same amount must not collapse into one cash entry.
	CreditReward(pubkey, commitment string, blockHash common.Hash) error
}

// CalcBlockReward returns what the producer of a block earns: a fixed coinbase
// plus every handling fee the block collected.
// Both arguments must be non-nil.
func CalcBlockReward(coinbase, fees *big.Int) *big.Int {
	return new(big.Int).Add(coinbase, fees)
}

// RewardRandomHex derives the blinding factor for a block's coinbase
// commitment from the block hash.
//
// It has to be derived rather than sampled: every node executes the block and
// must arrive at byte-identical state, so a random draw would fork the chain.
// The consequence is that the reward's opening is public — anyone can
// recompute (amount, random) — but the reward amount is public anyway. Only
// the owner's key can spend it.
func RewardRandomHex(blockHash common.Hash) string {
	h := sha256.New()
	h.Write(blockHash.Bytes())
	h.Write([]byte(rewardRandomDomain))
	return hex.EncodeToString(h.Sum(nil))
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
func (p *ProofOfBuy) payBlockReward(block *types.Block) {
	if p.rewarder == nil {
		return
	}
	if len(block.MinerPubkey) == 0 {
		logrus.Warnf("PoB: block at height=%d carries no miner key, reward dropped", block.Height)
		return
	}
	owner := hex.EncodeToString(block.MinerPubkey)

	coinbase, ok := new(big.Int).SetString(p.cfg.CoinbaseReward, 10)
	if !ok {
		logrus.Errorf("PoB: invalid coinbase_reward %q in config, paying no reward for height=%d",
			p.cfg.CoinbaseReward, block.Height)
		return
	}

	fees, err := p.rewarder.HandlingFees(block.Height)
	if err != nil {
		logrus.Errorf("PoB: summing handling fees at height=%d: %v, paying coinbase only", block.Height, err)
		fees = new(big.Int)
	}

	reward := CalcBlockReward(coinbase, fees)
	if reward.Sign() <= 0 {
		return
	}

	commitment, err := PoseidonCommit(reward, RewardRandomHex(block.Hash))
	if err != nil {
		logrus.Errorf("PoB: committing block reward at height=%d: %v", block.Height, err)
		return
	}
	if err := p.rewarder.CreditReward(owner, commitment, block.Hash); err != nil {
		logrus.Errorf("PoB: crediting block reward at height=%d: %v", block.Height, err)
		return
	}

	logrus.Infof("PoB: block reward height=%d coinbase=%s fees=%s total=%s to %s",
		block.Height, coinbase, fees, reward, shortHex(owner))
}
