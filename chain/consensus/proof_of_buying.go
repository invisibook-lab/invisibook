package consensus

import (
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
)

// ProofOfBuy is a placeholder consensus tripod for the "proof of buying" scheme.
// All hooks are still TODO and will panic if the tripod is wired into a kernel.
type ProofOfBuy struct {
	*tripod.Tripod
}

// StartBlock runs at the beginning of each block.
// TODO: implement proof-of-buying start-of-block logic.
func (p *ProofOfBuy) StartBlock(block *types.Block) {
	//TODO implement me
	panic("implement me")
}

// EndBlock runs after all transactions in `block` have been applied.
// TODO: implement proof-of-buying end-of-block logic.
func (p *ProofOfBuy) EndBlock(block *types.Block) {
	//TODO implement me
	panic("implement me")
}

// FinalizeBlock runs once `block` is finalized by consensus.
// TODO: implement proof-of-buying finalization logic.
func (p *ProofOfBuy) FinalizeBlock(block *types.Block) {
	//TODO implement me
	panic("implement me")
}

// NewProofOfBuy constructs an empty ProofOfBuy tripod. Hooks are TODO — see the
// type doc — so this is currently only safe to instantiate, not to run.
func NewProofOfBuy() *ProofOfBuy {
	tri := tripod.NewTripod()
	return &ProofOfBuy{tri}
}
