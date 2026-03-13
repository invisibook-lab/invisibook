package consensus

import (
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
)

type ProofOfBuy struct {
	*tripod.Tripod
}

func (p *ProofOfBuy) StartBlock(block *types.Block) {
	//TODO implement me
	panic("implement me")
}

func (p *ProofOfBuy) EndBlock(block *types.Block) {
	//TODO implement me
	panic("implement me")
}

func (p *ProofOfBuy) FinalizeBlock(block *types.Block) {
	//TODO implement me
	panic("implement me")
}

func NewProofOfBuy() *ProofOfBuy {
	tri := tripod.NewTripod()
	return &ProofOfBuy{tri}
}
