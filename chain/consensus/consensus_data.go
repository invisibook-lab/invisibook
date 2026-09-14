package consensus

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// ConsensusData holds the PoB-specific data stored in block.Header.Extra.
type ConsensusData struct {
	VRFResult  *VRFResult `json:"vrf_result"`
	L1Payment  *L1Payment `json:"l1_payment"`
	BlockScore string     `json:"block_score"` // big.Int decimal string
}

// l1PaymentJSON is an intermediate type for JSON marshalling of L1Payment,
// since big.Int does not have a default JSON representation.
type l1PaymentJSON struct {
	TxHash      string `json:"tx_hash"`
	Amount      string `json:"amount"`
	Random      string `json:"random"`
	BudgetProof string `json:"budget_proof,omitempty"`
	Payer       string `json:"payer"`
	MinerPubkey string `json:"miner_pubkey"`
}

type consensusDataJSON struct {
	VRFResult  *VRFResult     `json:"vrf_result"`
	L1Payment  *l1PaymentJSON `json:"l1_payment"`
	BlockScore string         `json:"block_score"`
}

// EncodeConsensusData serializes ConsensusData into JSON bytes for block.Extra.
func EncodeConsensusData(data *ConsensusData) ([]byte, error) {
	j := &consensusDataJSON{
		VRFResult:  data.VRFResult,
		BlockScore: data.BlockScore,
	}
	if data.L1Payment != nil {
		j.L1Payment = &l1PaymentJSON{
			TxHash:      data.L1Payment.TxHash,
			Amount:      data.L1Payment.Amount.String(),
			Random:      data.L1Payment.Random,
			BudgetProof: data.L1Payment.BudgetProof,
			Payer:       data.L1Payment.Payer,
			MinerPubkey: data.L1Payment.MinerPubkey,
		}
	}
	return json.Marshal(j)
}

// DecodeConsensusData deserializes JSON bytes from block.Extra into ConsensusData.
func DecodeConsensusData(raw []byte) (*ConsensusData, error) {
	var j consensusDataJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("decode consensus data: %w", err)
	}
	data := &ConsensusData{
		VRFResult:  j.VRFResult,
		BlockScore: j.BlockScore,
	}
	if j.L1Payment != nil {
		amount, ok := new(big.Int).SetString(j.L1Payment.Amount, 10)
		if !ok {
			return nil, fmt.Errorf("decode consensus data: invalid payment amount %q", j.L1Payment.Amount)
		}
		data.L1Payment = &L1Payment{
			TxHash:      j.L1Payment.TxHash,
			Amount:      amount,
			Random:      j.L1Payment.Random,
			BudgetProof: j.L1Payment.BudgetProof,
			Payer:       j.L1Payment.Payer,
			MinerPubkey: j.L1Payment.MinerPubkey,
		}
	}
	return data, nil
}
