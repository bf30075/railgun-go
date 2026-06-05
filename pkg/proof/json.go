package proof

import (
	"encoding/json"
	"fmt"
	"math/big"
)

type poiEngineProofInputsJSON struct {
	AnyRailgunTxidMerklerootAfterTransaction string     `json:"anyRailgunTxidMerklerootAfterTransaction"`
	POIMerkleRoots                           []string   `json:"poiMerkleroots"`
	BoundParamsHash                          string     `json:"boundParamsHash"`
	Nullifiers                               []string   `json:"nullifiers"`
	CommitmentsOut                           []string   `json:"commitmentsOut"`
	SpendingPublicKey                        [2]string  `json:"spendingPublicKey"`
	NullifyingKey                            string     `json:"nullifyingKey"`
	Token                                    string     `json:"token"`
	RandomsIn                                []string   `json:"randomsIn"`
	ValuesIn                                 []string   `json:"valuesIn"`
	UTXOPositionsIn                          []uint64   `json:"utxoPositionsIn"`
	UTXOTreeIn                               uint64     `json:"utxoTreeIn"`
	NPKsOut                                  []string   `json:"npksOut"`
	ValuesOut                                []string   `json:"valuesOut"`
	UTXOBatchGlobalStartPositionOut          string     `json:"utxoBatchGlobalStartPositionOut"`
	RailgunTxidIfHasUnshield                 string     `json:"railgunTxidIfHasUnshield"`
	RailgunTxidMerkleProofIndices            string     `json:"railgunTxidMerkleProofIndices"`
	RailgunTxidMerkleProofPathElements       []string   `json:"railgunTxidMerkleProofPathElements"`
	POIInMerkleProofIndices                  []string   `json:"poiInMerkleProofIndices"`
	POIInMerkleProofPathElements             [][]string `json:"poiInMerkleProofPathElements"`
}

func ParsePOIEngineProofInputsJSON(data []byte) (POIEngineProofInputs, error) {
	var raw poiEngineProofInputsJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return POIEngineProofInputs{}, err
	}

	spendingKey0, err := ParseNumberishBigInt(raw.SpendingPublicKey[0])
	if err != nil {
		return POIEngineProofInputs{}, fmt.Errorf("spendingPublicKey[0]: %w", err)
	}
	spendingKey1, err := ParseNumberishBigInt(raw.SpendingPublicKey[1])
	if err != nil {
		return POIEngineProofInputs{}, fmt.Errorf("spendingPublicKey[1]: %w", err)
	}
	nullifyingKey, err := ParseNumberishBigInt(raw.NullifyingKey)
	if err != nil {
		return POIEngineProofInputs{}, fmt.Errorf("nullifyingKey: %w", err)
	}
	valuesIn, err := parseNumberishSlice(raw.ValuesIn)
	if err != nil {
		return POIEngineProofInputs{}, fmt.Errorf("valuesIn: %w", err)
	}
	npksOut, err := parseNumberishSlice(raw.NPKsOut)
	if err != nil {
		return POIEngineProofInputs{}, fmt.Errorf("npksOut: %w", err)
	}
	valuesOut, err := parseNumberishSlice(raw.ValuesOut)
	if err != nil {
		return POIEngineProofInputs{}, fmt.Errorf("valuesOut: %w", err)
	}
	batchStart, err := ParseNumberishBigInt(raw.UTXOBatchGlobalStartPositionOut)
	if err != nil {
		return POIEngineProofInputs{}, fmt.Errorf("utxoBatchGlobalStartPositionOut: %w", err)
	}

	return POIEngineProofInputs{
		AnyRailgunTxidMerklerootAfterTransaction: raw.AnyRailgunTxidMerklerootAfterTransaction,
		POIMerkleRoots:                           raw.POIMerkleRoots,
		BoundParamsHash:                          raw.BoundParamsHash,
		Nullifiers:                               raw.Nullifiers,
		CommitmentsOut:                           raw.CommitmentsOut,
		SpendingPublicKey:                        [2]*big.Int{spendingKey0, spendingKey1},
		NullifyingKey:                            nullifyingKey,
		Token:                                    raw.Token,
		RandomsIn:                                raw.RandomsIn,
		ValuesIn:                                 valuesIn,
		UTXOPositionsIn:                          raw.UTXOPositionsIn,
		UTXOTreeIn:                               raw.UTXOTreeIn,
		NPKsOut:                                  npksOut,
		ValuesOut:                                valuesOut,
		UTXOBatchGlobalStartPositionOut:          batchStart,
		RailgunTxidIfHasUnshield:                 raw.RailgunTxidIfHasUnshield,
		RailgunTxidMerkleProofIndices:            raw.RailgunTxidMerkleProofIndices,
		RailgunTxidMerkleProofPathElements:       raw.RailgunTxidMerkleProofPathElements,
		POIInMerkleProofIndices:                  raw.POIInMerkleProofIndices,
		POIInMerkleProofPathElements:             raw.POIInMerkleProofPathElements,
	}, nil
}
