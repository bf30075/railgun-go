package proof

import (
	"fmt"
	"math/big"
)

type CircuitID struct {
	Name       string
	MaxInputs  int
	MaxOutputs int
}

func SelectPOICircuit(inputs POIEngineProofInputs) CircuitID {
	if len(inputs.Nullifiers) <= 3 && len(inputs.CommitmentsOut) <= 3 {
		return CircuitID{Name: "POI_3X3", MaxInputs: 3, MaxOutputs: 3}
	}
	return CircuitID{Name: "POI_13X13", MaxInputs: 13, MaxOutputs: 13}
}

func RailgunCircuitID(nullifiers int, commitments int) CircuitID {
	return CircuitID{
		Name:       fmt.Sprintf("JOINSPLIT_%dX%d", nullifiers, commitments),
		MaxInputs:  nullifiers,
		MaxOutputs: commitments,
	}
}

func GetPublicInputsPOI(
	anyRailgunTxidMerklerootAfterTransaction string,
	blindedCommitmentsOut []string,
	poiMerkleroots []string,
	railgunTxidIfHasUnshield string,
	maxInputs int,
	maxOutputs int,
) (PublicInputsPOI, error) {
	anyMerkleroot, err := ParseHexBigInt(anyRailgunTxidMerklerootAfterTransaction)
	if err != nil {
		return PublicInputsPOI{}, fmt.Errorf("anyRailgunTxidMerklerootAfterTransaction: %w", err)
	}
	blindedOut, err := parseHexSlice(blindedCommitmentsOut)
	if err != nil {
		return PublicInputsPOI{}, fmt.Errorf("blindedCommitmentsOut: %w", err)
	}
	poiRoots, err := parseHexSlice(poiMerkleroots)
	if err != nil {
		return PublicInputsPOI{}, fmt.Errorf("poiMerkleroots: %w", err)
	}
	txidIfUnshield, err := ParseHexBigInt(railgunTxidIfHasUnshield)
	if err != nil {
		return PublicInputsPOI{}, fmt.Errorf("railgunTxidIfHasUnshield: %w", err)
	}

	return PublicInputsPOI{
		AnyRailgunTxidMerklerootAfterTransaction: anyMerkleroot,
		BlindedCommitmentsOut:                    padBigIntsToMax(blindedOut, maxOutputs, ZeroValue),
		POIMerkleRoots:                           padBigIntsToMax(poiRoots, maxInputs, MerkleZeroValue),
		RailgunTxidIfHasUnshield:                 txidIfUnshield,
	}, nil
}

func FormatPOIInputs(proofInputs POIEngineProofInputs, maxInputs int, maxOutputs int) (FormattedCircuitInputsPOI, error) {
	anyMerkleroot, err := ParseHexBigInt(proofInputs.AnyRailgunTxidMerklerootAfterTransaction)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("anyRailgunTxidMerklerootAfterTransaction: %w", err)
	}
	boundParamsHash, err := ParseHexBigInt(proofInputs.BoundParamsHash)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("boundParamsHash: %w", err)
	}
	nullifiers, err := parseHexSlice(proofInputs.Nullifiers)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("nullifiers: %w", err)
	}
	commitmentsOut, err := parseHexSlice(proofInputs.CommitmentsOut)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("commitmentsOut: %w", err)
	}
	nullifyingKey, err := cloneRequiredBigInt(proofInputs.NullifyingKey, "nullifyingKey")
	if err != nil {
		return FormattedCircuitInputsPOI{}, err
	}
	token, err := ParseHexBigInt(proofInputs.Token)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("token: %w", err)
	}
	randomsIn, err := parseHexSlice(proofInputs.RandomsIn)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("randomsIn: %w", err)
	}
	utxoPositionsIn := make([]*big.Int, len(proofInputs.UTXOPositionsIn))
	for i, position := range proofInputs.UTXOPositionsIn {
		utxoPositionsIn[i] = new(big.Int).SetUint64(position)
	}
	railgunTxidIfHasUnshield, err := ParseNumberishBigInt(proofInputs.RailgunTxidIfHasUnshield)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("railgunTxidIfHasUnshield: %w", err)
	}
	railgunProofIndices, err := ParseHexBigInt(proofInputs.RailgunTxidMerkleProofIndices)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("railgunTxidMerkleProofIndices: %w", err)
	}
	railgunPathElements, err := parseHexSlice(proofInputs.RailgunTxidMerkleProofPathElements)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("railgunTxidMerkleProofPathElements: %w", err)
	}
	poiRoots, err := parseHexSlice(proofInputs.POIMerkleRoots)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("poiMerkleroots: %w", err)
	}
	poiProofIndices, err := parseHexSlice(proofInputs.POIInMerkleProofIndices)
	if err != nil {
		return FormattedCircuitInputsPOI{}, fmt.Errorf("poiInMerkleProofIndices: %w", err)
	}
	poiPathElements := make([][]*big.Int, len(proofInputs.POIInMerkleProofPathElements))
	for i, pathElements := range proofInputs.POIInMerkleProofPathElements {
		poiPathElements[i], err = parseHexSlice(pathElements)
		if err != nil {
			return FormattedCircuitInputsPOI{}, fmt.Errorf("poiInMerkleProofPathElements[%d]: %w", i, err)
		}
	}

	spendingPublicKey0, err := cloneRequiredBigInt(proofInputs.SpendingPublicKey[0], "spendingPublicKey[0]")
	if err != nil {
		return FormattedCircuitInputsPOI{}, err
	}
	spendingPublicKey1, err := cloneRequiredBigInt(proofInputs.SpendingPublicKey[1], "spendingPublicKey[1]")
	if err != nil {
		return FormattedCircuitInputsPOI{}, err
	}
	batchStart, err := cloneRequiredBigInt(proofInputs.UTXOBatchGlobalStartPositionOut, "utxoBatchGlobalStartPositionOut")
	if err != nil {
		return FormattedCircuitInputsPOI{}, err
	}

	return FormattedCircuitInputsPOI{
		AnyRailgunTxidMerklerootAfterTransaction: anyMerkleroot,
		BoundParamsHash:                          boundParamsHash,
		Nullifiers:                               padBigIntsToMax(nullifiers, maxInputs, MerkleZeroValue),
		CommitmentsOut:                           padBigIntsToMax(commitmentsOut, maxOutputs, MerkleZeroValue),
		SpendingPublicKey:                        [2]*big.Int{spendingPublicKey0, spendingPublicKey1},
		NullifyingKey:                            nullifyingKey,
		Token:                                    token,
		RandomsIn:                                padBigIntsToMax(randomsIn, maxInputs, MerkleZeroValue),
		ValuesIn:                                 padBigIntsToMax(proofInputs.ValuesIn, maxOutputs, ZeroValue),
		UTXOPositionsIn:                          padBigIntsToMax(utxoPositionsIn, maxInputs, MerkleZeroValue),
		UTXOTreeIn:                               new(big.Int).SetUint64(proofInputs.UTXOTreeIn),
		NPKsOut:                                  padBigIntsToMax(proofInputs.NPKsOut, maxOutputs, MerkleZeroValue),
		ValuesOut:                                padBigIntsToMax(proofInputs.ValuesOut, maxOutputs, ZeroValue),
		UTXOBatchGlobalStartPositionOut:          batchStart,
		RailgunTxidIfHasUnshield:                 railgunTxidIfHasUnshield,
		RailgunTxidMerkleProofIndices:            railgunProofIndices,
		RailgunTxidMerkleProofPathElements:       railgunPathElements,
		POIMerkleRoots:                           padBigIntsToMax(poiRoots, maxInputs, MerkleZeroValue),
		POIInMerkleProofIndices:                  padBigIntsToMax(poiProofIndices, maxInputs, ZeroValue),
		POIInMerkleProofPathElements:             padBigIntRowsToMaxAndLength(poiPathElements, maxInputs, defaultPOIPathLength, MerkleZeroValue),
	}, nil
}

func (inputs FormattedCircuitInputsPOI) NativeInputs() NativeFormattedCircuitInputsPOI {
	return NativeFormattedCircuitInputsPOI{
		AnyRailgunTxidMerklerootAfterTransaction: inputs.AnyRailgunTxidMerklerootAfterTransaction.String(),
		POIMerkleRoots:                           bigIntStrings(inputs.POIMerkleRoots),
		BoundParamsHash:                          inputs.BoundParamsHash.String(),
		Nullifiers:                               bigIntStrings(inputs.Nullifiers),
		CommitmentsOut:                           bigIntStrings(inputs.CommitmentsOut),
		SpendingPublicKey:                        [2]string{inputs.SpendingPublicKey[0].String(), inputs.SpendingPublicKey[1].String()},
		NullifyingKey:                            inputs.NullifyingKey.String(),
		Token:                                    inputs.Token.String(),
		RandomsIn:                                bigIntStrings(inputs.RandomsIn),
		ValuesIn:                                 bigIntStrings(inputs.ValuesIn),
		UTXOPositionsIn:                          bigIntStrings(inputs.UTXOPositionsIn),
		UTXOTreeIn:                               inputs.UTXOTreeIn.String(),
		NPKsOut:                                  bigIntStrings(inputs.NPKsOut),
		ValuesOut:                                bigIntStrings(inputs.ValuesOut),
		UTXOBatchGlobalStartPositionOut:          inputs.UTXOBatchGlobalStartPositionOut.String(),
		RailgunTxidIfHasUnshield:                 inputs.RailgunTxidIfHasUnshield.String(),
		RailgunTxidMerkleProofIndices:            inputs.RailgunTxidMerkleProofIndices.String(),
		RailgunTxidMerkleProofPathElements:       bigIntStrings(inputs.RailgunTxidMerkleProofPathElements),
		POIInMerkleProofIndices:                  bigIntStrings(inputs.POIInMerkleProofIndices),
		POIInMerkleProofPathElements:             bigIntRowStrings(inputs.POIInMerkleProofPathElements),
	}
}
