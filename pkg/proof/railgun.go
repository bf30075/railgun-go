package proof

import (
	"fmt"
	"math/big"
)

func FormatRailgunInputs(transactionInputs UnprovedTransactionInputs) (FormattedCircuitInputsRailgun, error) {
	merkleRoot, err := cloneRequiredBigInt(transactionInputs.PublicInputs.MerkleRoot, "publicInputs.merkleRoot")
	if err != nil {
		return FormattedCircuitInputsRailgun{}, err
	}
	boundParamsHash, err := cloneRequiredBigInt(transactionInputs.PublicInputs.BoundParamsHash, "publicInputs.boundParamsHash")
	if err != nil {
		return FormattedCircuitInputsRailgun{}, err
	}
	token, err := cloneRequiredBigInt(transactionInputs.PrivateInputs.TokenAddress, "privateInputs.tokenAddress")
	if err != nil {
		return FormattedCircuitInputsRailgun{}, err
	}
	nullifyingKey, err := cloneRequiredBigInt(transactionInputs.PrivateInputs.NullifyingKey, "privateInputs.nullifyingKey")
	if err != nil {
		return FormattedCircuitInputsRailgun{}, err
	}

	publicKey := make([]*big.Int, len(transactionInputs.PrivateInputs.PublicKey))
	for i, value := range transactionInputs.PrivateInputs.PublicKey {
		publicKey[i], err = cloneRequiredBigInt(value, fmt.Sprintf("privateInputs.publicKey[%d]", i))
		if err != nil {
			return FormattedCircuitInputsRailgun{}, err
		}
	}

	signature := make([]*big.Int, len(transactionInputs.Signature))
	for i, value := range transactionInputs.Signature {
		signature[i], err = cloneRequiredBigInt(value, fmt.Sprintf("signature[%d]", i))
		if err != nil {
			return FormattedCircuitInputsRailgun{}, err
		}
	}

	pathElements := make([]*big.Int, 0)
	for _, row := range transactionInputs.PrivateInputs.PathElements {
		pathElements = append(pathElements, cloneBigIntSlice(row)...)
	}

	return FormattedCircuitInputsRailgun{
		MerkleRoot:      merkleRoot,
		BoundParamsHash: boundParamsHash,
		Nullifiers:      cloneBigIntSlice(transactionInputs.PublicInputs.Nullifiers),
		CommitmentsOut:  cloneBigIntSlice(transactionInputs.PublicInputs.CommitmentsOut),
		Token:           token,
		PublicKey:       publicKey,
		Signature:       signature,
		RandomIn:        cloneBigIntSlice(transactionInputs.PrivateInputs.RandomIn),
		ValueIn:         cloneBigIntSlice(transactionInputs.PrivateInputs.ValueIn),
		PathElements:    pathElements,
		LeavesIndices:   cloneBigIntSlice(transactionInputs.PrivateInputs.LeavesIndices),
		NullifyingKey:   nullifyingKey,
		NPKOut:          cloneBigIntSlice(transactionInputs.PrivateInputs.NPKOut),
		ValueOut:        cloneBigIntSlice(transactionInputs.PrivateInputs.ValueOut),
	}, nil
}

func (inputs FormattedCircuitInputsRailgun) NativeInputs() NativeFormattedCircuitInputsRailgun {
	return NativeFormattedCircuitInputsRailgun{
		MerkleRoot:      inputs.MerkleRoot.String(),
		BoundParamsHash: inputs.BoundParamsHash.String(),
		Nullifiers:      bigIntStrings(inputs.Nullifiers),
		CommitmentsOut:  bigIntStrings(inputs.CommitmentsOut),
		Token:           inputs.Token.String(),
		PublicKey:       bigIntStrings(inputs.PublicKey),
		Signature:       bigIntStrings(inputs.Signature),
		RandomIn:        bigIntStrings(inputs.RandomIn),
		ValueIn:         bigIntStrings(inputs.ValueIn),
		PathElements:    bigIntStrings(inputs.PathElements),
		LeavesIndices:   bigIntStrings(inputs.LeavesIndices),
		NullifyingKey:   inputs.NullifyingKey.String(),
		NPKOut:          bigIntStrings(inputs.NPKOut),
		ValueOut:        bigIntStrings(inputs.ValueOut),
	}
}
