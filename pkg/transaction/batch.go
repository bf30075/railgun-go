package transaction

import (
	"context"
	"fmt"
	"math/big"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

type BatchWallet struct {
	MasterPublicKey   *big.Int
	ViewingPrivateKey []byte
	ViewingPublicKey  []byte
	SpendingPublicKey [2]*big.Int
	NullifyingKey     *big.Int
	WalletSource      string
}

type BatchUTXO struct {
	Position            uint64
	NoteRandom          string
	Value               *big.Int
	MerkleProofElements []string
}

type DummyTransactionGroup struct {
	SpendingTree   uint32
	MerkleRoot     string
	TokenData      railcrypto.TokenData
	UTXOs          []BatchUTXO
	Outputs        []RequestTransactOutput
	UnshieldOutput *RequestUnshieldOutput
}

type DummyTransactionBatchInputs struct {
	Chain                   Chain
	OverallBatchMinGasPrice *big.Int
	AdaptID                 AdaptID
	Wallet                  BatchWallet
	Groups                  []DummyTransactionGroup
	GlobalBoundParams       GlobalBoundParamsV3
	NoteCiphertextV2IVs     [][]string
	AnnotationV2IVs         [][]string
	NoteCiphertextV3Nonces  [][]string
	ChangeRandoms           []string
}

type UnprovedTransactionV2 struct {
	Request          TransactionRequestV2
	Signature        [3]*big.Int
	UnshieldPreimage CommitmentPreimage
}

type UnprovedTransactionV3 struct {
	Request          TransactionRequestV3
	Signature        [3]*big.Int
	UnshieldPreimage CommitmentPreimage
}

func GenerateUnprovedTransactionsV2(inputs DummyTransactionBatchInputs, spendingPrivateKey []byte) ([]UnprovedTransactionV2, error) {
	txs := make([]UnprovedTransactionV2, len(inputs.Groups))
	for i, group := range inputs.Groups {
		requestInputs, err := requestInputsForDummyGroup(inputs, group, i)
		if err != nil {
			return nil, err
		}
		requestInputs.MinGasPrice = cloneBigInt(defaultBigInt(inputs.OverallBatchMinGasPrice))
		if i < len(inputs.NoteCiphertextV2IVs) {
			requestInputs.NoteCiphertextV2IVs = cloneStringSlice(inputs.NoteCiphertextV2IVs[i])
		}
		if i < len(inputs.AnnotationV2IVs) {
			requestInputs.AnnotationV2IVs = cloneStringSlice(inputs.AnnotationV2IVs[i])
		}
		request, err := GenerateTransactionRequestV2(requestInputs)
		if err != nil {
			return nil, err
		}
		signature, err := signRequestPublicInputs(spendingPrivateKey, request.PublicInputs)
		if err != nil {
			return nil, err
		}
		txs[i] = UnprovedTransactionV2{
			Request:          request,
			Signature:        signature,
			UnshieldPreimage: unshieldPreimageFromGroup(group),
		}
	}
	return txs, nil
}

func GenerateUnprovedTransactionsV3(inputs DummyTransactionBatchInputs, spendingPrivateKey []byte) ([]UnprovedTransactionV3, error) {
	txs := make([]UnprovedTransactionV3, len(inputs.Groups))
	for i, group := range inputs.Groups {
		requestInputs, err := requestInputsForDummyGroup(inputs, group, i)
		if err != nil {
			return nil, err
		}
		requestInputs.GlobalBoundParams = globalBoundParamsForDummyBatch(inputs)
		if i < len(inputs.NoteCiphertextV3Nonces) {
			requestInputs.NoteCiphertextV3Nonces = cloneStringSlice(inputs.NoteCiphertextV3Nonces[i])
		}
		request, err := GenerateTransactionRequestV3(requestInputs)
		if err != nil {
			return nil, err
		}
		signature, err := signRequestPublicInputs(spendingPrivateKey, request.PublicInputs)
		if err != nil {
			return nil, err
		}
		txs[i] = UnprovedTransactionV3{
			Request:          request,
			Signature:        signature,
			UnshieldPreimage: unshieldPreimageFromGroup(group),
		}
	}
	return txs, nil
}

func (tx UnprovedTransactionV2) ProofInputs() railproof.UnprovedTransactionInputs {
	return railproof.UnprovedTransactionInputs{
		PublicInputs:  tx.Request.PublicInputs,
		PrivateInputs: tx.Request.PrivateInputs,
		Signature:     cloneSignature(tx.Signature),
	}
}

func (tx UnprovedTransactionV3) ProofInputs() railproof.UnprovedTransactionInputs {
	return railproof.UnprovedTransactionInputs{
		PublicInputs:  tx.Request.PublicInputs,
		PrivateInputs: tx.Request.PrivateInputs,
		Signature:     cloneSignature(tx.Signature),
	}
}

func ProveUnprovedTransactionsV2(ctx context.Context, prover *railproof.Prover, unproved []UnprovedTransactionV2, progress railproof.ProgressCallback) ([]TransactionStructV2, error) {
	txs := make([]TransactionStructV2, len(unproved))
	for i, tx := range unproved {
		proved, err := ProveUnprovedTransactionV2(ctx, prover, tx, progress)
		if err != nil {
			return nil, fmt.Errorf("transaction[%d]: %w", i, err)
		}
		txs[i] = proved
	}
	return txs, nil
}

func ProveUnprovedTransactionsV3(ctx context.Context, prover *railproof.Prover, unproved []UnprovedTransactionV3, progress railproof.ProgressCallback) ([]TransactionStructV3, error) {
	txs := make([]TransactionStructV3, len(unproved))
	for i, tx := range unproved {
		proved, err := ProveUnprovedTransactionV3(ctx, prover, tx, progress)
		if err != nil {
			return nil, fmt.Errorf("transaction[%d]: %w", i, err)
		}
		txs[i] = proved
	}
	return txs, nil
}

func GenerateProvedTransactionsV2(ctx context.Context, prover *railproof.Prover, inputs DummyTransactionBatchInputs, spendingPrivateKey []byte, progress railproof.ProgressCallback) ([]TransactionStructV2, error) {
	unproved, err := GenerateUnprovedTransactionsV2(inputs, spendingPrivateKey)
	if err != nil {
		return nil, err
	}
	return ProveUnprovedTransactionsV2(ctx, prover, unproved, progress)
}

func GenerateProvedTransactionsV3(ctx context.Context, prover *railproof.Prover, inputs DummyTransactionBatchInputs, spendingPrivateKey []byte, progress railproof.ProgressCallback) ([]TransactionStructV3, error) {
	unproved, err := GenerateUnprovedTransactionsV3(inputs, spendingPrivateKey)
	if err != nil {
		return nil, err
	}
	return ProveUnprovedTransactionsV3(ctx, prover, unproved, progress)
}

func GenerateDummyTransactionsV2(inputs DummyTransactionBatchInputs) ([]TransactionStructV2, error) {
	txs := make([]TransactionStructV2, len(inputs.Groups))
	for i, group := range inputs.Groups {
		requestInputs, err := requestInputsForDummyGroup(inputs, group, i)
		if err != nil {
			return nil, err
		}
		requestInputs.MinGasPrice = cloneBigInt(defaultBigInt(inputs.OverallBatchMinGasPrice))
		if i < len(inputs.NoteCiphertextV2IVs) {
			requestInputs.NoteCiphertextV2IVs = cloneStringSlice(inputs.NoteCiphertextV2IVs[i])
		}
		if i < len(inputs.AnnotationV2IVs) {
			requestInputs.AnnotationV2IVs = cloneStringSlice(inputs.AnnotationV2IVs[i])
		}
		request, err := GenerateTransactionRequestV2(requestInputs)
		if err != nil {
			return nil, err
		}
		tx, err := CreateDummyProvedTransactionV2WithUnshield(request, unshieldPreimageFromGroup(group))
		if err != nil {
			return nil, err
		}
		txs[i] = tx
	}
	return txs, nil
}

func GenerateDummyTransactionsV3(inputs DummyTransactionBatchInputs) ([]TransactionStructV3, error) {
	txs := make([]TransactionStructV3, len(inputs.Groups))
	for i, group := range inputs.Groups {
		requestInputs, err := requestInputsForDummyGroup(inputs, group, i)
		if err != nil {
			return nil, err
		}
		requestInputs.GlobalBoundParams = globalBoundParamsForDummyBatch(inputs)
		if i < len(inputs.NoteCiphertextV3Nonces) {
			requestInputs.NoteCiphertextV3Nonces = cloneStringSlice(inputs.NoteCiphertextV3Nonces[i])
		}
		request, err := GenerateTransactionRequestV3(requestInputs)
		if err != nil {
			return nil, err
		}
		tx, err := CreateDummyProvedTransactionV3WithUnshield(request, unshieldPreimageFromGroup(group))
		if err != nil {
			return nil, err
		}
		txs[i] = tx
	}
	return txs, nil
}

func signRequestPublicInputs(privateKey []byte, publicInputs railproof.PublicInputsRailgun) ([3]*big.Int, error) {
	signature, err := railproof.SignPublicInputsRailgun(privateKey, publicInputs)
	if err != nil {
		return [3]*big.Int{}, err
	}
	return [3]*big.Int{
		cloneBigInt(signature.R8[0]),
		cloneBigInt(signature.R8[1]),
		cloneBigInt(signature.S),
	}, nil
}

func cloneSignature(signature [3]*big.Int) [3]*big.Int {
	return [3]*big.Int{
		cloneBigInt(signature[0]),
		cloneBigInt(signature[1]),
		cloneBigInt(signature[2]),
	}
}

func requestInputsForDummyGroup(inputs DummyTransactionBatchInputs, group DummyTransactionGroup, index int) (TransactionRequestInputs, error) {
	outputs := cloneRequestOutputs(group.Outputs)
	changeOutput, err := changeOutputForDummyGroup(inputs, group, index)
	if err != nil {
		return TransactionRequestInputs{}, err
	}
	if changeOutput != nil {
		outputs = append(outputs, *changeOutput)
	}
	utxos := make([]RequestUTXO, len(group.UTXOs))
	for i, utxo := range group.UTXOs {
		if utxo.Value == nil {
			return TransactionRequestInputs{}, fmt.Errorf("group[%d] utxo[%d] value is required", index, i)
		}
		utxos[i] = RequestUTXO{
			Position:            utxo.Position,
			NoteRandom:          utxo.NoteRandom,
			NoteValue:           cloneBigInt(utxo.Value),
			MerkleProofElements: cloneStringSlice(utxo.MerkleProofElements),
		}
	}
	return TransactionRequestInputs{
		Chain:                   inputs.Chain,
		SpendingTree:            group.SpendingTree,
		MerkleRoot:              group.MerkleRoot,
		TokenData:               group.TokenData,
		UTXOs:                   utxos,
		Outputs:                 outputs,
		UnshieldOutput:          cloneUnshieldOutput(group.UnshieldOutput),
		SpendingPublicKey:       [2]*big.Int{cloneBigInt(inputs.Wallet.SpendingPublicKey[0]), cloneBigInt(inputs.Wallet.SpendingPublicKey[1])},
		NullifyingKey:           cloneBigInt(inputs.Wallet.NullifyingKey),
		SenderMasterPublicKey:   cloneBigInt(inputs.Wallet.MasterPublicKey),
		SenderViewingPrivateKey: append([]byte(nil), inputs.Wallet.ViewingPrivateKey...),
		SenderViewingPublicKey:  append([]byte(nil), inputs.Wallet.ViewingPublicKey...),
		AdaptID:                 defaultAdaptID(inputs.AdaptID),
	}, nil
}

func changeOutputForDummyGroup(inputs DummyTransactionBatchInputs, group DummyTransactionGroup, index int) (*RequestTransactOutput, error) {
	change, err := dummyGroupChangeValue(group)
	if err != nil {
		return nil, err
	}
	if change.Sign() == 0 {
		return nil, nil
	}
	if index >= len(inputs.ChangeRandoms) || inputs.ChangeRandoms[index] == "" {
		return nil, fmt.Errorf("missing change random for group %d", index)
	}
	return &RequestTransactOutput{
		ReceiverMasterPublicKey:  cloneBigInt(inputs.Wallet.MasterPublicKey),
		ReceiverViewingPublicKey: append([]byte(nil), inputs.Wallet.ViewingPublicKey...),
		Random:                   inputs.ChangeRandoms[index],
		Value:                    change,
		TokenData:                group.TokenData,
		SenderRandom:             railcrypto.MemoSenderRandomNull,
		OutputType:               railcrypto.OutputTypeChange,
		WalletSource:             inputs.Wallet.WalletSource,
	}, nil
}

func dummyGroupChangeValue(group DummyTransactionGroup) (*big.Int, error) {
	totalIn := big.NewInt(0)
	for _, utxo := range group.UTXOs {
		if utxo.Value != nil {
			totalIn.Add(totalIn, utxo.Value)
		}
	}
	totalOut := big.NewInt(0)
	for _, output := range group.Outputs {
		if output.Value != nil {
			totalOut.Add(totalOut, output.Value)
		}
	}
	if group.UnshieldOutput != nil && group.UnshieldOutput.Value != nil {
		totalOut.Add(totalOut, group.UnshieldOutput.Value)
	}
	change := new(big.Int).Sub(totalIn, totalOut)
	if change.Sign() < 0 {
		return nil, fmt.Errorf("negative change value - transaction not possible")
	}
	return change, nil
}

func globalBoundParamsForDummyBatch(inputs DummyTransactionBatchInputs) GlobalBoundParamsV3 {
	params := cloneGlobalBoundParams(inputs.GlobalBoundParams)
	if params.MinGasPrice == nil {
		params.MinGasPrice = cloneBigInt(defaultBigInt(inputs.OverallBatchMinGasPrice))
	}
	if params.ChainID == nil {
		params.ChainID = new(big.Int).SetUint64(inputs.Chain.ID)
	}
	return params
}

func unshieldPreimageFromGroup(group DummyTransactionGroup) CommitmentPreimage {
	if group.UnshieldOutput == nil {
		return EmptyUnshieldPreimage()
	}
	return CommitmentPreimage{
		NPK:   group.UnshieldOutput.ToAddress,
		Token: group.UnshieldOutput.TokenData,
		Value: cloneBigInt(defaultBigInt(group.UnshieldOutput.Value)),
	}
}

func defaultAdaptID(adaptID AdaptID) AdaptID {
	if adaptID.Contract == "" {
		adaptID.Contract = zeroAddress
	}
	if adaptID.Params == "" {
		adaptID.Params = "0x00"
	}
	return adaptID
}

func cloneRequestOutputs(outputs []RequestTransactOutput) []RequestTransactOutput {
	out := make([]RequestTransactOutput, len(outputs))
	for i, output := range outputs {
		out[i] = RequestTransactOutput{
			ReceiverMasterPublicKey:  cloneBigInt(output.ReceiverMasterPublicKey),
			ReceiverViewingPublicKey: append([]byte(nil), output.ReceiverViewingPublicKey...),
			Random:                   output.Random,
			Value:                    cloneBigInt(output.Value),
			TokenData:                output.TokenData,
			SenderRandom:             output.SenderRandom,
			OutputType:               output.OutputType,
			WalletSource:             output.WalletSource,
			MemoText:                 output.MemoText,
		}
	}
	return out
}

func cloneUnshieldOutput(output *RequestUnshieldOutput) *RequestUnshieldOutput {
	if output == nil {
		return nil
	}
	return &RequestUnshieldOutput{
		ToAddress:     output.ToAddress,
		Value:         cloneBigInt(output.Value),
		TokenData:     output.TokenData,
		AllowOverride: output.AllowOverride,
	}
}

func cloneStringSlice(values []string) []string {
	return append([]string(nil), values...)
}
