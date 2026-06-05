package transaction

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/proof"
)

const (
	UnshieldFlagNone     = 0
	UnshieldFlagUnshield = 1
	UnshieldFlagOverride = 2
)

type Chain struct {
	Type int    `json:"type"`
	ID   uint64 `json:"id"`
}

type AdaptID struct {
	Contract string `json:"contract"`
	Params   string `json:"parameters"`
}

type RequestUTXO struct {
	Position            uint64
	NoteRandom          string
	NoteValue           *big.Int
	MerkleProofElements []string
}

type RequestTransactOutput struct {
	ReceiverMasterPublicKey  *big.Int
	ReceiverViewingPublicKey []byte
	Random                   string
	Value                    *big.Int
	TokenData                railcrypto.TokenData
	SenderRandom             string
	OutputType               int
	WalletSource             string
	MemoText                 string
}

type RequestUnshieldOutput struct {
	ToAddress     string
	Value         *big.Int
	TokenData     railcrypto.TokenData
	AllowOverride bool
}

type TransactionRequestInputs struct {
	Chain                   Chain
	SpendingTree            uint32
	MerkleRoot              string
	TokenData               railcrypto.TokenData
	UTXOs                   []RequestUTXO
	Outputs                 []RequestTransactOutput
	UnshieldOutput          *RequestUnshieldOutput
	SpendingPublicKey       [2]*big.Int
	NullifyingKey           *big.Int
	SenderMasterPublicKey   *big.Int
	SenderViewingPrivateKey []byte
	SenderViewingPublicKey  []byte
	AdaptID                 AdaptID
	MinGasPrice             *big.Int
	GlobalBoundParams       GlobalBoundParamsV3
	NoteCiphertextV2IVs     []string
	AnnotationV2IVs         []string
	NoteCiphertextV3Nonces  []string
}

type TransactionRequestV2 struct {
	TXIDVersion   string
	PrivateInputs proof.PrivateInputsRailgun
	PublicInputs  proof.PublicInputsRailgun
	BoundParams   BoundParamsV2
}

type TransactionRequestV3 struct {
	TXIDVersion   string
	PrivateInputs proof.PrivateInputsRailgun
	PublicInputs  proof.PublicInputsRailgun
	BoundParams   BoundParamsV3
}

type NativeTransactionRequestV2 struct {
	TXIDVersion   string                     `json:"txidVersion"`
	PrivateInputs NativePrivateInputsRailgun `json:"privateInputs"`
	PublicInputs  NativePublicInputsRailgun  `json:"publicInputs"`
	BoundParams   NativeBoundParamsV2        `json:"boundParams"`
}

type NativeTransactionRequestV3 struct {
	TXIDVersion   string                     `json:"txidVersion"`
	PrivateInputs NativePrivateInputsRailgun `json:"privateInputs"`
	PublicInputs  NativePublicInputsRailgun  `json:"publicInputs"`
	BoundParams   NativeBoundParamsV3        `json:"boundParams"`
}

type NativePrivateInputsRailgun struct {
	TokenAddress  string     `json:"tokenAddress"`
	PublicKey     [2]string  `json:"publicKey"`
	RandomIn      []string   `json:"randomIn"`
	ValueIn       []string   `json:"valueIn"`
	PathElements  [][]string `json:"pathElements"`
	LeavesIndices []string   `json:"leavesIndices"`
	NullifyingKey string     `json:"nullifyingKey"`
	NPKOut        []string   `json:"npkOut"`
	ValueOut      []string   `json:"valueOut"`
}

type NativePublicInputsRailgun struct {
	MerkleRoot      string   `json:"merkleRoot"`
	BoundParamsHash string   `json:"boundParamsHash"`
	Nullifiers      []string `json:"nullifiers"`
	CommitmentsOut  []string `json:"commitmentsOut"`
}

func GenerateTransactionRequestV2(inputs TransactionRequestInputs) (TransactionRequestV2, error) {
	privateInputs, outputData, err := buildRequestCore(inputs)
	if err != nil {
		return TransactionRequestV2{}, err
	}
	commitmentCiphertext := make([]CommitmentCiphertextV2, len(outputData.InternalOutputs))
	for i, output := range outputData.InternalOutputs {
		if i >= len(inputs.NoteCiphertextV2IVs) {
			return TransactionRequestV2{}, fmt.Errorf("missing V2 note ciphertext IV for output %d", i)
		}
		if i >= len(inputs.AnnotationV2IVs) {
			return TransactionRequestV2{}, fmt.Errorf("missing V2 annotation IV for output %d", i)
		}
		encrypted, err := railcrypto.EncryptTransactNoteV2(output.EncryptionInputs, inputs.NoteCiphertextV2IVs[i], inputs.AnnotationV2IVs[i])
		if err != nil {
			return TransactionRequestV2{}, err
		}
		commitmentCiphertext[i], err = CreateCommitmentCiphertextV2(encrypted, output.BlindedSenderViewingKey, output.BlindedReceiverViewingKey)
		if err != nil {
			return TransactionRequestV2{}, err
		}
	}
	adaptContract, err := AddressFromHex(inputs.AdaptID.Contract)
	if err != nil {
		return TransactionRequestV2{}, fmt.Errorf("adapt contract: %w", err)
	}
	adaptParams, err := Bytes32FromHex(inputs.AdaptID.Params)
	if err != nil {
		return TransactionRequestV2{}, fmt.Errorf("adapt params: %w", err)
	}
	chainID, err := chainFullNetworkID(inputs.Chain)
	if err != nil {
		return TransactionRequestV2{}, err
	}
	boundParams := BoundParamsV2{
		TreeNumber:           uint16(inputs.SpendingTree),
		MinGasPrice:          cloneBigInt(defaultBigInt(inputs.MinGasPrice)),
		Unshield:             outputData.UnshieldFlag,
		ChainID:              chainID,
		AdaptContract:        adaptContract,
		AdaptParams:          adaptParams,
		CommitmentCiphertext: commitmentCiphertext,
	}
	boundParamsHash, err := HashBoundParamsV2(boundParams)
	if err != nil {
		return TransactionRequestV2{}, err
	}
	publicInputs, err := buildRequestPublicInputs(inputs.MerkleRoot, boundParamsHash, outputData)
	if err != nil {
		return TransactionRequestV2{}, err
	}
	return TransactionRequestV2{
		TXIDVersion:   TXIDVersionV2PoseidonMerkle,
		PrivateInputs: privateInputs,
		PublicInputs:  publicInputs,
		BoundParams:   boundParams,
	}, nil
}

func GenerateTransactionRequestV3(inputs TransactionRequestInputs) (TransactionRequestV3, error) {
	privateInputs, outputData, err := buildRequestCore(inputs)
	if err != nil {
		return TransactionRequestV3{}, err
	}
	commitmentCiphertext := make([]CommitmentCiphertextV3, len(outputData.InternalOutputs))
	for i, output := range outputData.InternalOutputs {
		if i >= len(inputs.NoteCiphertextV3Nonces) {
			return TransactionRequestV3{}, fmt.Errorf("missing V3 note ciphertext nonce for output %d", i)
		}
		ciphertext, err := railcrypto.EncryptTransactNoteV3Ciphertext(output.EncryptionInputs, inputs.NoteCiphertextV3Nonces[i])
		if err != nil {
			return TransactionRequestV3{}, err
		}
		commitmentCiphertext[i], err = CreateCommitmentCiphertextV3(
			railcrypto.TransactNoteV3Encryption{NoteCiphertext: ciphertext},
			output.BlindedSenderViewingKey,
			output.BlindedReceiverViewingKey,
		)
		if err != nil {
			return TransactionRequestV3{}, err
		}
	}
	boundParams := BoundParamsV3{
		Local: LocalBoundParamsV3{
			TreeNumber:           inputs.SpendingTree,
			CommitmentCiphertext: commitmentCiphertext,
		},
		Global: cloneGlobalBoundParams(inputs.GlobalBoundParams),
	}
	if boundParams.Global.MinGasPrice == nil {
		boundParams.Global.MinGasPrice = big.NewInt(0)
	}
	if boundParams.Global.ChainID == nil {
		chainID, err := chainFullNetworkID(inputs.Chain)
		if err != nil {
			return TransactionRequestV3{}, err
		}
		boundParams.Global.ChainID = new(big.Int).SetUint64(chainID)
	}
	boundParamsHash, err := HashBoundParamsV3(boundParams)
	if err != nil {
		return TransactionRequestV3{}, err
	}
	publicInputs, err := buildRequestPublicInputs(inputs.MerkleRoot, boundParamsHash, outputData)
	if err != nil {
		return TransactionRequestV3{}, err
	}
	return TransactionRequestV3{
		TXIDVersion:   TXIDVersionV3PoseidonMerkle,
		PrivateInputs: privateInputs,
		PublicInputs:  publicInputs,
		BoundParams:   boundParams,
	}, nil
}

type internalRequestOutput struct {
	EncryptionInputs          railcrypto.TransactNoteEncryptionInputs
	BlindedSenderViewingKey   []byte
	BlindedReceiverViewingKey []byte
}

type requestOutputData struct {
	InternalOutputs []internalRequestOutput
	Nullifiers      []*big.Int
	ValuesOut       []*big.Int
	NPKOut          []*big.Int
	CommitmentsOut  []*big.Int
	UnshieldFlag    uint8
}

func buildRequestCore(inputs TransactionRequestInputs) (proof.PrivateInputsRailgun, requestOutputData, error) {
	if inputs.NullifyingKey == nil {
		return proof.PrivateInputsRailgun{}, requestOutputData{}, fmt.Errorf("nullifying key is required")
	}
	tokenHash, err := railcrypto.TokenDataHash(inputs.TokenData)
	if err != nil {
		return proof.PrivateInputsRailgun{}, requestOutputData{}, err
	}
	tokenAddress, err := railcrypto.HexToBigInt(tokenHash)
	if err != nil {
		return proof.PrivateInputsRailgun{}, requestOutputData{}, err
	}
	randomIn := make([]*big.Int, len(inputs.UTXOs))
	valueIn := make([]*big.Int, len(inputs.UTXOs))
	pathElements := make([][]*big.Int, len(inputs.UTXOs))
	leavesIndices := make([]*big.Int, len(inputs.UTXOs))
	nullifiers := make([]*big.Int, len(inputs.UTXOs))
	for i, utxo := range inputs.UTXOs {
		randomIn[i], err = railcrypto.HexToBigInt(utxo.NoteRandom)
		if err != nil {
			return proof.PrivateInputsRailgun{}, requestOutputData{}, fmt.Errorf("utxo[%d] random: %w", i, err)
		}
		if utxo.NoteValue == nil {
			return proof.PrivateInputsRailgun{}, requestOutputData{}, fmt.Errorf("utxo[%d] value is required", i)
		}
		valueIn[i] = cloneBigInt(utxo.NoteValue)
		leavesIndices[i] = new(big.Int).SetUint64(utxo.Position)
		nullifiers[i], err = railcrypto.Nullifier(inputs.NullifyingKey, utxo.Position)
		if err != nil {
			return proof.PrivateInputsRailgun{}, requestOutputData{}, err
		}
		pathElements[i] = make([]*big.Int, len(utxo.MerkleProofElements))
		for j, element := range utxo.MerkleProofElements {
			pathElements[i][j], err = railcrypto.HexToBigInt(element)
			if err != nil {
				return proof.PrivateInputsRailgun{}, requestOutputData{}, fmt.Errorf("utxo[%d] path element[%d]: %w", i, j, err)
			}
		}
	}
	outputData, err := buildRequestOutputData(inputs)
	if err != nil {
		return proof.PrivateInputsRailgun{}, requestOutputData{}, err
	}
	outputData.Nullifiers = cloneBigIntSlice(nullifiers)
	return proof.PrivateInputsRailgun{
		TokenAddress:  tokenAddress,
		PublicKey:     [2]*big.Int{cloneBigInt(inputs.SpendingPublicKey[0]), cloneBigInt(inputs.SpendingPublicKey[1])},
		RandomIn:      randomIn,
		ValueIn:       valueIn,
		PathElements:  pathElements,
		LeavesIndices: leavesIndices,
		NullifyingKey: cloneBigInt(inputs.NullifyingKey),
		NPKOut:        cloneBigIntSlice(outputData.NPKOut),
		ValueOut:      cloneBigIntSlice(outputData.ValuesOut),
	}, outputData, nil
}

func buildRequestOutputData(inputs TransactionRequestInputs) (requestOutputData, error) {
	if len(inputs.Outputs) > 5 {
		return requestOutputData{}, fmt.Errorf("cannot create a transaction with >5 outputs")
	}
	data := requestOutputData{
		InternalOutputs: make([]internalRequestOutput, len(inputs.Outputs)),
	}
	for i, output := range inputs.Outputs {
		if output.ReceiverMasterPublicKey == nil {
			return requestOutputData{}, fmt.Errorf("output[%d] receiver master public key is required", i)
		}
		if output.Value == nil {
			return requestOutputData{}, fmt.Errorf("output[%d] value is required", i)
		}
		notePublicKey, err := railcrypto.NotePublicKey(output.ReceiverMasterPublicKey, output.Random)
		if err != nil {
			return requestOutputData{}, err
		}
		noteHash, err := railcrypto.NoteHashFromTokenData(notePublicKey, output.TokenData, output.Value)
		if err != nil {
			return requestOutputData{}, err
		}
		blindedSender, blindedReceiver, err := railcrypto.NoteBlindingKeys(
			inputs.SenderViewingPublicKey,
			output.ReceiverViewingPublicKey,
			output.Random,
			output.SenderRandom,
		)
		if err != nil {
			return requestOutputData{}, err
		}
		sharedKey, err := railcrypto.SharedSymmetricKey(inputs.SenderViewingPrivateKey, blindedReceiver)
		if err != nil {
			return requestOutputData{}, err
		}
		data.InternalOutputs[i] = internalRequestOutput{
			EncryptionInputs: railcrypto.TransactNoteEncryptionInputs{
				ReceiverMasterPublicKey: output.ReceiverMasterPublicKey,
				SenderMasterPublicKey:   inputs.SenderMasterPublicKey,
				Random:                  output.Random,
				Value:                   output.Value,
				TokenData:               output.TokenData,
				SenderRandom:            output.SenderRandom,
				SharedKey:               sharedKey,
				ViewingPrivateKey:       inputs.SenderViewingPrivateKey,
				OutputType:              output.OutputType,
				WalletSource:            output.WalletSource,
				MemoText:                output.MemoText,
			},
			BlindedSenderViewingKey:   blindedSender,
			BlindedReceiverViewingKey: blindedReceiver,
		}
		data.NPKOut = append(data.NPKOut, notePublicKey)
		data.ValuesOut = append(data.ValuesOut, cloneBigInt(output.Value))
		data.CommitmentsOut = append(data.CommitmentsOut, noteHash)
	}
	if inputs.UnshieldOutput != nil {
		if inputs.UnshieldOutput.Value == nil {
			return requestOutputData{}, fmt.Errorf("unshield value is required")
		}
		unshieldHash, err := railcrypto.UnshieldNoteHash(inputs.UnshieldOutput.ToAddress, inputs.UnshieldOutput.TokenData, inputs.UnshieldOutput.Value)
		if err != nil {
			return requestOutputData{}, err
		}
		npk, err := railcrypto.NumberishToBigInt(inputs.UnshieldOutput.ToAddress)
		if err != nil {
			return requestOutputData{}, err
		}
		data.NPKOut = append(data.NPKOut, npk)
		data.ValuesOut = append(data.ValuesOut, cloneBigInt(inputs.UnshieldOutput.Value))
		data.CommitmentsOut = append(data.CommitmentsOut, unshieldHash)
		if inputs.UnshieldOutput.AllowOverride {
			data.UnshieldFlag = UnshieldFlagOverride
		} else {
			data.UnshieldFlag = UnshieldFlagUnshield
		}
	}
	return data, nil
}

func buildRequestPublicInputs(merkleRootHex string, boundParamsHash *big.Int, outputData requestOutputData) (proof.PublicInputsRailgun, error) {
	merkleRoot, err := railcrypto.HexToBigInt(merkleRootHex)
	if err != nil {
		return proof.PublicInputsRailgun{}, err
	}
	return proof.PublicInputsRailgun{
		MerkleRoot:      merkleRoot,
		BoundParamsHash: cloneBigInt(boundParamsHash),
		Nullifiers:      cloneBigIntSlice(outputData.Nullifiers),
		CommitmentsOut:  cloneBigIntSlice(outputData.CommitmentsOut),
	}, nil
}

func (request TransactionRequestV2) Native() NativeTransactionRequestV2 {
	return NativeTransactionRequestV2{
		TXIDVersion:   request.TXIDVersion,
		PrivateInputs: nativePrivateInputs(request.PrivateInputs),
		PublicInputs:  nativePublicInputs(request.PublicInputs),
		BoundParams:   request.BoundParams.Native(),
	}
}

func (request TransactionRequestV3) Native() NativeTransactionRequestV3 {
	return NativeTransactionRequestV3{
		TXIDVersion:   request.TXIDVersion,
		PrivateInputs: nativePrivateInputs(request.PrivateInputs),
		PublicInputs:  nativePublicInputs(request.PublicInputs),
		BoundParams:   request.BoundParams.Native(),
	}
}

func nativePrivateInputs(inputs proof.PrivateInputsRailgun) NativePrivateInputsRailgun {
	return NativePrivateInputsRailgun{
		TokenAddress:  inputs.TokenAddress.String(),
		PublicKey:     [2]string{inputs.PublicKey[0].String(), inputs.PublicKey[1].String()},
		RandomIn:      bigIntStringSlice(inputs.RandomIn),
		ValueIn:       bigIntStringSlice(inputs.ValueIn),
		PathElements:  bigIntStringRows(inputs.PathElements),
		LeavesIndices: bigIntStringSlice(inputs.LeavesIndices),
		NullifyingKey: inputs.NullifyingKey.String(),
		NPKOut:        bigIntStringSlice(inputs.NPKOut),
		ValueOut:      bigIntStringSlice(inputs.ValueOut),
	}
}

func nativePublicInputs(inputs proof.PublicInputsRailgun) NativePublicInputsRailgun {
	return NativePublicInputsRailgun{
		MerkleRoot:      inputs.MerkleRoot.String(),
		BoundParamsHash: inputs.BoundParamsHash.String(),
		Nullifiers:      bigIntStringSlice(inputs.Nullifiers),
		CommitmentsOut:  bigIntStringSlice(inputs.CommitmentsOut),
	}
}

func bigIntStringSlice(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value.String()
	}
	return out
}

func bigIntStringRows(values [][]*big.Int) [][]string {
	out := make([][]string, len(values))
	for i, row := range values {
		out[i] = bigIntStringSlice(row)
	}
	return out
}

func cloneBigIntSlice(values []*big.Int) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = cloneBigInt(value)
	}
	return out
}

func defaultBigInt(value *big.Int) *big.Int {
	if value == nil {
		return big.NewInt(0)
	}
	return value
}

func cloneGlobalBoundParams(value GlobalBoundParamsV3) GlobalBoundParamsV3 {
	return GlobalBoundParamsV3{
		MinGasPrice:      cloneBigInt(value.MinGasPrice),
		ChainID:          cloneBigInt(value.ChainID),
		SenderCiphertext: append([]byte(nil), value.SenderCiphertext...),
		To:               common.BytesToAddress(value.To.Bytes()),
		Data:             append([]byte(nil), value.Data...),
	}
}

func chainFullNetworkID(chain Chain) (uint64, error) {
	return railchain.FullNetworkIDUint64(railchain.Chain{Type: chain.Type, ID: chain.ID})
}
