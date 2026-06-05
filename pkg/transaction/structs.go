package transaction

import (
	"fmt"
	"math/big"
	"strings"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/proof"
)

const (
	TXIDVersionV2PoseidonMerkle = "V2_PoseidonMerkle"
	TXIDVersionV3PoseidonMerkle = "V3_PoseidonMerkle"
)

type ContractG1Point struct {
	X *big.Int
	Y *big.Int
}

type ContractG2Point struct {
	X [2]*big.Int
	Y [2]*big.Int
}

type ContractSnarkProof struct {
	A ContractG1Point
	B ContractG2Point
	C ContractG1Point
}

type CommitmentPreimage struct {
	NPK   string
	Token railcrypto.TokenData
	Value *big.Int
}

type ShieldCiphertext struct {
	EncryptedBundle [3]string
	ShieldKey       string
}

type ShieldRequest struct {
	Preimage   CommitmentPreimage
	Ciphertext ShieldCiphertext
}

type TransactionStructV2 struct {
	TXIDVersion      string
	Proof            ContractSnarkProof
	MerkleRoot       string
	Nullifiers       []string
	Commitments      []string
	BoundParams      BoundParamsV2
	UnshieldPreimage CommitmentPreimage
}

type TransactionStructV3 struct {
	TXIDVersion      string
	Proof            ContractSnarkProof
	MerkleRoot       string
	Nullifiers       []string
	Commitments      []string
	BoundParams      BoundParamsV3
	UnshieldPreimage CommitmentPreimage
}

type NativeTransactionStructV2 struct {
	TXIDVersion      string                   `json:"txidVersion"`
	Proof            NativeSnarkProof         `json:"proof"`
	MerkleRoot       string                   `json:"merkleRoot"`
	Nullifiers       []string                 `json:"nullifiers"`
	BoundParams      NativeBoundParamsV2      `json:"boundParams"`
	Commitments      []string                 `json:"commitments"`
	UnshieldPreimage NativeCommitmentPreimage `json:"unshieldPreimage"`
}

type NativeTransactionStructV3 struct {
	TXIDVersion      string                   `json:"txidVersion"`
	Proof            NativeSnarkProof         `json:"proof"`
	MerkleRoot       string                   `json:"merkleRoot"`
	Nullifiers       []string                 `json:"nullifiers"`
	BoundParams      NativeBoundParamsV3      `json:"boundParams"`
	Commitments      []string                 `json:"commitments"`
	UnshieldPreimage NativeCommitmentPreimage `json:"unshieldPreimage"`
}

type NativeG1Point struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type NativeG2Point struct {
	X [2]string `json:"x"`
	Y [2]string `json:"y"`
}

type NativeSnarkProof struct {
	A NativeG1Point `json:"a"`
	B NativeG2Point `json:"b"`
	C NativeG1Point `json:"c"`
}

type NativeCommitmentPreimage struct {
	NPK   string               `json:"npk"`
	Token railcrypto.TokenData `json:"token"`
	Value string               `json:"value"`
}

type NativeShieldCiphertext struct {
	EncryptedBundle [3]string `json:"encryptedBundle"`
	ShieldKey       string    `json:"shieldKey"`
}

type NativeShieldRequest struct {
	Preimage   NativeCommitmentPreimage `json:"preimage"`
	Ciphertext NativeShieldCiphertext   `json:"ciphertext"`
}

type NativeBoundParamsV2 struct {
	TreeNumber           string                         `json:"treeNumber"`
	MinGasPrice          string                         `json:"minGasPrice"`
	Unshield             string                         `json:"unshield"`
	ChainID              string                         `json:"chainID"`
	AdaptContract        string                         `json:"adaptContract"`
	AdaptParams          string                         `json:"adaptParams"`
	CommitmentCiphertext []NativeCommitmentCiphertextV2 `json:"commitmentCiphertext"`
}

type NativeCommitmentCiphertextV2 struct {
	Ciphertext                [4]string `json:"ciphertext"`
	BlindedSenderViewingKey   string    `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string    `json:"blindedReceiverViewingKey"`
	AnnotationData            string    `json:"annotationData"`
	Memo                      string    `json:"memo"`
}

type NativeBoundParamsV3 struct {
	Local  NativeLocalBoundParamsV3  `json:"local"`
	Global NativeGlobalBoundParamsV3 `json:"global"`
}

type NativeLocalBoundParamsV3 struct {
	TreeNumber           string                         `json:"treeNumber"`
	CommitmentCiphertext []NativeCommitmentCiphertextV3 `json:"commitmentCiphertext"`
}

type NativeCommitmentCiphertextV3 struct {
	Ciphertext                string `json:"ciphertext"`
	BlindedSenderViewingKey   string `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string `json:"blindedReceiverViewingKey"`
}

type NativeGlobalBoundParamsV3 struct {
	MinGasPrice      string `json:"minGasPrice"`
	ChainID          string `json:"chainID"`
	SenderCiphertext string `json:"senderCiphertext"`
	To               string `json:"to"`
	Data             string `json:"data"`
}

func CreateTransactionStructV2(snarkProof proof.Proof, publicInputs proof.PublicInputsRailgun, boundParams BoundParamsV2, unshieldPreimage CommitmentPreimage) (TransactionStructV2, error) {
	contractProof, err := FormatContractProof(snarkProof)
	if err != nil {
		return TransactionStructV2{}, err
	}
	merkleRoot, err := requiredBigIntHex(publicInputs.MerkleRoot, "merkleRoot")
	if err != nil {
		return TransactionStructV2{}, err
	}
	nullifiers, err := requiredBigIntHexSlice(publicInputs.Nullifiers, "nullifiers")
	if err != nil {
		return TransactionStructV2{}, err
	}
	commitments, err := requiredBigIntHexSlice(publicInputs.CommitmentsOut, "commitmentsOut")
	if err != nil {
		return TransactionStructV2{}, err
	}
	formattedPreimage, err := formatCommitmentPreimage(unshieldPreimage)
	if err != nil {
		return TransactionStructV2{}, err
	}
	return TransactionStructV2{
		TXIDVersion:      TXIDVersionV2PoseidonMerkle,
		Proof:            contractProof,
		MerkleRoot:       merkleRoot,
		Nullifiers:       nullifiers,
		BoundParams:      boundParams,
		Commitments:      commitments,
		UnshieldPreimage: formattedPreimage,
	}, nil
}

func CreateTransactionStructV3(snarkProof proof.Proof, publicInputs proof.PublicInputsRailgun, boundParams BoundParamsV3, unshieldPreimage CommitmentPreimage) (TransactionStructV3, error) {
	contractProof, err := FormatContractProof(snarkProof)
	if err != nil {
		return TransactionStructV3{}, err
	}
	merkleRoot, err := requiredBigIntHex(publicInputs.MerkleRoot, "merkleRoot")
	if err != nil {
		return TransactionStructV3{}, err
	}
	nullifiers, err := requiredBigIntHexSlice(publicInputs.Nullifiers, "nullifiers")
	if err != nil {
		return TransactionStructV3{}, err
	}
	commitments, err := requiredBigIntHexSlice(publicInputs.CommitmentsOut, "commitmentsOut")
	if err != nil {
		return TransactionStructV3{}, err
	}
	formattedPreimage, err := formatCommitmentPreimage(unshieldPreimage)
	if err != nil {
		return TransactionStructV3{}, err
	}
	return TransactionStructV3{
		TXIDVersion:      TXIDVersionV3PoseidonMerkle,
		Proof:            contractProof,
		MerkleRoot:       merkleRoot,
		Nullifiers:       nullifiers,
		BoundParams:      boundParams,
		Commitments:      commitments,
		UnshieldPreimage: formattedPreimage,
	}, nil
}

func FormatContractProof(snarkProof proof.Proof) (ContractSnarkProof, error) {
	formatted, err := proof.FormatProof(snarkProof)
	if err != nil {
		return ContractSnarkProof{}, err
	}
	return ContractSnarkProof{
		A: ContractG1Point{X: cloneBigInt(formatted.A.X), Y: cloneBigInt(formatted.A.Y)},
		B: ContractG2Point{
			X: [2]*big.Int{cloneBigInt(formatted.B.X[0]), cloneBigInt(formatted.B.X[1])},
			Y: [2]*big.Int{cloneBigInt(formatted.B.Y[0]), cloneBigInt(formatted.B.Y[1])},
		},
		C: ContractG1Point{X: cloneBigInt(formatted.C.X), Y: cloneBigInt(formatted.C.Y)},
	}, nil
}

func (tx TransactionStructV2) Native() NativeTransactionStructV2 {
	return NativeTransactionStructV2{
		TXIDVersion:      tx.TXIDVersion,
		Proof:            tx.Proof.Native(),
		MerkleRoot:       tx.MerkleRoot,
		Nullifiers:       append([]string(nil), tx.Nullifiers...),
		BoundParams:      tx.BoundParams.Native(),
		Commitments:      append([]string(nil), tx.Commitments...),
		UnshieldPreimage: tx.UnshieldPreimage.Native(),
	}
}

func (tx TransactionStructV3) Native() NativeTransactionStructV3 {
	return NativeTransactionStructV3{
		TXIDVersion:      tx.TXIDVersion,
		Proof:            tx.Proof.Native(),
		MerkleRoot:       tx.MerkleRoot,
		Nullifiers:       append([]string(nil), tx.Nullifiers...),
		BoundParams:      tx.BoundParams.Native(),
		Commitments:      append([]string(nil), tx.Commitments...),
		UnshieldPreimage: tx.UnshieldPreimage.Native(),
	}
}

func (snarkProof ContractSnarkProof) Native() NativeSnarkProof {
	return NativeSnarkProof{
		A: NativeG1Point{X: snarkProof.A.X.String(), Y: snarkProof.A.Y.String()},
		B: NativeG2Point{
			X: [2]string{snarkProof.B.X[0].String(), snarkProof.B.X[1].String()},
			Y: [2]string{snarkProof.B.Y[0].String(), snarkProof.B.Y[1].String()},
		},
		C: NativeG1Point{X: snarkProof.C.X.String(), Y: snarkProof.C.Y.String()},
	}
}

func (preimage CommitmentPreimage) Native() NativeCommitmentPreimage {
	value := ""
	if preimage.Value != nil {
		value = preimage.Value.String()
	}
	return NativeCommitmentPreimage{
		NPK:   preimage.NPK,
		Token: preimage.Token,
		Value: value,
	}
}

func (ciphertext ShieldCiphertext) Native() NativeShieldCiphertext {
	return NativeShieldCiphertext{
		EncryptedBundle: ciphertext.EncryptedBundle,
		ShieldKey:       ciphertext.ShieldKey,
	}
}

func (request ShieldRequest) Native() NativeShieldRequest {
	return NativeShieldRequest{
		Preimage:   request.Preimage.Native(),
		Ciphertext: request.Ciphertext.Native(),
	}
}

func (boundParams BoundParamsV2) Native() NativeBoundParamsV2 {
	commitments := make([]NativeCommitmentCiphertextV2, len(boundParams.CommitmentCiphertext))
	for i, ciphertext := range boundParams.CommitmentCiphertext {
		commitments[i] = ciphertext.Native()
	}
	return NativeBoundParamsV2{
		TreeNumber:           fmt.Sprint(boundParams.TreeNumber),
		MinGasPrice:          boundParams.MinGasPrice.String(),
		Unshield:             fmt.Sprint(boundParams.Unshield),
		ChainID:              fmt.Sprint(boundParams.ChainID),
		AdaptContract:        strings.ToLower(boundParams.AdaptContract.Hex()),
		AdaptParams:          bytes32Hex(boundParams.AdaptParams),
		CommitmentCiphertext: commitments,
	}
}

func (ciphertext CommitmentCiphertextV2) Native() NativeCommitmentCiphertextV2 {
	return NativeCommitmentCiphertextV2{
		Ciphertext: [4]string{
			bytes32Hex(ciphertext.Ciphertext[0]),
			bytes32Hex(ciphertext.Ciphertext[1]),
			bytes32Hex(ciphertext.Ciphertext[2]),
			bytes32Hex(ciphertext.Ciphertext[3]),
		},
		BlindedSenderViewingKey:   bytes32Hex(ciphertext.BlindedSenderViewingKey),
		BlindedReceiverViewingKey: bytes32Hex(ciphertext.BlindedReceiverViewingKey),
		AnnotationData:            dynamicBytesHex(ciphertext.AnnotationData),
		Memo:                      dynamicBytesHex(ciphertext.Memo),
	}
}

func (boundParams BoundParamsV3) Native() NativeBoundParamsV3 {
	commitments := make([]NativeCommitmentCiphertextV3, len(boundParams.Local.CommitmentCiphertext))
	for i, ciphertext := range boundParams.Local.CommitmentCiphertext {
		commitments[i] = ciphertext.Native()
	}
	return NativeBoundParamsV3{
		Local: NativeLocalBoundParamsV3{
			TreeNumber:           fmt.Sprint(boundParams.Local.TreeNumber),
			CommitmentCiphertext: commitments,
		},
		Global: NativeGlobalBoundParamsV3{
			MinGasPrice:      boundParams.Global.MinGasPrice.String(),
			ChainID:          boundParams.Global.ChainID.String(),
			SenderCiphertext: dynamicBytesHex(boundParams.Global.SenderCiphertext),
			To:               strings.ToLower(boundParams.Global.To.Hex()),
			Data:             dynamicBytesHex(boundParams.Global.Data),
		},
	}
}

func (ciphertext CommitmentCiphertextV3) Native() NativeCommitmentCiphertextV3 {
	return NativeCommitmentCiphertextV3{
		Ciphertext:                dynamicBytesHex(ciphertext.Ciphertext),
		BlindedSenderViewingKey:   bytes32Hex(ciphertext.BlindedSenderViewingKey),
		BlindedReceiverViewingKey: bytes32Hex(ciphertext.BlindedReceiverViewingKey),
	}
}

func formatCommitmentPreimage(preimage CommitmentPreimage) (CommitmentPreimage, error) {
	npk, err := railcrypto.FormatHexToByteLength(preimage.NPK, 32, true)
	if err != nil {
		return CommitmentPreimage{}, fmt.Errorf("unshieldPreimage.npk: %w", err)
	}
	if preimage.Value == nil {
		return CommitmentPreimage{}, fmt.Errorf("unshieldPreimage.value is required")
	}
	return CommitmentPreimage{
		NPK:   npk,
		Token: preimage.Token,
		Value: cloneBigInt(preimage.Value),
	}, nil
}

func requiredBigIntHex(value *big.Int, name string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("%s is required", name)
	}
	return railcrypto.BigIntToHex(value, 32, true)
}

func requiredBigIntHexSlice(values []*big.Int, name string) ([]string, error) {
	out := make([]string, len(values))
	for i, value := range values {
		hexValue, err := requiredBigIntHex(value, fmt.Sprintf("%s[%d]", name, i))
		if err != nil {
			return nil, err
		}
		out[i] = hexValue
	}
	return out, nil
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func bytes32Hex(value [32]byte) string {
	return "0x" + railcrypto.BytesToHex(value[:], false)
}

func dynamicBytesHex(value []byte) string {
	return "0x" + railcrypto.BytesToHex(value, false)
}
