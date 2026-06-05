package transaction

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

type CommitmentCiphertextV2 struct {
	Ciphertext                [4][32]byte `abi:"ciphertext"`
	BlindedSenderViewingKey   [32]byte    `abi:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey [32]byte    `abi:"blindedReceiverViewingKey"`
	AnnotationData            []byte      `abi:"annotationData"`
	Memo                      []byte      `abi:"memo"`
}

type BoundParamsV2 struct {
	TreeNumber           uint16                   `abi:"treeNumber"`
	MinGasPrice          *big.Int                 `abi:"minGasPrice"`
	Unshield             uint8                    `abi:"unshield"`
	ChainID              uint64                   `abi:"chainID"`
	AdaptContract        common.Address           `abi:"adaptContract"`
	AdaptParams          [32]byte                 `abi:"adaptParams"`
	CommitmentCiphertext []CommitmentCiphertextV2 `abi:"commitmentCiphertext"`
}

type CommitmentCiphertextV3 struct {
	Ciphertext                []byte   `abi:"ciphertext"`
	BlindedSenderViewingKey   [32]byte `abi:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey [32]byte `abi:"blindedReceiverViewingKey"`
}

type LocalBoundParamsV3 struct {
	TreeNumber           uint32                   `abi:"treeNumber"`
	CommitmentCiphertext []CommitmentCiphertextV3 `abi:"commitmentCiphertext"`
}

type GlobalBoundParamsV3 struct {
	MinGasPrice      *big.Int       `abi:"minGasPrice"`
	ChainID          *big.Int       `abi:"chainID"`
	SenderCiphertext []byte         `abi:"senderCiphertext"`
	To               common.Address `abi:"to"`
	Data             []byte         `abi:"data"`
}

type BoundParamsV3 struct {
	Local  LocalBoundParamsV3  `abi:"local"`
	Global GlobalBoundParamsV3 `abi:"global"`
}

func HashBoundParamsV2(boundParams BoundParamsV2) (*big.Int, error) {
	packed, err := packBoundParamsV2(boundParams)
	if err != nil {
		return nil, err
	}
	return keccakModSNARKPrime(packed)
}

func HashBoundParamsV3(boundParams BoundParamsV3) (*big.Int, error) {
	packed, err := packBoundParamsV3(boundParams)
	if err != nil {
		return nil, err
	}
	return keccakModSNARKPrime(packed)
}

func HashBoundParamsV2Hex(boundParams BoundParamsV2, prefix bool) (string, error) {
	hash, err := HashBoundParamsV2(boundParams)
	if err != nil {
		return "", err
	}
	return railcrypto.BigIntToHex(hash, 32, prefix)
}

func HashBoundParamsV3Hex(boundParams BoundParamsV3, prefix bool) (string, error) {
	hash, err := HashBoundParamsV3(boundParams)
	if err != nil {
		return "", err
	}
	return railcrypto.BigIntToHex(hash, 32, prefix)
}

func AddressFromHex(value string) (common.Address, error) {
	formatted, err := railcrypto.FormatHexToByteLength(value, 20, true)
	if err != nil {
		return common.Address{}, err
	}
	return common.HexToAddress(formatted), nil
}

func Bytes32FromHex(value string) ([32]byte, error) {
	formatted, err := railcrypto.FormatHexToByteLength(value, 32, false)
	if err != nil {
		return [32]byte{}, err
	}
	decoded, err := hex.DecodeString(formatted)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], decoded)
	return out, nil
}

func DynamicBytesFromHex(value string) ([]byte, error) {
	return railcrypto.HexToBytes(value)
}

func packBoundParamsV2(boundParams BoundParamsV2) ([]byte, error) {
	boundParamsType, err := abi.NewType("tuple", "boundParams", []abi.ArgumentMarshaling{
		{Name: "treeNumber", Type: "uint16"},
		{Name: "minGasPrice", Type: "uint48"},
		{Name: "unshield", Type: "uint8"},
		{Name: "chainID", Type: "uint64"},
		{Name: "adaptContract", Type: "address"},
		{Name: "adaptParams", Type: "bytes32"},
		{
			Name: "commitmentCiphertext",
			Type: "tuple[]",
			Components: []abi.ArgumentMarshaling{
				{Name: "ciphertext", Type: "bytes32[4]"},
				{Name: "blindedSenderViewingKey", Type: "bytes32"},
				{Name: "blindedReceiverViewingKey", Type: "bytes32"},
				{Name: "annotationData", Type: "bytes"},
				{Name: "memo", Type: "bytes"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return abi.Arguments{{Type: boundParamsType}}.Pack(boundParams)
}

func packBoundParamsV3(boundParams BoundParamsV3) ([]byte, error) {
	boundParamsType, err := abi.NewType("tuple", "boundParams", []abi.ArgumentMarshaling{
		{
			Name: "local",
			Type: "tuple",
			Components: []abi.ArgumentMarshaling{
				{Name: "treeNumber", Type: "uint32"},
				{
					Name: "commitmentCiphertext",
					Type: "tuple[]",
					Components: []abi.ArgumentMarshaling{
						{Name: "ciphertext", Type: "bytes"},
						{Name: "blindedSenderViewingKey", Type: "bytes32"},
						{Name: "blindedReceiverViewingKey", Type: "bytes32"},
					},
				},
			},
		},
		{
			Name: "global",
			Type: "tuple",
			Components: []abi.ArgumentMarshaling{
				{Name: "minGasPrice", Type: "uint128"},
				{Name: "chainID", Type: "uint128"},
				{Name: "senderCiphertext", Type: "bytes"},
				{Name: "to", Type: "address"},
				{Name: "data", Type: "bytes"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return abi.Arguments{{Type: boundParamsType}}.Pack(boundParams)
}

func keccakModSNARKPrime(data []byte) (*big.Int, error) {
	hash, err := railcrypto.HexToBigInt(railcrypto.Keccak256HexBytes(data))
	if err != nil {
		return nil, fmt.Errorf("keccak hash: %w", err)
	}
	hash.Mod(hash, railcrypto.SNARKPrime)
	return hash, nil
}
