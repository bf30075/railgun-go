package note

import (
	"fmt"
	"math/big"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const BasisPoints = 10000

type UnshieldNote struct {
	ToAddress     string
	Value         *big.Int
	TokenData     railcrypto.TokenData
	Hash          *big.Int
	AllowOverride bool
}

type UnshieldData struct {
	ToAddress     string
	Value         *big.Int
	TokenData     railcrypto.TokenData
	AllowOverride bool
}

type UnshieldPreimage struct {
	NPK   string
	Token railcrypto.TokenData
	Value *big.Int
}

type SerializedUnshieldPreimage struct {
	NPK   string               `json:"npk"`
	Token railcrypto.TokenData `json:"token"`
	Value string               `json:"value"`
}

func NewUnshieldNote(toAddress string, value *big.Int, tokenData railcrypto.TokenData, allowOverride bool) (UnshieldNote, error) {
	if value == nil {
		return UnshieldNote{}, fmt.Errorf("value is required")
	}
	if err := assertValidNoteToken(tokenData, value); err != nil {
		return UnshieldNote{}, err
	}
	hash, err := railcrypto.UnshieldNoteHash(toAddress, tokenData, value)
	if err != nil {
		return UnshieldNote{}, err
	}
	return UnshieldNote{
		ToAddress:     toAddress,
		Value:         new(big.Int).Set(value),
		TokenData:     tokenData,
		Hash:          hash,
		AllowOverride: allowOverride,
	}, nil
}

func NewUnshieldNoteERC20(toAddress string, value *big.Int, tokenAddress string, allowOverride bool) (UnshieldNote, error) {
	tokenData, err := railcrypto.TokenDataERC20(tokenAddress)
	if err != nil {
		return UnshieldNote{}, err
	}
	return NewUnshieldNote(toAddress, value, tokenData, allowOverride)
}

func EmptyUnshieldNoteERC20() (UnshieldNote, error) {
	return NewUnshieldNoteERC20(
		"0x0000000000000000000000000000000000000000",
		big.NewInt(0),
		"0x0000000000000000000000000000000000000000",
		false,
	)
}

func NewUnshieldNoteNFT(toAddress string, tokenData railcrypto.TokenData, allowOverride bool) (UnshieldNote, error) {
	return NewUnshieldNote(toAddress, big.NewInt(1), tokenData, allowOverride)
}

func AmountFeeFromValue(value *big.Int, feeBasisPoints *big.Int) (*big.Int, *big.Int) {
	fee := new(big.Int).Mul(value, feeBasisPoints)
	fee.Div(fee, big.NewInt(BasisPoints))
	amount := new(big.Int).Sub(value, fee)
	return amount, fee
}

func (n UnshieldNote) UnshieldData() UnshieldData {
	return UnshieldData{
		ToAddress:     n.ToAddress,
		Value:         new(big.Int).Set(n.Value),
		TokenData:     n.TokenData,
		AllowOverride: n.AllowOverride,
	}
}

func (n UnshieldNote) NPK() string {
	return n.ToAddress
}

func (n UnshieldNote) NotePublicKey() (*big.Int, error) {
	return railcrypto.NumberishToBigInt(n.NPK())
}

func (n UnshieldNote) HashHex() (string, error) {
	return railcrypto.BigIntToHex(n.Hash, 32, false)
}

func (n UnshieldNote) Serialize(prefix bool) (SerializedUnshieldPreimage, error) {
	npk, err := railcrypto.FormatHexToByteLength(n.ToAddress, 32, prefix)
	if err != nil {
		return SerializedUnshieldPreimage{}, fmt.Errorf("npk: %w", err)
	}
	value, err := railcrypto.BigIntToHex(n.Value, 16, prefix)
	if err != nil {
		return SerializedUnshieldPreimage{}, fmt.Errorf("value: %w", err)
	}
	return SerializedUnshieldPreimage{
		NPK:   npk,
		Token: n.TokenData,
		Value: value,
	}, nil
}

func (n UnshieldNote) PreImage() UnshieldPreimage {
	return UnshieldPreimage{
		NPK:   n.NPK(),
		Token: n.TokenData,
		Value: new(big.Int).Set(n.Value),
	}
}

func assertValidNoteToken(tokenData railcrypto.TokenData, value *big.Int) error {
	tokenAddressLength := len(railcrypto.Strip0x(tokenData.TokenAddress))
	switch tokenData.TokenType {
	case railcrypto.TokenTypeERC20:
		if tokenAddressLength != 40 && tokenAddressLength != 64 {
			return fmt.Errorf("ERC20 address must be length 40 (20 bytes) or 64 (32 bytes). Got %s.", railcrypto.Strip0x(tokenData.TokenAddress))
		}
		tokenSubID, err := railcrypto.NumberishToBigInt(tokenData.TokenSubID)
		if err != nil {
			return err
		}
		if tokenSubID.Sign() != 0 {
			return fmt.Errorf("ERC20 note cannot have tokenSubID parameter.")
		}
	case railcrypto.TokenTypeERC721:
		if tokenAddressLength != 40 {
			return fmt.Errorf("ERC721 address must be length 40 (20 bytes). Got %s.", railcrypto.Strip0x(tokenData.TokenAddress))
		}
		if tokenData.TokenSubID == "" {
			return fmt.Errorf("ERC721 note must have tokenSubID parameter.")
		}
		if value.Cmp(big.NewInt(1)) != 0 {
			return fmt.Errorf("ERC721 note must have value of 1.")
		}
	case railcrypto.TokenTypeERC1155:
		if tokenAddressLength != 40 {
			return fmt.Errorf("ERC1155 address must be length 40 (20 bytes). Got %s.", railcrypto.Strip0x(tokenData.TokenAddress))
		}
		if tokenData.TokenSubID == "" {
			return fmt.Errorf("ERC1155 note must have tokenSubID parameter.")
		}
	default:
		return fmt.Errorf("unrecognized token type %d", tokenData.TokenType)
	}
	return nil
}
