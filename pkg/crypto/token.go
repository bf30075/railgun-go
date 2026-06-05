package railcrypto

import (
	"fmt"
	"math/big"
)

const (
	TokenTypeERC20   = 0
	TokenTypeERC721  = 1
	TokenTypeERC1155 = 2
)

type TokenData struct {
	TokenAddress string `json:"tokenAddress"`
	TokenType    int    `json:"tokenType"`
	TokenSubID   string `json:"tokenSubID"`
}

func SerializeTokenData(tokenAddress string, tokenType int, tokenSubID string) (TokenData, error) {
	address, err := FormatHexToByteLength(tokenAddress, 20, true)
	if err != nil {
		return TokenData{}, fmt.Errorf("token address: %w", err)
	}
	subID, err := FormatHexToByteLengthFromNumberish(tokenSubID, 32, true)
	if err != nil {
		return TokenData{}, fmt.Errorf("token sub id: %w", err)
	}
	return TokenData{
		TokenAddress: address,
		TokenType:    tokenType,
		TokenSubID:   subID,
	}, nil
}

func TokenDataERC20(tokenAddress string) (TokenData, error) {
	return SerializeTokenData(tokenAddress, TokenTypeERC20, "0")
}

func TokenDataNFT(tokenAddress string, tokenType int, tokenSubID string) (TokenData, error) {
	if tokenType != TokenTypeERC721 && tokenType != TokenTypeERC1155 {
		return TokenData{}, fmt.Errorf("invalid NFT token type %d", tokenType)
	}
	return SerializeTokenData(tokenAddress, tokenType, tokenSubID)
}

func TokenDataHash(tokenData TokenData) (string, error) {
	switch tokenData.TokenType {
	case TokenTypeERC20:
		return TokenDataHashERC20(tokenData.TokenAddress)
	case TokenTypeERC721, TokenTypeERC1155:
		return TokenDataHashNFT(tokenData)
	default:
		return "", fmt.Errorf("unrecognized token type %d", tokenData.TokenType)
	}
}

func TokenDataHashERC20(tokenAddress string) (string, error) {
	return FormatHexToByteLength(tokenAddress, 32, false)
}

func TokenDataHashNFT(tokenData TokenData) (string, error) {
	tokenTypeHex, err := BigIntToHex(big.NewInt(int64(tokenData.TokenType)), 32, false)
	if err != nil {
		return "", err
	}
	tokenAddressHex, err := FormatHexToByteLength(tokenData.TokenAddress, 32, false)
	if err != nil {
		return "", fmt.Errorf("token address: %w", err)
	}
	tokenSubID, err := NumberishToBigInt(tokenData.TokenSubID)
	if err != nil {
		return "", fmt.Errorf("token sub id: %w", err)
	}
	tokenSubIDHex, err := BigIntToHex(tokenSubID, 32, false)
	if err != nil {
		return "", err
	}
	hashed, err := Keccak256Hex(tokenTypeHex + tokenAddressHex + tokenSubIDHex)
	if err != nil {
		return "", err
	}
	hashedBigInt, err := HexToBigInt(hashed)
	if err != nil {
		return "", err
	}
	hashedBigInt.Mod(hashedBigInt, SNARKPrime)
	return BigIntToHex(hashedBigInt, 32, false)
}

func FormatHexToByteLengthFromNumberish(value string, byteLength int, prefix bool) (string, error) {
	n, err := NumberishToBigInt(value)
	if err != nil {
		return "", err
	}
	return BigIntToHex(n, byteLength, prefix)
}
