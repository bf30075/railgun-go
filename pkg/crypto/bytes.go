package railcrypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	SNARKPrimeDecimal  = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	MerkleZeroValueHex = "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc"
)

var (
	SNARKPrime      = mustDecimal(SNARKPrimeDecimal)
	MerkleZeroValue = mustHex(MerkleZeroValueHex)
)

func mustDecimal(value string) *big.Int {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic(value)
	}
	return n
}

func mustHex(value string) *big.Int {
	n, err := HexToBigInt(value)
	if err != nil {
		panic(err)
	}
	return n
}

func Strip0x(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	return value
}

func Prefix0x(value string) string {
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return "0x" + strings.ToLower(Strip0x(value))
	}
	return "0x" + strings.ToLower(value)
}

func HexToBigInt(value string) (*big.Int, error) {
	value = Strip0x(value)
	if value == "" {
		return nil, errors.New("empty hex bigint")
	}
	n, ok := new(big.Int).SetString(value, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex bigint %q", value)
	}
	return n, nil
}

func NumberishToBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return HexToBigInt(value)
	}
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal bigint %q", value)
	}
	return n, nil
}

func BigIntToHex(value *big.Int, byteLength int, prefix bool) (string, error) {
	if value == nil {
		return "", errors.New("nil bigint")
	}
	if value.Sign() < 0 {
		return "", errors.New("bigint must be positive")
	}
	hexValue := value.Text(16)
	if len(hexValue) > byteLength*2 {
		hexValue = hexValue[len(hexValue)-byteLength*2:]
	}
	if len(hexValue) < byteLength*2 {
		hexValue = strings.Repeat("0", byteLength*2-len(hexValue)) + hexValue
	}
	hexValue = strings.ToLower(hexValue)
	if prefix {
		return "0x" + hexValue, nil
	}
	return hexValue, nil
}

func FormatHexToByteLength(value string, byteLength int, prefix bool) (string, error) {
	if byteLength <= 0 {
		return "", errors.New("byte length must be positive")
	}
	hexValue := strings.ToLower(Strip0x(value))
	if hexValue == "" {
		hexValue = "0"
	}
	if _, ok := new(big.Int).SetString(hexValue, 16); !ok {
		return "", fmt.Errorf("invalid hex value %q", value)
	}
	targetLength := byteLength * 2
	if len(hexValue) > targetLength {
		hexValue = hexValue[len(hexValue)-targetLength:]
	}
	if len(hexValue) < targetLength {
		hexValue = strings.Repeat("0", targetLength-len(hexValue)) + hexValue
	}
	if prefix {
		return "0x" + hexValue, nil
	}
	return hexValue, nil
}

func HexToBytes(value string) ([]byte, error) {
	value = Strip0x(value)
	if value == "" {
		return nil, nil
	}
	if len(value)%2 == 1 {
		value = "0" + value
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func BytesToHex(value []byte, prefix bool) string {
	out := strings.ToLower(hex.EncodeToString(value))
	if prefix {
		return "0x" + out
	}
	return out
}
