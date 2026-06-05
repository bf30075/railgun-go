package proof

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	snarkPrimeDecimal    = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	merkleZeroValueHex   = "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc"
	defaultPOIPathLength = 16
)

var (
	SNARKPrime        = mustParseDecimal(snarkPrimeDecimal)
	MerkleZeroValue   = mustParseHex(merkleZeroValueHex)
	ZeroValue         = big.NewInt(0)
	errEmptyBigIntStr = errors.New("empty bigint string")
)

func mustParseDecimal(value string) *big.Int {
	n, err := ParseDecimalBigInt(value)
	if err != nil {
		panic(err)
	}
	return n
}

func mustParseHex(value string) *big.Int {
	n, err := ParseHexBigInt(value)
	if err != nil {
		panic(err)
	}
	return n
}

func ParseDecimalBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errEmptyBigIntStr
	}
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal bigint %q", value)
	}
	return n, nil
}

func ParseHexBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errEmptyBigIntStr
	}
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	if value == "" {
		return nil, fmt.Errorf("invalid hex bigint %q", value)
	}
	n, ok := new(big.Int).SetString(value, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex bigint %q", value)
	}
	return n, nil
}

func ParseNumberishBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return ParseHexBigInt(value)
	}
	return ParseDecimalBigInt(value)
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func cloneRequiredBigInt(value *big.Int, name string) (*big.Int, error) {
	if value == nil {
		return nil, fmt.Errorf("%s is required", name)
	}
	return cloneBigInt(value), nil
}

func cloneBigIntSlice(values []*big.Int) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = cloneBigInt(value)
	}
	return out
}

func cloneBigIntRows(values [][]*big.Int) [][]*big.Int {
	out := make([][]*big.Int, len(values))
	for i, row := range values {
		out[i] = cloneBigIntSlice(row)
	}
	return out
}

func padBigIntsToMax(values []*big.Int, max int, zeroValue *big.Int) []*big.Int {
	out := cloneBigIntSlice(values)
	for len(out) < max {
		out = append(out, cloneBigInt(zeroValue))
	}
	return out
}

func padBigIntRowsToMaxAndLength(values [][]*big.Int, max int, length int, zeroValue *big.Int) [][]*big.Int {
	out := cloneBigIntRows(values)
	for len(out) < max {
		row := make([]*big.Int, length)
		for i := range row {
			row[i] = cloneBigInt(zeroValue)
		}
		out = append(out, row)
	}
	return out
}

func parseHexSlice(values []string) ([]*big.Int, error) {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		n, err := ParseHexBigInt(value)
		if err != nil {
			return nil, fmt.Errorf("hex value at index %d: %w", i, err)
		}
		out[i] = n
	}
	return out, nil
}

func parseNumberishSlice(values []string) ([]*big.Int, error) {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		n, err := ParseNumberishBigInt(value)
		if err != nil {
			return nil, fmt.Errorf("numberish value at index %d: %w", i, err)
		}
		out[i] = n
	}
	return out, nil
}

func bigIntStrings(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		if value == nil {
			out[i] = ""
			continue
		}
		out[i] = value.String()
	}
	return out
}

func bigIntRowStrings(values [][]*big.Int) [][]string {
	out := make([][]string, len(values))
	for i, row := range values {
		out[i] = bigIntStrings(row)
	}
	return out
}
