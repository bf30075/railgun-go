package txid

import (
	"fmt"
	"math/big"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const TreeMaxItems = 65536

func GetGlobalTreePosition(tree uint64, index uint64) *big.Int {
	out := new(big.Int).SetUint64(tree)
	out.Mul(out, big.NewInt(TreeMaxItems))
	out.Add(out, new(big.Int).SetUint64(index))
	return out
}

func RailgunTransactionIDHex(nullifiers []string, commitments []string, boundParamsHash string) (string, error) {
	id, err := RailgunTransactionID(nullifiers, commitments, boundParamsHash)
	if err != nil {
		return "", err
	}
	return railcrypto.BigIntToHex(id, 32, false)
}

func RailgunTransactionID(nullifiers []string, commitments []string, boundParamsHash string) (*big.Int, error) {
	nullifierBigInts, err := parseHexList(nullifiers)
	if err != nil {
		return nil, err
	}
	commitmentBigInts, err := parseHexList(commitments)
	if err != nil {
		return nil, err
	}
	boundParams, err := railcrypto.HexToBigInt(boundParamsHash)
	if err != nil {
		return nil, err
	}
	return RailgunTransactionIDFromBigInts(nullifierBigInts, commitmentBigInts, boundParams)
}

func RailgunTransactionIDFromBigInts(nullifiers []*big.Int, commitments []*big.Int, boundParamsHash *big.Int) (*big.Int, error) {
	if err := validateBigIntList("nullifiers", nullifiers); err != nil {
		return nil, err
	}
	if err := validateBigIntList("commitments", commitments); err != nil {
		return nil, err
	}
	if boundParamsHash == nil {
		return nil, fmt.Errorf("bound params hash is required")
	}
	nullifiersHash, err := railcrypto.Poseidon(padTo13(nullifiers)...)
	if err != nil {
		return nil, err
	}
	commitmentsHash, err := railcrypto.Poseidon(padTo13(commitments)...)
	if err != nil {
		return nil, err
	}
	return railcrypto.Poseidon(nullifiersHash, commitmentsHash, boundParamsHash)
}

func RailgunTxidLeafHash(railgunTxid *big.Int, utxoTreeIn uint64, globalTreePosition *big.Int) (string, error) {
	if railgunTxid == nil {
		return "", fmt.Errorf("railgun txid is required")
	}
	if globalTreePosition == nil {
		return "", fmt.Errorf("global tree position is required")
	}
	hash, err := railcrypto.Poseidon(railgunTxid, new(big.Int).SetUint64(utxoTreeIn), globalTreePosition)
	if err != nil {
		return "", err
	}
	return railcrypto.BigIntToHex(hash, 32, false)
}

func CalculateVerificationHash(previousVerificationHash string, firstNullifier string) (string, error) {
	previous, err := railcrypto.HexToBytes(previousVerificationHash)
	if err != nil {
		return "", err
	}
	nullifier, err := railcrypto.HexToBytes(firstNullifier)
	if err != nil {
		return "", err
	}
	combined := append(previous, nullifier...)
	return "0x" + railcrypto.Keccak256HexBytes(combined), nil
}

func parseHexList(values []string) ([]*big.Int, error) {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		n, err := railcrypto.HexToBigInt(value)
		if err != nil {
			return nil, err
		}
		out[i] = n
	}
	return out, nil
}

func padTo13(values []*big.Int) []*big.Int {
	out := make([]*big.Int, len(values), 13)
	for i, value := range values {
		out[i] = new(big.Int).Set(value)
	}
	for len(out) < 13 {
		out = append(out, new(big.Int).Set(railcrypto.MerkleZeroValue))
	}
	return out
}

func validateBigIntList(name string, values []*big.Int) error {
	for i, value := range values {
		if value == nil {
			return fmt.Errorf("%s[%d] is required", name, i)
		}
	}
	return nil
}
