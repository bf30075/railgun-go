package merkletree

import (
	"math/big"
	"strings"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const TreeDepth = 16

type MerkleProof struct {
	Leaf     string   `json:"leaf"`
	Indices  string   `json:"indices"`
	Elements []string `json:"elements"`
	Root     string   `json:"root"`
}

func CreateDummyProof(leaf string) (MerkleProof, error) {
	indices, err := railcrypto.BigIntToHex(big.NewInt(0), 32, false)
	if err != nil {
		return MerkleProof{}, err
	}
	zero, err := railcrypto.BigIntToHex(big.NewInt(0), 32, false)
	if err != nil {
		return MerkleProof{}, err
	}
	elements := make([]string, TreeDepth)
	for i := range elements {
		elements[i] = zero
	}
	proof := MerkleProof{
		Leaf:     leaf,
		Indices:  indices,
		Elements: elements,
	}
	proof.Root, err = CalculateRoot(proof)
	if err != nil {
		return MerkleProof{}, err
	}
	return proof, nil
}

func HashLeftRight(left *big.Int, right *big.Int) (*big.Int, error) {
	return railcrypto.Poseidon(left, right)
}

func CalculateRoot(proof MerkleProof) (string, error) {
	indices, err := railcrypto.HexToBigInt(proof.Indices)
	if err != nil {
		return "", err
	}
	current, err := railcrypto.HexToBigInt(proof.Leaf)
	if err != nil {
		return "", err
	}

	for i, elementHex := range proof.Elements {
		element, err := railcrypto.HexToBigInt(elementHex)
		if err != nil {
			return "", err
		}
		if indices.Bit(i) == 1 {
			current, err = HashLeftRight(element, current)
		} else {
			current, err = HashLeftRight(current, element)
		}
		if err != nil {
			return "", err
		}
	}
	return railcrypto.BigIntToHex(current, 32, false)
}

func VerifyProof(proof MerkleProof) (bool, error) {
	root, err := CalculateRoot(proof)
	if err != nil {
		return false, err
	}
	return normalizeHex(root) == normalizeHex(proof.Root), nil
}

func normalizeHex(value string) string {
	value = railcrypto.Strip0x(value)
	value = strings.TrimLeft(value, "0")
	if value == "" {
		return "0"
	}
	return strings.ToLower(value)
}
