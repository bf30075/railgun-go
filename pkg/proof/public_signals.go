package proof

import (
	"fmt"
	"math/big"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func BuildPublicSignalsRailgun(publicInputs PublicInputsRailgun) []*big.Int {
	signals := make([]*big.Int, 0, 2+len(publicInputs.Nullifiers)+len(publicInputs.CommitmentsOut))
	signals = append(signals, cloneBigInt(publicInputs.MerkleRoot))
	signals = append(signals, cloneBigInt(publicInputs.BoundParamsHash))
	signals = append(signals, cloneBigIntSlice(publicInputs.Nullifiers)...)
	signals = append(signals, cloneBigIntSlice(publicInputs.CommitmentsOut)...)
	return signals
}

func HashPublicInputsRailgun(publicInputs PublicInputsRailgun) (*big.Int, error) {
	return railcrypto.Poseidon(BuildPublicSignalsRailgun(publicInputs)...)
}

func SignPublicInputsRailgun(privateKey []byte, publicInputs PublicInputsRailgun) (railcrypto.PoseidonSignature, error) {
	message, err := HashPublicInputsRailgun(publicInputs)
	if err != nil {
		return railcrypto.PoseidonSignature{}, err
	}
	return railcrypto.SignPoseidon(privateKey, message)
}

func BuildPublicSignalsPOI(publicInputs PublicInputsPOI) []*big.Int {
	signals := make([]*big.Int, 0, len(publicInputs.BlindedCommitmentsOut)+2+len(publicInputs.POIMerkleRoots))
	signals = append(signals, cloneBigIntSlice(publicInputs.BlindedCommitmentsOut)...)
	signals = append(signals, cloneBigInt(publicInputs.AnyRailgunTxidMerklerootAfterTransaction))
	signals = append(signals, cloneBigInt(publicInputs.RailgunTxidIfHasUnshield))
	signals = append(signals, cloneBigIntSlice(publicInputs.POIMerkleRoots)...)
	return signals
}

func AssertPublicSignalsMatch(expected []*big.Int, actual []*big.Int) error {
	if len(actual) == 0 {
		return nil
	}
	if len(expected) != len(actual) {
		return fmt.Errorf("public signals length mismatch: expected %d, got %d", len(expected), len(actual))
	}
	for i := range expected {
		if expected[i] == nil || actual[i] == nil {
			if expected[i] != actual[i] {
				return fmt.Errorf("public signal %d mismatch: expected %v, got %v", i, expected[i], actual[i])
			}
			continue
		}
		if expected[i].Cmp(actual[i]) != 0 {
			return fmt.Errorf("public signal %d mismatch: expected %s, got %s", i, expected[i], actual[i])
		}
	}
	return nil
}
