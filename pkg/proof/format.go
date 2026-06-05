package proof

import (
	"fmt"
	"math/big"
)

func FormatProof(proof Proof) (SnarkProof, error) {
	piA0, err := ParseNumberishBigInt(proof.PiA[0])
	if err != nil {
		return SnarkProof{}, fmt.Errorf("pi_a[0]: %w", err)
	}
	piA1, err := ParseNumberishBigInt(proof.PiA[1])
	if err != nil {
		return SnarkProof{}, fmt.Errorf("pi_a[1]: %w", err)
	}
	piB00, err := ParseNumberishBigInt(proof.PiB[0][0])
	if err != nil {
		return SnarkProof{}, fmt.Errorf("pi_b[0][0]: %w", err)
	}
	piB01, err := ParseNumberishBigInt(proof.PiB[0][1])
	if err != nil {
		return SnarkProof{}, fmt.Errorf("pi_b[0][1]: %w", err)
	}
	piB10, err := ParseNumberishBigInt(proof.PiB[1][0])
	if err != nil {
		return SnarkProof{}, fmt.Errorf("pi_b[1][0]: %w", err)
	}
	piB11, err := ParseNumberishBigInt(proof.PiB[1][1])
	if err != nil {
		return SnarkProof{}, fmt.Errorf("pi_b[1][1]: %w", err)
	}
	piC0, err := ParseNumberishBigInt(proof.PiC[0])
	if err != nil {
		return SnarkProof{}, fmt.Errorf("pi_c[0]: %w", err)
	}
	piC1, err := ParseNumberishBigInt(proof.PiC[1])
	if err != nil {
		return SnarkProof{}, fmt.Errorf("pi_c[1]: %w", err)
	}

	return SnarkProof{
		A: G1Point{X: piA0, Y: piA1},
		B: G2Point{
			X: [2]*big.Int{piB01, piB00},
			Y: [2]*big.Int{piB11, piB10},
		},
		C: G1Point{X: piC0, Y: piC1},
	}, nil
}
