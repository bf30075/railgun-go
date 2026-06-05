package groth16

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254"

	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

type VerificationKey struct {
	Protocol string       `json:"protocol"`
	Curve    string       `json:"curve"`
	NPublic  int          `json:"nPublic"`
	Alpha1   [3]string    `json:"vk_alpha_1"`
	Beta2    [3][2]string `json:"vk_beta_2"`
	Gamma2   [3][2]string `json:"vk_gamma_2"`
	Delta2   [3][2]string `json:"vk_delta_2"`
	IC       [][3]string  `json:"IC"`
}

func ParseVerificationKey(data []byte) (VerificationKey, error) {
	var vkey VerificationKey
	if err := json.Unmarshal(data, &vkey); err != nil {
		return VerificationKey{}, err
	}
	return vkey, nil
}

func VerifyStrings(vkey VerificationKey, publicSignals []string, snarkProof railproof.Proof) (bool, error) {
	signals := make([]*big.Int, len(publicSignals))
	for i, signal := range publicSignals {
		n, err := railproof.ParseNumberishBigInt(signal)
		if err != nil {
			return false, fmt.Errorf("public signal %d: %w", i, err)
		}
		signals[i] = n
	}
	return Verify(vkey, signals, snarkProof)
}

func Verify(vkey VerificationKey, publicSignals []*big.Int, snarkProof railproof.Proof) (bool, error) {
	if err := validateVerificationKey(vkey, len(publicSignals)); err != nil {
		return false, err
	}

	alpha, err := parseG1Projective(vkey.Alpha1, "vk_alpha_1")
	if err != nil {
		return false, err
	}
	beta, err := parseG2Projective(vkey.Beta2, "vk_beta_2")
	if err != nil {
		return false, err
	}
	gamma, err := parseG2Projective(vkey.Gamma2, "vk_gamma_2")
	if err != nil {
		return false, err
	}
	delta, err := parseG2Projective(vkey.Delta2, "vk_delta_2")
	if err != nil {
		return false, err
	}

	ic := make([]bn254.G1Affine, len(vkey.IC))
	for i, point := range vkey.IC {
		ic[i], err = parseG1Projective(point, fmt.Sprintf("IC[%d]", i))
		if err != nil {
			return false, err
		}
	}
	vkX, err := linearCombination(ic, publicSignals)
	if err != nil {
		return false, err
	}

	a, err := parseG1Pair(snarkProof.PiA[0], snarkProof.PiA[1], "proof.pi_a")
	if err != nil {
		return false, err
	}
	b, err := parseG2SnarkJSPair(snarkProof.PiB[0], snarkProof.PiB[1], "proof.pi_b")
	if err != nil {
		return false, err
	}
	c, err := parseG1Pair(snarkProof.PiC[0], snarkProof.PiC[1], "proof.pi_c")
	if err != nil {
		return false, err
	}

	var negAlpha, negVKX, negC bn254.G1Affine
	negAlpha.Neg(&alpha)
	negVKX.Neg(&vkX)
	negC.Neg(&c)

	return bn254.PairingCheck(
		[]bn254.G1Affine{a, negAlpha, negVKX, negC},
		[]bn254.G2Affine{b, beta, gamma, delta},
	)
}

func validateVerificationKey(vkey VerificationKey, publicSignalCount int) error {
	if vkey.Protocol != "" && vkey.Protocol != "groth16" {
		return fmt.Errorf("unsupported proving protocol %q", vkey.Protocol)
	}
	curve := strings.ToLower(vkey.Curve)
	if curve != "" && curve != "bn128" && curve != "bn254" {
		return fmt.Errorf("unsupported curve %q", vkey.Curve)
	}
	if vkey.NPublic != publicSignalCount {
		return fmt.Errorf("public signal count mismatch: vkey expects %d, got %d", vkey.NPublic, publicSignalCount)
	}
	if len(vkey.IC) != publicSignalCount+1 {
		return fmt.Errorf("IC length mismatch: expected %d, got %d", publicSignalCount+1, len(vkey.IC))
	}
	return nil
}

func linearCombination(ic []bn254.G1Affine, publicSignals []*big.Int) (bn254.G1Affine, error) {
	var acc bn254.G1Affine
	acc.Set(&ic[0])
	for i, signal := range publicSignals {
		if err := validatePublicSignal(signal, i); err != nil {
			return bn254.G1Affine{}, err
		}
		var term bn254.G1Affine
		term.ScalarMultiplication(&ic[i+1], signal)
		acc.Add(&acc, &term)
	}
	return acc, nil
}

func validatePublicSignal(signal *big.Int, index int) error {
	if signal == nil {
		return fmt.Errorf("public signal %d is nil", index)
	}
	if signal.Sign() < 0 || signal.Cmp(railproof.SNARKPrime) >= 0 {
		return fmt.Errorf("public signal %d is outside the SNARK field", index)
	}
	return nil
}

func parseG1Projective(point [3]string, name string) (bn254.G1Affine, error) {
	if point[2] != "" && point[2] != "1" {
		return bn254.G1Affine{}, fmt.Errorf("%s: only affine z=1 points are supported", name)
	}
	return parseG1Pair(point[0], point[1], name)
}

func parseG1Pair(x string, y string, name string) (bn254.G1Affine, error) {
	var point bn254.G1Affine
	if _, err := point.X.SetString(x); err != nil {
		return bn254.G1Affine{}, fmt.Errorf("%s.x: %w", name, err)
	}
	if _, err := point.Y.SetString(y); err != nil {
		return bn254.G1Affine{}, fmt.Errorf("%s.y: %w", name, err)
	}
	if !point.IsOnCurve() {
		return bn254.G1Affine{}, fmt.Errorf("%s is not on G1", name)
	}
	if !point.IsInSubGroup() {
		return bn254.G1Affine{}, fmt.Errorf("%s is not in the G1 subgroup", name)
	}
	return point, nil
}

func parseG2Projective(point [3][2]string, name string) (bn254.G2Affine, error) {
	if point[2][0] != "" && point[2][0] != "1" {
		return bn254.G2Affine{}, fmt.Errorf("%s: only affine z=1 points are supported", name)
	}
	if point[2][1] != "" && point[2][1] != "0" {
		return bn254.G2Affine{}, fmt.Errorf("%s: only affine z=1 points are supported", name)
	}
	return parseG2SnarkJSPair(point[0], point[1], name)
}

func parseG2SnarkJSPair(x [2]string, y [2]string, name string) (bn254.G2Affine, error) {
	return parseG2Strings(x[0], x[1], y[0], y[1], name)
}

func parseG2Strings(x0 string, x1 string, y0 string, y1 string, name string) (bn254.G2Affine, error) {
	var point bn254.G2Affine
	if _, err := point.X.A0.SetString(x0); err != nil {
		return bn254.G2Affine{}, fmt.Errorf("%s.x[0]: %w", name, err)
	}
	if _, err := point.X.A1.SetString(x1); err != nil {
		return bn254.G2Affine{}, fmt.Errorf("%s.x[1]: %w", name, err)
	}
	if _, err := point.Y.A0.SetString(y0); err != nil {
		return bn254.G2Affine{}, fmt.Errorf("%s.y[0]: %w", name, err)
	}
	if _, err := point.Y.A1.SetString(y1); err != nil {
		return bn254.G2Affine{}, fmt.Errorf("%s.y[1]: %w", name, err)
	}
	if !point.IsOnCurve() {
		return bn254.G2Affine{}, fmt.Errorf("%s is not on G2", name)
	}
	if !point.IsInSubGroup() {
		return bn254.G2Affine{}, fmt.Errorf("%s is not in the G2 subgroup", name)
	}
	return point, nil
}
