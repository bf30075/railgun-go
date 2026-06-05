//go:build witnesscalc

package witness

import (
	"fmt"
	"math/big"

	witnesscalc "github.com/iden3/go-circom-witnesscalc"
)

func CalculateWTNSFromJSON(wasm []byte, inputJSON []byte, sanityCheck bool) ([]byte, error) {
	inputs, err := witnesscalc.ParseInputs(inputJSON)
	if err != nil {
		return nil, fmt.Errorf("parse witness inputs: %w", err)
	}
	calculator, err := witnesscalc.NewCircom2WitnessCalculator(wasm, sanityCheck)
	if err != nil {
		return nil, fmt.Errorf("create witness calculator: %w", err)
	}
	out, err := calculator.CalculateWTNSBin(inputs, sanityCheck)
	if err != nil {
		return nil, fmt.Errorf("calculate wtns: %w", err)
	}
	return out, nil
}

func CalculateWitnessFromJSON(wasm []byte, inputJSON []byte, sanityCheck bool) ([]*big.Int, error) {
	inputs, err := witnesscalc.ParseInputs(inputJSON)
	if err != nil {
		return nil, fmt.Errorf("parse witness inputs: %w", err)
	}
	calculator, err := witnesscalc.NewCircom2WitnessCalculator(wasm, sanityCheck)
	if err != nil {
		return nil, fmt.Errorf("create witness calculator: %w", err)
	}
	out, err := calculator.CalculateWitness(inputs, sanityCheck)
	if err != nil {
		return nil, fmt.Errorf("calculate witness: %w", err)
	}
	return out, nil
}
