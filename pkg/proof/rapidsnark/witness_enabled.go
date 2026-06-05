//go:build rapidsnark && witnesscalc

package rapidsnark

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bf30075/railgun-go/pkg/proof"
	"github.com/bf30075/railgun-go/pkg/proof/witness"
)

func calculateWTNSRailgun(inputs proof.FormattedCircuitInputsRailgun, artifacts proof.Artifact) ([]byte, error) {
	return calculateWTNS(inputs.NativeInputs(), artifacts)
}

func calculateWTNSPOI(inputs proof.FormattedCircuitInputsPOI, artifacts proof.Artifact) ([]byte, error) {
	return calculateWTNS(inputs.NativeInputs(), artifacts)
}

func calculateWTNS(inputs any, artifacts proof.Artifact) ([]byte, error) {
	if len(artifacts.WASM) == 0 {
		return nil, errors.New("wasm artifact is required for witness calculation")
	}
	inputJSON, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("marshal witness inputs: %w", err)
	}
	return witness.CalculateWTNSFromJSON(artifacts.WASM, inputJSON, true)
}
