//go:build rapidsnark && !witnesscalc

package rapidsnark

import "github.com/bf30075/railgun-go/pkg/proof"

func calculateWTNSRailgun(proof.FormattedCircuitInputsRailgun, proof.Artifact) ([]byte, error) {
	return nil, ErrWitnessGenerationNotImplemented
}

func calculateWTNSPOI(proof.FormattedCircuitInputsPOI, proof.Artifact) ([]byte, error) {
	return nil, ErrWitnessGenerationNotImplemented
}
