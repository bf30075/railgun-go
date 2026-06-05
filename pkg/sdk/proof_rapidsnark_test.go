//go:build rapidsnark

package sdk

import "testing"

func TestNewRapidsnarkProverWithBuildTag(t *testing.T) {
	prover, err := NewRapidsnarkProver(ProofConfig{
		LocalArtifactManifest:  writeSDKLocalArtifactManifest(t),
		RapidsnarkProverBinary: "/bin/echo",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prover == nil {
		t.Fatal("expected rapidsnark prover")
	}
}
