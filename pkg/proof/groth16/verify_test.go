package groth16

import (
	"encoding/json"
	"os"
	"testing"

	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

type exportedFixtures struct {
	ProofFixtures struct {
		POI3x3Proof struct {
			Proof         railproof.Proof `json:"proof"`
			PublicSignals []string        `json:"publicSignals"`
			Verified      bool            `json:"verified"`
			VKey          VerificationKey `json:"vkey"`
		} `json:"poi3x3Proof"`
	} `json:"proofFixtures"`
}

func TestVerifyPOI3x3SnarkJSProof(t *testing.T) {
	fixture := loadPOI3x3ProofFixture(t)
	if !fixture.Verified {
		t.Fatal("expected TypeScript fixture to verify")
	}

	ok, err := VerifyStrings(fixture.VKey, fixture.PublicSignals, fixture.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected Go Groth16 verifier to accept POI 3x3 proof")
	}
}

func TestVerifyRejectsWrongPublicSignal(t *testing.T) {
	fixture := loadPOI3x3ProofFixture(t)
	publicSignals := append([]string(nil), fixture.PublicSignals...)
	publicSignals[0] = "1"

	ok, err := VerifyStrings(fixture.VKey, publicSignals, fixture.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected changed public signal to fail verification")
	}
}

func loadPOI3x3ProofFixture(t *testing.T) struct {
	Proof         railproof.Proof `json:"proof"`
	PublicSignals []string        `json:"publicSignals"`
	Verified      bool            `json:"verified"`
	VKey          VerificationKey `json:"vkey"`
} {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.ProofFixtures.POI3x3Proof
}
