//go:build rapidsnark

package rapidsnark

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/bf30075/railgun-go/pkg/proof"
	"github.com/bf30075/railgun-go/pkg/proof/groth16"
)

func TestParseProofResult(t *testing.T) {
	fixture := loadProofFixture(t)
	proofJSON, err := json.Marshal(fixture.SampleProof)
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, err := json.Marshal(fixture.RailgunPublicSignals.Signals)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseProofResult(proofJSON, publicJSON)
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof.PiA != fixture.SampleProof.PiA {
		t.Fatalf("unexpected pi_a: %+v", result.Proof.PiA)
	}
	if len(result.PublicSignals) != len(fixture.RailgunPublicSignals.Signals) {
		t.Fatalf("expected %d public signals, got %d", len(fixture.RailgunPublicSignals.Signals), len(result.PublicSignals))
	}
	for i, expected := range fixture.RailgunPublicSignals.Signals {
		if result.PublicSignals[i].String() != expected {
			t.Fatalf("public signal %d mismatch: expected %s, got %s", i, expected, result.PublicSignals[i])
		}
	}
}

func TestProveWTNSWithRapidsnarkBinary(t *testing.T) {
	prover := os.Getenv("RAPIDSNARK_PROVER")
	zkeyPath := os.Getenv("RAPIDSNARK_ZKEY")
	wtnsPath := os.Getenv("RAPIDSNARK_WTNS")
	if prover == "" || zkeyPath == "" || wtnsPath == "" {
		t.Skip("set RAPIDSNARK_PROVER, RAPIDSNARK_ZKEY, and RAPIDSNARK_WTNS for POI 3x3 to run")
	}

	zkey, err := os.ReadFile(zkeyPath)
	if err != nil {
		t.Fatal(err)
	}
	wtns, err := os.ReadFile(wtnsPath)
	if err != nil {
		t.Fatal(err)
	}

	backend := New(prover)
	result, err := backend.ProveWTNSResult(context.Background(), zkey, wtns)
	if err != nil {
		t.Fatal(err)
	}
	fixture := loadProofFixture(t).POI3x3Proof
	if err := proof.AssertPublicSignalsMatch(mustBigIntSignals(t, fixture.PublicSignals), result.PublicSignals); err != nil {
		t.Fatal(err)
	}
	ok, err := groth16.Verify(fixture.VKey, result.PublicSignals, result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected rapidsnark proof to verify")
	}
}

type exportedFixtures struct {
	POIFixtures   []backendPOIFixture `json:"poiFixtures"`
	ProofFixtures proofFixtureSet     `json:"proofFixtures"`
}

type proofFixtureSet struct {
	SampleProof          proof.Proof           `json:"sampleProof"`
	POI3x3Proof          backendProofFixture   `json:"poi3x3Proof"`
	RailgunPublicSignals railgunSignalsFixture `json:"railgunPublicSignals"`
}

type backendPOIFixture struct {
	Name      string                                `json:"name"`
	Raw       json.RawMessage                       `json:"raw"`
	Formatted proof.NativeFormattedCircuitInputsPOI `json:"formatted"`
}

type backendProofFixture struct {
	Proof         proof.Proof             `json:"proof"`
	PublicSignals []string                `json:"publicSignals"`
	Verified      bool                    `json:"verified"`
	VKey          groth16.VerificationKey `json:"vkey"`
}

type railgunSignalsFixture struct {
	Signals []string `json:"signals"`
}

func loadProofFixture(t *testing.T) proofFixtureSet {
	t.Helper()
	return loadBackendFixtures(t).ProofFixtures
}

func loadBackendFixtures(t *testing.T) exportedFixtures {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func TestVerifyPOIWithFixtureVKey(t *testing.T) {
	fixtures := loadBackendFixtures(t)
	poiProof := fixtures.ProofFixtures.POI3x3Proof
	if !poiProof.Verified {
		t.Fatal("expected TypeScript fixture to verify")
	}

	poiFixture := findBackendPOIFixture(t, fixtures, "poi-3x3")
	inputs, err := proof.ParsePOIEngineProofInputsJSON(poiFixture.Raw)
	if err != nil {
		t.Fatal(err)
	}
	publicInputs, err := proof.GetPublicInputsPOI(
		inputs.AnyRailgunTxidMerklerootAfterTransaction,
		parseBackendBlindedCommitmentsOut(t, poiFixture.Raw),
		inputs.POIMerkleRoots,
		inputs.RailgunTxidIfHasUnshield,
		len(poiFixture.Formatted.Nullifiers),
		len(poiFixture.Formatted.CommitmentsOut),
	)
	if err != nil {
		t.Fatal(err)
	}
	vkeyJSON, err := json.Marshal(poiProof.VKey)
	if err != nil {
		t.Fatal(err)
	}

	backend := New("")
	ok, err := backend.VerifyPOI(context.Background(), publicInputs, poiProof.Proof, proof.Artifact{VKey: vkeyJSON})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected rapidsnark verifier to accept POI proof")
	}

	publicInputs.RailgunTxidIfHasUnshield = big.NewInt(1)
	ok, err = backend.VerifyPOI(context.Background(), publicInputs, poiProof.Proof, proof.Artifact{VKey: vkeyJSON})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected changed public inputs to fail verification")
	}
}

func TestVerifyRequiresVKeyByDefault(t *testing.T) {
	backend := New("")

	ok, err := backend.VerifyPOI(context.Background(), proof.PublicInputsPOI{}, proof.Proof{}, proof.Artifact{})
	if !errors.Is(err, ErrVerificationKeyRequired) {
		t.Fatalf("expected missing vkey error, got ok=%v err=%v", ok, err)
	}
	if ok {
		t.Fatal("expected verification to fail without vkey")
	}
}

func TestVerifyAllowsMissingVKeyWhenStrictVerifyDisabled(t *testing.T) {
	backend := New("")
	backend.StrictVerify = false

	ok, err := backend.VerifyPOI(context.Background(), proof.PublicInputsPOI{}, proof.Proof{}, proof.Artifact{})
	if err != nil {
		t.Fatalf("expected missing vkey to be allowed, got %v", err)
	}
	if !ok {
		t.Fatal("expected missing vkey to pass when strict verification is disabled")
	}
}

func findBackendPOIFixture(t *testing.T, fixtures exportedFixtures, name string) backendPOIFixture {
	t.Helper()
	for _, fixture := range fixtures.POIFixtures {
		if fixture.Name == name {
			return fixture
		}
	}
	t.Fatalf("missing POI fixture %q", name)
	return backendPOIFixture{}
}

func parseBackendBlindedCommitmentsOut(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var parsed struct {
		BlindedCommitmentsOut []string `json:"blindedCommitmentsOut"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.BlindedCommitmentsOut
}

func mustBigIntSignals(t *testing.T, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(values))
	for i, value := range values {
		n, err := proof.ParseNumberishBigInt(value)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = n
	}
	return out
}
