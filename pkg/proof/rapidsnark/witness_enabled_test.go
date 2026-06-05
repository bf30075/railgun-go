//go:build rapidsnark && witnesscalc

package rapidsnark

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/bf30075/railgun-go/pkg/proof"
	"github.com/bf30075/railgun-go/pkg/proof/witness"
)

func TestCalculateWTNSPOIFromFormattedInputs(t *testing.T) {
	fixtures := loadRapidsnarkWitnessFixtures(t)
	poiFixture := findRapidsnarkPOI3x3Fixture(t, fixtures)
	wasm, err := os.ReadFile(filepath.Join("../../../testdata/railgun", fixtures.WitnessFixtures.POI3x3.ArtifactPath))
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := proof.ParsePOIEngineProofInputsJSON(poiFixture.Raw)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := proof.FormatPOIInputs(inputs, len(poiFixture.Formatted.Nullifiers), len(poiFixture.Formatted.CommitmentsOut))
	if err != nil {
		t.Fatal(err)
	}
	wtns, err := calculateWTNSPOI(formatted, proof.Artifact{WASM: wasm})
	if err != nil {
		t.Fatal(err)
	}
	if len(wtns) != fixtures.WitnessFixtures.POI3x3.WTNSSize {
		t.Fatalf("expected wtns size %d, got %d", fixtures.WitnessFixtures.POI3x3.WTNSSize, len(wtns))
	}
	if got := witness.SHA256Hex(wtns); got != fixtures.WitnessFixtures.POI3x3.WTNSSHA256 {
		t.Fatalf("expected wtns sha256 %s, got %s", fixtures.WitnessFixtures.POI3x3.WTNSSHA256, got)
	}
}

func TestProvePOIUsesWitnessCalculatorAndProverOutput(t *testing.T) {
	fixtures := loadRapidsnarkWitnessFixtures(t)
	poiFixture := findRapidsnarkPOI3x3Fixture(t, fixtures)
	wasm, err := os.ReadFile(filepath.Join("../../../testdata/railgun", fixtures.WitnessFixtures.POI3x3.ArtifactPath))
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := proof.ParsePOIEngineProofInputsJSON(poiFixture.Raw)
	if err != nil {
		t.Fatal(err)
	}
	blindedCommitmentsOut := parseBlindedCommitmentsOut(t, poiFixture.Raw)
	publicInputs, err := proof.GetPublicInputsPOI(
		inputs.AnyRailgunTxidMerklerootAfterTransaction,
		blindedCommitmentsOut,
		inputs.POIMerkleRoots,
		inputs.RailgunTxidIfHasUnshield,
		len(poiFixture.Formatted.Nullifiers),
		len(poiFixture.Formatted.CommitmentsOut),
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedSignals := proof.BuildPublicSignalsPOI(publicInputs)
	publicJSON, err := json.Marshal(bigIntStrings(expectedSignals))
	if err != nil {
		t.Fatal(err)
	}
	expectedProof := proof.Proof{
		PiA: [2]string{"1", "2"},
		PiB: [2][2]string{{"3", "4"}, {"5", "6"}},
		PiC: [2]string{"7", "8"},
	}
	proofJSON, err := json.Marshal(expectedProof)
	if err != nil {
		t.Fatal(err)
	}

	formatted, err := proof.FormatPOIInputs(inputs, len(poiFixture.Formatted.Nullifiers), len(poiFixture.Formatted.CommitmentsOut))
	if err != nil {
		t.Fatal(err)
	}
	backend := New("")
	backend.WTNSProver = fakeWTNSProver{
		proofJSON:  proofJSON,
		publicJSON: publicJSON,
	}
	result, err := backend.ProvePOI(
		t.Context(),
		proof.CircuitID{Name: "POI_3X3", MaxInputs: 3, MaxOutputs: 3},
		formatted,
		proof.Artifact{WASM: wasm, ZKey: []byte("fake-zkey")},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Proof.PiA != expectedProof.PiA {
		t.Fatalf("unexpected proof: %+v", result.Proof)
	}
	if err := proof.AssertPublicSignalsMatch(expectedSignals, result.PublicSignals); err != nil {
		t.Fatal(err)
	}
}

type rapidsnarkWitnessFixtures struct {
	POIFixtures     []rapidsnarkPOIFixture `json:"poiFixtures"`
	WitnessFixtures witnessFixtureSet      `json:"witnessFixtures"`
}

type witnessFixtureSet struct {
	POI3x3 witnessFixture `json:"poi3x3"`
}

type witnessFixture struct {
	ArtifactPath     string `json:"artifactPath"`
	InputFixtureName string `json:"inputFixtureName"`
	WTNSSHA256       string `json:"wtnsSHA256"`
	WTNSSize         int    `json:"wtnsSize"`
}

type rapidsnarkPOIFixture struct {
	Name      string                                `json:"name"`
	Raw       json.RawMessage                       `json:"raw"`
	Formatted proof.NativeFormattedCircuitInputsPOI `json:"formatted"`
}

func loadRapidsnarkWitnessFixtures(t *testing.T) rapidsnarkWitnessFixtures {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures rapidsnarkWitnessFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func findRapidsnarkPOI3x3Fixture(t *testing.T, fixtures rapidsnarkWitnessFixtures) rapidsnarkPOIFixture {
	t.Helper()
	for _, fixture := range fixtures.POIFixtures {
		if fixture.Name == fixtures.WitnessFixtures.POI3x3.InputFixtureName {
			return fixture
		}
	}
	t.Fatalf("missing POI fixture %q", fixtures.WitnessFixtures.POI3x3.InputFixtureName)
	return rapidsnarkPOIFixture{}
}

type fakeWTNSProver struct {
	proofJSON  []byte
	publicJSON []byte
}

func (p fakeWTNSProver) ProveWTNS(context.Context, []byte, []byte) ([]byte, []byte, error) {
	return p.proofJSON, p.publicJSON, nil
}

func parseBlindedCommitmentsOut(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var parsed struct {
		BlindedCommitmentsOut []string `json:"blindedCommitmentsOut"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.BlindedCommitmentsOut
}

func bigIntStrings(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value.String()
	}
	return out
}
