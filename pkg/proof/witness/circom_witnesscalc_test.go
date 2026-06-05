//go:build witnesscalc

package witness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bf30075/railgun-go/pkg/proof"
)

func TestCalculatePOI3x3WTNSMatchesSnarkJSFixture(t *testing.T) {
	fixtures := loadWitnessFixtures(t)
	poiFixture := findPOI3x3Fixture(t, fixtures)

	inputJSON, err := json.Marshal(poiFixture.Formatted)
	if err != nil {
		t.Fatal(err)
	}
	wasmPath := filepath.Join("../../../testdata/railgun", fixtures.WitnessFixtures.POI3x3.ArtifactPath)
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatal(err)
	}
	wtns, err := CalculateWTNSFromJSON(wasm, inputJSON, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(wtns) != fixtures.WitnessFixtures.POI3x3.WTNSSize {
		t.Fatalf("expected wtns size %d, got %d", fixtures.WitnessFixtures.POI3x3.WTNSSize, len(wtns))
	}
	if got := SHA256Hex(wtns); got != fixtures.WitnessFixtures.POI3x3.WTNSSHA256 {
		t.Fatalf("expected wtns sha256 %s, got %s", fixtures.WitnessFixtures.POI3x3.WTNSSHA256, got)
	}
	parsed, err := ParseWTNS(wtns)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != 2 {
		t.Fatalf("expected wtns version 2, got %d", parsed.Version)
	}
	if len(parsed.Witness) == 0 || parsed.Witness[0].String() != "1" {
		t.Fatalf("expected first witness value to be 1")
	}
	if parsed.Prime.String() != proof.SNARKPrime.String() {
		t.Fatalf("expected field prime %s, got %s", proof.SNARKPrime, parsed.Prime)
	}
}

type exportedFixtures struct {
	POIFixtures     []poiExportedFixture `json:"poiFixtures"`
	WitnessFixtures witnessFixtureSet    `json:"witnessFixtures"`
}

type poiExportedFixture struct {
	Name      string                                `json:"name"`
	Formatted proof.NativeFormattedCircuitInputsPOI `json:"formatted"`
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

func loadWitnessFixtures(t *testing.T) exportedFixtures {
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

func findPOI3x3Fixture(t *testing.T, fixtures exportedFixtures) poiExportedFixture {
	t.Helper()
	for _, fixture := range fixtures.POIFixtures {
		if fixture.Name == fixtures.WitnessFixtures.POI3x3.InputFixtureName {
			return fixture
		}
	}
	t.Fatalf("missing POI fixture %q", fixtures.WitnessFixtures.POI3x3.InputFixtureName)
	return poiExportedFixture{}
}
