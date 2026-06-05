package proof

import (
	"encoding/json"
	"os"
	"testing"
)

const (
	expectedFixtureRepo   = "https://github.com/Railgun-Community/engine.git"
	expectedFixtureCommit = "e2913b39e13f82f43556d23705fa20d2ece2e8ab"
)

type exportedFixtures struct {
	Source struct {
		Repo   string `json:"repo"`
		Commit string `json:"commit"`
	} `json:"source"`
	RailgunFixtures []railgunFormatFixture `json:"railgunFixtures"`
	POIFixtures     []poiExportedFixture   `json:"poiFixtures"`
	ProofFixtures   proofFixtureSet        `json:"proofFixtures"`
}

type poiExportedFixture struct {
	Name      string                          `json:"name"`
	Raw       json.RawMessage                 `json:"raw"`
	Formatted NativeFormattedCircuitInputsPOI `json:"formatted"`
}

type proofFixtureSet struct {
	SampleProof          Proof                 `json:"sampleProof"`
	FormattedProof       formattedProofFixture `json:"formattedProof"`
	POI3x3Proof          realProofFixture      `json:"poi3x3Proof"`
	RailgunPublicSignals railgunSignalsFixture `json:"railgunPublicSignals"`
	POIPublicSignals     poiSignalsFixture     `json:"poiPublicSignals"`
}

type realProofFixture struct {
	Proof               Proof    `json:"proof"`
	PublicSignals       []string `json:"publicSignals"`
	PublicSignalsSHA256 string   `json:"publicSignalsSHA256"`
	ProofSHA256         string   `json:"proofSHA256"`
	Verified            bool     `json:"verified"`
}

type formattedProofFixture struct {
	A g1PointFixture `json:"a"`
	B g2PointFixture `json:"b"`
	C g1PointFixture `json:"c"`
}

type g1PointFixture struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type g2PointFixture struct {
	X [2]string `json:"x"`
	Y [2]string `json:"y"`
}

type railgunSignalsFixture struct {
	PublicInputs struct {
		MerkleRoot      string   `json:"merkleRoot"`
		BoundParamsHash string   `json:"boundParamsHash"`
		Nullifiers      []string `json:"nullifiers"`
		CommitmentsOut  []string `json:"commitmentsOut"`
	} `json:"publicInputs"`
	Signals []string `json:"signals"`
}

type poiSignalsFixture struct {
	PublicInputs struct {
		BlindedCommitmentsOut                    []string `json:"blindedCommitmentsOut"`
		AnyRailgunTxidMerklerootAfterTransaction string   `json:"anyRailgunTxidMerklerootAfterTransaction"`
		RailgunTxidIfHasUnshield                 string   `json:"railgunTxidIfHasUnshield"`
		POIMerkleRoots                           []string `json:"poiMerkleroots"`
	} `json:"publicInputs"`
	Signals []string `json:"signals"`
}

func TestExportedFixtureSourcePinned(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	if fixtures.Source.Repo != expectedFixtureRepo {
		t.Fatalf("unexpected fixture repo: %s", fixtures.Source.Repo)
	}
	if fixtures.Source.Commit != expectedFixtureCommit {
		t.Fatalf("unexpected fixture commit: %s", fixtures.Source.Commit)
	}
}

func TestExportedRailgunFixturesMatchFormatter(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	expectedNames := map[string]bool{
		"1x2": false,
		"1x3": false,
		"2x2": false,
		"2x3": false,
		"8x2": false,
	}

	for _, fixture := range fixtures.RailgunFixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if _, ok := expectedNames[fixture.Name]; !ok {
				t.Fatalf("unexpected Railgun fixture %q", fixture.Name)
			}
			expectedNames[fixture.Name] = true

			inputs := mustRailgunFixtureInputs(t, fixture.Raw)
			formatted, err := FormatRailgunInputs(inputs)
			if err != nil {
				t.Fatal(err)
			}
			got := formatted.NativeInputs()
			if !nativeRailgunEqual(got, fixture.Expected) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				expectedJSON, _ := json.MarshalIndent(fixture.Expected, "", "  ")
				t.Fatalf("formatted inputs mismatch\nexpected:\n%s\nactual:\n%s", expectedJSON, gotJSON)
			}
		})
	}

	for name, seen := range expectedNames {
		if !seen {
			t.Fatalf("missing Railgun fixture %q", name)
		}
	}
}

func TestExportedPOIFixturesMatchFormatter(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	expectedNames := map[string]bool{
		"poi-3x3":   false,
		"poi-13x13": false,
	}

	for _, fixture := range fixtures.POIFixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if _, ok := expectedNames[fixture.Name]; !ok {
				t.Fatalf("unexpected POI fixture %q", fixture.Name)
			}
			expectedNames[fixture.Name] = true

			inputs, err := ParsePOIEngineProofInputsJSON(fixture.Raw)
			if err != nil {
				t.Fatal(err)
			}
			formatted, err := FormatPOIInputs(inputs, len(fixture.Formatted.Nullifiers), len(fixture.Formatted.CommitmentsOut))
			if err != nil {
				t.Fatal(err)
			}
			got := formatted.NativeInputs()
			if !nativePOIEqual(got, fixture.Formatted) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				expectedJSON, _ := json.MarshalIndent(fixture.Formatted, "", "  ")
				t.Fatalf("formatted inputs mismatch\nexpected:\n%s\nactual:\n%s", expectedJSON, gotJSON)
			}
		})
	}

	for name, seen := range expectedNames {
		if !seen {
			t.Fatalf("missing POI fixture %q", name)
		}
	}
}

func TestExportedProofFixtureMatchesSolidityOrdering(t *testing.T) {
	fixture := loadExportedFixtures(t).ProofFixtures
	formatted, err := FormatProof(fixture.SampleProof)
	if err != nil {
		t.Fatal(err)
	}
	if formatted.A.X.String() != fixture.FormattedProof.A.X || formatted.A.Y.String() != fixture.FormattedProof.A.Y {
		t.Fatalf("unexpected proof A: %+v", formatted.A)
	}
	if formatted.B.X[0].String() != fixture.FormattedProof.B.X[0] || formatted.B.X[1].String() != fixture.FormattedProof.B.X[1] {
		t.Fatalf("unexpected proof B.X: %+v", formatted.B.X)
	}
	if formatted.B.Y[0].String() != fixture.FormattedProof.B.Y[0] || formatted.B.Y[1].String() != fixture.FormattedProof.B.Y[1] {
		t.Fatalf("unexpected proof B.Y: %+v", formatted.B.Y)
	}
	if formatted.C.X.String() != fixture.FormattedProof.C.X || formatted.C.Y.String() != fixture.FormattedProof.C.Y {
		t.Fatalf("unexpected proof C: %+v", formatted.C)
	}
}

func TestExportedPublicSignalFixturesMatchBuilders(t *testing.T) {
	fixture := loadExportedFixtures(t).ProofFixtures
	railgunSignals := BuildPublicSignalsRailgun(PublicInputsRailgun{
		MerkleRoot:      mustNumberish(t, fixture.RailgunPublicSignals.PublicInputs.MerkleRoot),
		BoundParamsHash: mustNumberish(t, fixture.RailgunPublicSignals.PublicInputs.BoundParamsHash),
		Nullifiers:      mustNumberishSlice(t, fixture.RailgunPublicSignals.PublicInputs.Nullifiers),
		CommitmentsOut:  mustNumberishSlice(t, fixture.RailgunPublicSignals.PublicInputs.CommitmentsOut),
	})
	assertStringSlices(t, bigIntStrings(railgunSignals), fixture.RailgunPublicSignals.Signals)

	poiSignals := BuildPublicSignalsPOI(PublicInputsPOI{
		BlindedCommitmentsOut:                    mustNumberishSlice(t, fixture.POIPublicSignals.PublicInputs.BlindedCommitmentsOut),
		AnyRailgunTxidMerklerootAfterTransaction: mustNumberish(t, fixture.POIPublicSignals.PublicInputs.AnyRailgunTxidMerklerootAfterTransaction),
		RailgunTxidIfHasUnshield:                 mustNumberish(t, fixture.POIPublicSignals.PublicInputs.RailgunTxidIfHasUnshield),
		POIMerkleRoots:                           mustNumberishSlice(t, fixture.POIPublicSignals.PublicInputs.POIMerkleRoots),
	})
	assertStringSlices(t, bigIntStrings(poiSignals), fixture.POIPublicSignals.Signals)
}

func TestExportedPOI3x3ProofFixturePublicSignals(t *testing.T) {
	fixtures := loadExportedFixtures(t)
	proofFixture := fixtures.ProofFixtures.POI3x3Proof
	if !proofFixture.Verified {
		t.Fatal("expected TypeScript proof fixture to verify")
	}
	if _, err := FormatProof(proofFixture.Proof); err != nil {
		t.Fatal(err)
	}

	poiFixture := findPOIFixture(t, fixtures, "poi-3x3")
	inputs, err := ParsePOIEngineProofInputsJSON(poiFixture.Raw)
	if err != nil {
		t.Fatal(err)
	}
	publicInputs, err := GetPublicInputsPOI(
		inputs.AnyRailgunTxidMerklerootAfterTransaction,
		parseBlindedCommitmentsOut(t, poiFixture.Raw),
		inputs.POIMerkleRoots,
		inputs.RailgunTxidIfHasUnshield,
		len(poiFixture.Formatted.Nullifiers),
		len(poiFixture.Formatted.CommitmentsOut),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlices(t, bigIntStrings(BuildPublicSignalsPOI(publicInputs)), proofFixture.PublicSignals)
	if proofFixture.ProofSHA256 == "" || proofFixture.PublicSignalsSHA256 == "" {
		t.Fatal("expected proof fixture hashes")
	}
}

func loadExportedFixtures(t *testing.T) exportedFixtures {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func findPOIFixture(t *testing.T, fixtures exportedFixtures, name string) poiExportedFixture {
	t.Helper()
	for _, fixture := range fixtures.POIFixtures {
		if fixture.Name == name {
			return fixture
		}
	}
	t.Fatalf("missing POI fixture %q", name)
	return poiExportedFixture{}
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

func assertStringSlices(t *testing.T, got []string, expected []string) {
	t.Helper()
	if len(got) != len(expected) {
		t.Fatalf("expected %d values, got %d", len(expected), len(got))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("value %d mismatch: expected %s, got %s", i, expected[i], got[i])
		}
	}
}

func nativePOIEqual(left NativeFormattedCircuitInputsPOI, right NativeFormattedCircuitInputsPOI) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}
