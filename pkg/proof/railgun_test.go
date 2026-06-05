package proof

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

type railgunFormatFixture struct {
	Name     string                              `json:"name"`
	Raw      railgunFormatFixtureRaw             `json:"raw"`
	Expected NativeFormattedCircuitInputsRailgun `json:"expected"`
}

type railgunFormatFixtureRaw struct {
	PublicInputs struct {
		MerkleRoot      string   `json:"merkleRoot"`
		BoundParamsHash string   `json:"boundParamsHash"`
		Nullifiers      []string `json:"nullifiers"`
		CommitmentsOut  []string `json:"commitmentsOut"`
	} `json:"publicInputs"`
	Signature     [3]string `json:"signature"`
	PrivateInputs struct {
		TokenAddress  string     `json:"tokenAddress"`
		PublicKey     [2]string  `json:"publicKey"`
		Signature     [3]string  `json:"signature"`
		RandomIn      []string   `json:"randomIn"`
		ValueIn       []string   `json:"valueIn"`
		PathElements  [][]string `json:"pathElements"`
		LeavesIndices []string   `json:"leavesIndices"`
		NullifyingKey string     `json:"nullifyingKey"`
		NPKOut        []string   `json:"npkOut"`
		ValueOut      []string   `json:"valueOut"`
	} `json:"privateInputs"`
}

func TestFormatRailgunInputsFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/railgun_format_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []railgunFormatFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}

	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
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
}

func mustRailgunFixtureInputs(t *testing.T, raw railgunFormatFixtureRaw) UnprovedTransactionInputs {
	t.Helper()
	merkleRoot := mustNumberish(t, raw.PublicInputs.MerkleRoot)
	boundParamsHash := mustNumberish(t, raw.PublicInputs.BoundParamsHash)
	tokenAddress := mustNumberish(t, raw.PrivateInputs.TokenAddress)
	nullifyingKey := mustNumberish(t, raw.PrivateInputs.NullifyingKey)
	signature := raw.Signature
	if signature[0] == "" && signature[1] == "" && signature[2] == "" {
		signature = raw.PrivateInputs.Signature
	}

	pathElements := make([][]*big.Int, len(raw.PrivateInputs.PathElements))
	for i, row := range raw.PrivateInputs.PathElements {
		pathElements[i] = mustNumberishSlice(t, row)
	}

	return UnprovedTransactionInputs{
		PublicInputs: PublicInputsRailgun{
			MerkleRoot:      merkleRoot,
			BoundParamsHash: boundParamsHash,
			Nullifiers:      mustNumberishSlice(t, raw.PublicInputs.Nullifiers),
			CommitmentsOut:  mustNumberishSlice(t, raw.PublicInputs.CommitmentsOut),
		},
		PrivateInputs: PrivateInputsRailgun{
			TokenAddress: tokenAddress,
			PublicKey: [2]*big.Int{
				mustNumberish(t, raw.PrivateInputs.PublicKey[0]),
				mustNumberish(t, raw.PrivateInputs.PublicKey[1]),
			},
			RandomIn:      mustNumberishSlice(t, raw.PrivateInputs.RandomIn),
			ValueIn:       mustNumberishSlice(t, raw.PrivateInputs.ValueIn),
			PathElements:  pathElements,
			LeavesIndices: mustNumberishSlice(t, raw.PrivateInputs.LeavesIndices),
			NullifyingKey: nullifyingKey,
			NPKOut:        mustNumberishSlice(t, raw.PrivateInputs.NPKOut),
			ValueOut:      mustNumberishSlice(t, raw.PrivateInputs.ValueOut),
		},
		Signature: [3]*big.Int{
			mustNumberish(t, signature[0]),
			mustNumberish(t, signature[1]),
			mustNumberish(t, signature[2]),
		},
	}
}

func mustNumberish(t *testing.T, value string) *big.Int {
	t.Helper()
	n, err := ParseNumberishBigInt(value)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustNumberishSlice(t *testing.T, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = mustNumberish(t, value)
	}
	return out
}

func nativeRailgunEqual(left NativeFormattedCircuitInputsRailgun, right NativeFormattedCircuitInputsRailgun) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}
