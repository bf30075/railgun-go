package proof

import (
	"os"
	"testing"
)

func loadPOITestVector(t *testing.T) POIEngineProofInputs {
	t.Helper()
	data, err := os.ReadFile("testdata/test-vector-poi.json")
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := ParsePOIEngineProofInputsJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	return inputs
}

func TestSelectPOICircuit(t *testing.T) {
	inputs := loadPOITestVector(t)
	circuit := SelectPOICircuit(inputs)
	if circuit.Name != "POI_3X3" || circuit.MaxInputs != 3 || circuit.MaxOutputs != 3 {
		t.Fatalf("unexpected circuit: %+v", circuit)
	}
}

func TestGetPublicInputsPOIMatchesTypeScriptVector(t *testing.T) {
	inputs := loadPOITestVector(t)
	publicInputs, err := GetPublicInputsPOI(
		inputs.AnyRailgunTxidMerklerootAfterTransaction,
		nil,
		inputs.POIMerkleRoots,
		inputs.RailgunTxidIfHasUnshield,
		3,
		3,
	)
	if err != nil {
		t.Fatal(err)
	}

	if publicInputs.AnyRailgunTxidMerklerootAfterTransaction.String() != "11019437426225148358311556875836248687006846610001820581512966955070859864181" {
		t.Fatalf("unexpected txid merkleroot: %s", publicInputs.AnyRailgunTxidMerklerootAfterTransaction)
	}
	if len(publicInputs.BlindedCommitmentsOut) != 3 {
		t.Fatalf("expected 3 blinded commitments out, got %d", len(publicInputs.BlindedCommitmentsOut))
	}
	for i, value := range publicInputs.BlindedCommitmentsOut {
		if value.Sign() != 0 {
			t.Fatalf("expected zero blinded commitment at %d, got %s", i, value)
		}
	}
	if len(publicInputs.POIMerkleRoots) != 3 {
		t.Fatalf("expected 3 poi roots, got %d", len(publicInputs.POIMerkleRoots))
	}
	if publicInputs.POIMerkleRoots[1].Cmp(MerkleZeroValue) != 0 || publicInputs.POIMerkleRoots[2].Cmp(MerkleZeroValue) != 0 {
		t.Fatalf("expected padded POI roots to use Railgun merkle zero value")
	}
}

func TestFormatPOIInputsMatchesTypeScriptPadding(t *testing.T) {
	inputs := loadPOITestVector(t)
	formatted, err := FormatPOIInputs(inputs, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	native := formatted.NativeInputs()

	if native.BoundParamsHash != "4661797874939845348508326997048879240636549591648639333359732436996901146055" {
		t.Fatalf("unexpected bound params hash: %s", native.BoundParamsHash)
	}
	if len(native.Nullifiers) != 3 {
		t.Fatalf("expected 3 nullifiers, got %d", len(native.Nullifiers))
	}
	if native.Nullifiers[0] != "2488005839880174281371566850742862351218389849446606448043615745372921337838" {
		t.Fatalf("unexpected first nullifier: %s", native.Nullifiers[0])
	}
	if native.Nullifiers[1] != MerkleZeroValue.String() || native.Nullifiers[2] != MerkleZeroValue.String() {
		t.Fatalf("expected padded nullifiers to use Railgun merkle zero value")
	}
	if len(native.ValuesIn) != 3 {
		t.Fatalf("expected valuesIn padded to max outputs, got %d", len(native.ValuesIn))
	}
	if native.ValuesIn[0] != "109725000000000000000000" || native.ValuesIn[1] != "0" || native.ValuesIn[2] != "0" {
		t.Fatalf("unexpected valuesIn: %+v", native.ValuesIn)
	}
	if len(native.POIInMerkleProofPathElements) != 3 {
		t.Fatalf("expected 3 POI path rows, got %d", len(native.POIInMerkleProofPathElements))
	}
	if len(native.POIInMerkleProofPathElements[1]) != 16 {
		t.Fatalf("expected padded POI path row length 16, got %d", len(native.POIInMerkleProofPathElements[1]))
	}
	if native.POIInMerkleProofPathElements[1][0] != MerkleZeroValue.String() {
		t.Fatalf("expected padded POI path element to use Railgun merkle zero value")
	}
}
