package proof

import "testing"

func TestBuildPublicSignalsRailgunOrder(t *testing.T) {
	inputs := PublicInputsRailgun{
		MerkleRoot:      mustNumberish(t, "1"),
		BoundParamsHash: mustNumberish(t, "2"),
		Nullifiers:      mustNumberishSlice(t, []string{"3", "4"}),
		CommitmentsOut:  mustNumberishSlice(t, []string{"5", "6", "7"}),
	}
	got := bigIntStrings(BuildPublicSignalsRailgun(inputs))
	expected := []string{"1", "2", "3", "4", "5", "6", "7"}
	if len(got) != len(expected) {
		t.Fatalf("expected %d signals, got %d", len(expected), len(got))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("signal %d mismatch: expected %s, got %s", i, expected[i], got[i])
		}
	}
}

func TestBuildPublicSignalsPOIOrder(t *testing.T) {
	inputs := PublicInputsPOI{
		BlindedCommitmentsOut:                    mustNumberishSlice(t, []string{"1", "2"}),
		AnyRailgunTxidMerklerootAfterTransaction: mustNumberish(t, "3"),
		RailgunTxidIfHasUnshield:                 mustNumberish(t, "4"),
		POIMerkleRoots:                           mustNumberishSlice(t, []string{"5", "6"}),
	}
	got := bigIntStrings(BuildPublicSignalsPOI(inputs))
	expected := []string{"1", "2", "3", "4", "5", "6"}
	if len(got) != len(expected) {
		t.Fatalf("expected %d signals, got %d", len(expected), len(got))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("signal %d mismatch: expected %s, got %s", i, expected[i], got[i])
		}
	}
}
