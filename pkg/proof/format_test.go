package proof

import "testing"

func TestFormatProofSwapsPiBCoordinatesForSolidity(t *testing.T) {
	formatted, err := FormatProof(Proof{
		PiA: [2]string{"1", "2"},
		PiB: [2][2]string{
			{"3", "4"},
			{"5", "6"},
		},
		PiC: [2]string{"7", "8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if formatted.B.X[0].String() != "4" || formatted.B.X[1].String() != "3" {
		t.Fatalf("unexpected B.X order: %s, %s", formatted.B.X[0], formatted.B.X[1])
	}
	if formatted.B.Y[0].String() != "6" || formatted.B.Y[1].String() != "5" {
		t.Fatalf("unexpected B.Y order: %s, %s", formatted.B.Y[0], formatted.B.Y[1])
	}
}
