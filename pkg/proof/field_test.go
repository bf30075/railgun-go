package proof

import "testing"

func TestParseHexBigIntMatchesTypeScriptByteUtils(t *testing.T) {
	withPrefix, err := ParseHexBigInt("0x0a")
	if err != nil {
		t.Fatal(err)
	}
	withoutPrefix, err := ParseHexBigInt("0a")
	if err != nil {
		t.Fatal(err)
	}
	if withPrefix.Cmp(withoutPrefix) != 0 {
		t.Fatalf("expected prefixed and unprefixed hex to match")
	}
	if withoutPrefix.String() != "10" {
		t.Fatalf("expected 10, got %s", withoutPrefix.String())
	}
}

func TestMerkleZeroValueConstant(t *testing.T) {
	const expected = "2051258411002736885948763699317990061539314419500486054347250703186609807356"
	if MerkleZeroValue.String() != expected {
		t.Fatalf("unexpected merkle zero value: %s", MerkleZeroValue.String())
	}
}
