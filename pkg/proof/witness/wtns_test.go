package witness

import (
	"testing"
)

func TestParseWTNSRejectsInvalidMagic(t *testing.T) {
	if _, err := ParseWTNS([]byte("nope")); err == nil {
		t.Fatal("expected invalid magic error")
	}
}

func TestSHA256Hex(t *testing.T) {
	if got := SHA256Hex([]byte("railgun")); got != "5d0afac6783502d701ebd089be93f497bd46ea52b0fb2a4304a952572899aadb" {
		t.Fatalf("unexpected sha256: %s", got)
	}
}

func TestLittleEndianToBigInt(t *testing.T) {
	got := littleEndianToBigInt([]byte{0x34, 0x12})
	if got.String() != "4660" {
		t.Fatalf("unexpected integer: %s", got)
	}
}
