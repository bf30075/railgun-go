package merkletree

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifySingleStepMerkleProof(t *testing.T) {
	fixtures := loadMerkleFixtures(t)
	ok, err := VerifyProof(fixtures.SingleStepProof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected proof to verify")
	}
}

func TestVerifyPOITxidMerkleProof(t *testing.T) {
	fixtures := loadMerkleFixtures(t)
	if !fixtures.POITxidProofVerified {
		t.Fatal("fixture expected TypeScript Merkle verification to pass")
	}
	ok, err := VerifyProof(fixtures.POITxidProof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected proof to verify")
	}
}

type exportedFixtures struct {
	MerkleFixtures merkleFixtureSet `json:"merkleFixtures"`
}

type merkleFixtureSet struct {
	SingleStepProof      MerkleProof `json:"singleStepProof"`
	POITxidProof         MerkleProof `json:"poiTxidProof"`
	POITxidProofVerified bool        `json:"poiTxidProofVerified"`
}

func loadMerkleFixtures(t *testing.T) merkleFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.MerkleFixtures
}
