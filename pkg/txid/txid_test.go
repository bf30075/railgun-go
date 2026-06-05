package txid

import (
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestRailgunTransactionIDMatchesPOIVector(t *testing.T) {
	fixtures := loadTxidFixtures(t)
	transaction := fixtures.POITransaction
	id, err := RailgunTransactionIDHex(
		transaction.Nullifiers,
		transaction.Commitments,
		transaction.BoundParamsHash,
	)
	if err != nil {
		t.Fatal(err)
	}
	if id != transaction.RailgunTxid {
		t.Fatalf("unexpected txid: %s", id)
	}
	idBig, err := railcrypto.HexToBigInt(id)
	if err != nil {
		t.Fatal(err)
	}
	if idBig.String() != transaction.RailgunTxidDecimal {
		t.Fatalf("expected txid decimal %s, got %s", transaction.RailgunTxidDecimal, idBig)
	}
}

func TestRailgunTxidLeafHashMatchesPOIVector(t *testing.T) {
	fixtures := loadTxidFixtures(t)
	transaction := fixtures.POITransaction
	id, err := railcrypto.HexToBigInt(transaction.RailgunTxid)
	if err != nil {
		t.Fatal(err)
	}
	globalTreePosition := GetGlobalTreePosition(transaction.UTXOTreeOut, transaction.UTXOBatchStartPositionOut)
	if globalTreePosition.String() != transaction.GlobalTreePosition {
		t.Fatalf("expected global tree position %s, got %s", transaction.GlobalTreePosition, globalTreePosition)
	}
	leaf, err := RailgunTxidLeafHash(id, transaction.UTXOTreeIn, globalTreePosition)
	if err != nil {
		t.Fatal(err)
	}
	if leaf != transaction.LeafHash {
		t.Fatalf("unexpected leaf hash: %s", leaf)
	}
}

func TestRailgunTransactionIDRejectsNilBigInts(t *testing.T) {
	_, err := RailgunTransactionIDFromBigInts(nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "bound params hash is required") {
		t.Fatalf("expected bound params error, got %v", err)
	}
	_, err = RailgunTransactionIDFromBigInts([]*big.Int{nil}, nil, big.NewInt(1))
	if err == nil || !strings.Contains(err.Error(), "nullifiers[0] is required") {
		t.Fatalf("expected nullifier error, got %v", err)
	}
	_, err = RailgunTransactionIDFromBigInts(nil, []*big.Int{nil}, big.NewInt(1))
	if err == nil || !strings.Contains(err.Error(), "commitments[0] is required") {
		t.Fatalf("expected commitment error, got %v", err)
	}
	if _, err := RailgunTxidLeafHash(nil, 0, big.NewInt(1)); err == nil || !strings.Contains(err.Error(), "railgun txid is required") {
		t.Fatalf("expected railgun txid error, got %v", err)
	}
	if _, err := RailgunTxidLeafHash(big.NewInt(1), 0, nil); err == nil || !strings.Contains(err.Error(), "global tree position is required") {
		t.Fatalf("expected global tree position error, got %v", err)
	}
}

func TestGlobalTreePosition(t *testing.T) {
	fixtures := loadTxidFixtures(t)
	for _, vector := range fixtures.GlobalTreePositions {
		got := GetGlobalTreePosition(vector.Tree, vector.Index)
		if got.String() != vector.Output {
			t.Fatalf("expected global tree position %s for tree %d index %d, got %s", vector.Output, vector.Tree, vector.Index, got)
		}
	}
}

func TestCalculateVerificationHashMatchesTypeScript(t *testing.T) {
	fixtures := loadTxidFixtures(t)
	got, err := CalculateVerificationHash(
		fixtures.VerificationHash.PreviousVerificationHash,
		fixtures.VerificationHash.FirstNullifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != fixtures.VerificationHash.Output {
		t.Fatalf("expected verification hash %s, got %s", fixtures.VerificationHash.Output, got)
	}
}

type exportedFixtures struct {
	TxidFixtures txidFixtureSet `json:"txidFixtures"`
}

type txidFixtureSet struct {
	POITransaction      poiTransactionFixture       `json:"poiTransaction"`
	GlobalTreePositions []globalTreePositionFixture `json:"globalTreePositions"`
	VerificationHash    verificationHashFixture     `json:"verificationHash"`
}

type poiTransactionFixture struct {
	Nullifiers                []string `json:"nullifiers"`
	Commitments               []string `json:"commitments"`
	BoundParamsHash           string   `json:"boundParamsHash"`
	RailgunTxid               string   `json:"railgunTxid"`
	RailgunTxidDecimal        string   `json:"railgunTxidDecimal"`
	UTXOTreeIn                uint64   `json:"utxoTreeIn"`
	UTXOTreeOut               uint64   `json:"utxoTreeOut"`
	UTXOBatchStartPositionOut uint64   `json:"utxoBatchStartPositionOut"`
	GlobalTreePosition        string   `json:"globalTreePosition"`
	LeafHash                  string   `json:"leafHash"`
}

type globalTreePositionFixture struct {
	Tree   uint64 `json:"tree"`
	Index  uint64 `json:"index"`
	Output string `json:"output"`
}

type verificationHashFixture struct {
	PreviousVerificationHash string `json:"previousVerificationHash"`
	FirstNullifier           string `json:"firstNullifier"`
	Output                   string `json:"output"`
}

func loadTxidFixtures(t *testing.T) txidFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.TxidFixtures
}
