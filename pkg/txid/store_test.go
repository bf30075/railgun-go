package txid

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestMemoryTransactionStoreLifecycleAndRollback(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTransactionStore()
	first := testTransaction("railgun-1", 20)
	second := testTransaction("railgun-2", 10)
	if err := store.UpsertTransaction(ctx, first); err != nil {
		t.Fatal(err)
	}
	first.Commitments[0] = "mutated"
	if err := store.UpsertTransaction(ctx, second); err != nil {
		t.Fatal(err)
	}

	got, ok, err := store.GetByRailgunTxid(ctx, "railgun-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected transaction")
	}
	if got.Commitments[0] != "0x01" {
		t.Fatalf("expected stored commitment clone, got %+v", got.Commitments)
	}
	got.Commitments[0] = "mutated-again"
	got, ok, err = store.GetByRailgunTxid(ctx, "railgun-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Commitments[0] != "0x01" {
		t.Fatalf("expected returned transaction clone, got %+v", got)
	}

	transactions, err := store.ListTransactions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(transactions) != 2 || transactions[0].RailgunTxid != "railgun-2" || transactions[1].RailgunTxid != "railgun-1" {
		t.Fatalf("expected transactions sorted by block number, got %+v", transactions)
	}
	if err := store.RollbackToBlock(ctx, 20); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.GetByRailgunTxid(ctx, "railgun-1"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove transaction at rollback block")
	}
	if _, ok, err := store.GetByRailgunTxid(ctx, "railgun-2"); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected older transaction to remain")
	}
}

func TestFileTransactionStorePersistsAndRollsBack(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "txids.json")
	store := NewFileTransactionStore(path)
	if err := store.UpsertTransaction(ctx, testTransaction("railgun-1", 20)); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertTransaction(ctx, testTransaction("railgun-2", 30)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"railgunTxid": "railgun-1"`) {
		t.Fatalf("expected persisted railgun txid, got\n%s", raw)
	}

	got, ok, err := NewFileTransactionStore(path).GetByRailgunTxid(ctx, "railgun-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.BlockNumber != 20 || got.Unshield == nil || got.Unshield.Value != "5" || got.Unshield.Fee != "1" {
		t.Fatalf("unexpected persisted transaction %+v", got)
	}
	if err := store.RollbackToBlock(ctx, 25); err != nil {
		t.Fatal(err)
	}
	transactions, err := NewFileTransactionStore(path).ListTransactions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(transactions) != 1 || transactions[0].RailgunTxid != "railgun-1" {
		t.Fatalf("expected rollback to keep only older transaction, got %+v", transactions)
	}
}

func TestTransactionStoreRejectsMissingRailgunTxid(t *testing.T) {
	if err := NewMemoryTransactionStore().UpsertTransaction(context.Background(), Transaction{}); err == nil {
		t.Fatal("expected missing railgun txid to fail")
	}
}

func testTransaction(railgunTxid string, blockNumber uint64) Transaction {
	token, _ := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	return Transaction{
		Version:                   "V3",
		RailgunTxid:               railgunTxid,
		Txid:                      "0xtxid",
		BlockNumber:               blockNumber,
		Commitments:               []string{"0x01"},
		Nullifiers:                []string{"0x02"},
		BoundParamsHash:           "0x03",
		UTXOTreeIn:                1,
		UTXOTreeOut:               2,
		UTXOBatchStartPositionOut: 3,
		VerificationHash:          "0x04",
		Unshield: &UnshieldData{
			TokenData: token,
			ToAddress: "0x1111111111111111111111111111111111111111",
			Value:     "5",
			Fee:       "1",
		},
	}
}
