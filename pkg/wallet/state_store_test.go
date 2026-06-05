package wallet

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

func TestMemoryStateStoreTXOLifecycleAndBalances(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	manager := testBalancePOIManager()
	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	change := railcrypto.OutputTypeChange
	first := StoredTXO{
		TXIDVersion:    "V2_PoseidonMerkle",
		Tree:           1,
		Position:       2,
		TXID:           "txid-1",
		Nullifier:      "nullifier-1",
		TokenHash:      tokenHash,
		TokenData:      tokenData,
		Value:          big.NewInt(10),
		OutputType:     &change,
		CommitmentType: railpoi.CommitmentTypeTransactV2,
		POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
	}
	second := StoredTXO{
		TXIDVersion:    "V2_PoseidonMerkle",
		Tree:           1,
		Position:       1,
		TXID:           "txid-2",
		Nullifier:      "nullifier-2",
		TokenHash:      tokenHash,
		TokenData:      tokenData,
		Value:          big.NewInt(5),
		OutputType:     &change,
		CommitmentType: railpoi.CommitmentTypeTransactV2,
		POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
	}
	if err := store.UpsertTXO(ctx, first); err != nil {
		t.Fatal(err)
	}
	first.Value.SetInt64(999)
	if err := store.UpsertTXO(ctx, second); err != nil {
		t.Fatal(err)
	}

	txos, err := store.ListTXOs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(txos) != 2 {
		t.Fatalf("expected 2 txos, got %d", len(txos))
	}
	if txos[0].Nullifier != "nullifier-2" || txos[1].Nullifier != "nullifier-1" {
		t.Fatalf("expected txos sorted by tree position, got %+v", txos)
	}
	if txos[1].Value.String() != "10" {
		t.Fatalf("expected stored value clone to remain 10, got %s", txos[1].Value)
	}

	balances, err := store.TokenBalances(ctx, manager, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances, tokenHash, "10", 1)

	if err := store.UpdateTXOPOIs(ctx, "nullifier-2", railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid}); err != nil {
		t.Fatal(err)
	}
	balances, err = store.TokenBalances(ctx, manager, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances, tokenHash, "15", 2)

	if err := store.MarkTXOSpent(ctx, "nullifier-1", "spend-txid"); err != nil {
		t.Fatal(err)
	}
	balances, err = store.TokenBalances(ctx, manager, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances, tokenHash, "5", 1)
}

func TestMemoryStateStoreRejectsMissingTXOUpdates(t *testing.T) {
	store := NewMemoryStateStore()
	if err := store.MarkTXOSpent(context.Background(), "missing", "spend"); err == nil {
		t.Fatal("expected missing txo spend update to fail")
	}
	if err := store.UpdateTXOPOIs(context.Background(), "missing", railpoi.POIsPerList{}); err == nil {
		t.Fatal("expected missing txo poi update to fail")
	}
	if _, err := store.TokenBalances(context.Background(), nil, nil); err == nil {
		t.Fatal("expected nil poi manager to fail")
	}
}

func TestMemoryStateStoreRollbackToBlock(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	oldTXO := StoredTXO{
		Tree:        1,
		Position:    1,
		BlockNumber: 10,
		Nullifier:   "old",
		TokenData:   tokenData,
		Value:       big.NewInt(10),
	}
	newTXO := StoredTXO{
		Tree:        1,
		Position:    2,
		BlockNumber: 25,
		Nullifier:   "new",
		TokenData:   tokenData,
		Value:       big.NewInt(5),
	}
	if err := store.UpsertTXO(ctx, oldTXO); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertTXO(ctx, newTXO); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTXOSpentAtBlock(ctx, "old", "spend-new-block", 22); err != nil {
		t.Fatal(err)
	}
	if err := store.RollbackToBlock(ctx, 20); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.GetTXO(ctx, "new"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected txo created after rollback block to be removed")
	}
	got, ok, err := store.GetTXO(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected old txo to remain")
	}
	if got.SpendTXID != "" || got.SpendBlockNumber != nil {
		t.Fatalf("expected spend marker to be cleared, got %+v", got)
	}
}

func TestFileStateStorePersistsTXOLifecycleAndBalances(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "wallet-state.json")
	store := NewFileStateStore(path)
	manager := testBalancePOIManager()
	tokenData, err := railcrypto.TokenDataERC20("0x2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	change := railcrypto.OutputTypeChange
	timestamp := uint64(123456)
	txo := StoredTXO{
		TXIDVersion:                 "V3_PoseidonMerkle",
		Tree:                        2,
		Position:                    5,
		TXID:                        "txid-file",
		Timestamp:                   &timestamp,
		BlockNumber:                 77,
		Nullifier:                   "nullifier-file",
		CommitmentHash:              "commitment-file",
		NotePublicKey:               "npk-file",
		NoteRandom:                  "random-file",
		TokenHash:                   tokenHash,
		TokenData:                   tokenData,
		Value:                       big.NewInt(42),
		OutputType:                  &change,
		WalletSource:                "wallet-source",
		MemoText:                    "memo text",
		SenderAddress:               "0zksender",
		RecipientAddress:            "0zkrecipient",
		ShieldFee:                   "7",
		CommitmentType:              railpoi.CommitmentTypeTransactV3,
		POIsPerList:                 railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		BlindedCommitment:           "blinded",
		TransactCreationRailgunTxid: "railgun-txid",
	}
	if err := store.UpsertTXO(ctx, txo); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"value": "42"`) {
		t.Fatalf("expected decimal string value in file, got\n%s", raw)
	}

	reopened := NewFileStateStore(path)
	got, ok, err := reopened.GetTXO(ctx, "nullifier-file")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected persisted txo")
	}
	if got.Value.String() != "42" || got.Timestamp == nil || *got.Timestamp != timestamp || got.CommitmentHash != "commitment-file" || got.NotePublicKey != "npk-file" || got.NoteRandom != "random-file" {
		t.Fatalf("unexpected persisted txo %+v", got)
	}
	if got.WalletSource != "wallet-source" || got.MemoText != "memo text" || got.SenderAddress != "0zksender" || got.RecipientAddress != "0zkrecipient" || got.ShieldFee != "7" {
		t.Fatalf("unexpected persisted annotations %+v", got)
	}

	balances, err := reopened.TokenBalances(ctx, manager, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := balances[tokenHash]; ok {
		t.Fatal("expected missing POI txo to be excluded from spendable balance")
	}

	if err := reopened.UpdateTXOPOIs(ctx, "nullifier-file", railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid}); err != nil {
		t.Fatal(err)
	}
	balances, err = NewFileStateStore(path).TokenBalances(ctx, manager, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances, tokenHash, "42", 1)

	if err := reopened.MarkTXOSpent(ctx, "nullifier-file", "spend-file"); err != nil {
		t.Fatal(err)
	}
	balances, err = NewFileStateStore(path).TokenBalances(ctx, manager, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := balances[tokenHash]; ok {
		t.Fatal("expected spent txo to be excluded from spendable balance")
	}
}

func TestFileStateStoreRollbackToBlockPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "wallet-state.json")
	store := NewFileStateStore(path)
	tokenData, err := railcrypto.TokenDataERC20("0x2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertTXO(ctx, StoredTXO{
		Tree:        1,
		Position:    1,
		BlockNumber: 10,
		Nullifier:   "old",
		TokenData:   tokenData,
		Value:       big.NewInt(10),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertTXO(ctx, StoredTXO{
		Tree:        1,
		Position:    2,
		BlockNumber: 30,
		Nullifier:   "new",
		TokenData:   tokenData,
		Value:       big.NewInt(5),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTXOSpentAtBlock(ctx, "old", "spend-new-block", 25); err != nil {
		t.Fatal(err)
	}
	if err := store.RollbackToBlock(ctx, 20); err != nil {
		t.Fatal(err)
	}

	reopened := NewFileStateStore(path)
	if _, ok, err := reopened.GetTXO(ctx, "new"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected txo created after rollback block to be removed")
	}
	got, ok, err := reopened.GetTXO(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected old txo to remain")
	}
	if got.SpendTXID != "" || got.SpendBlockNumber != nil {
		t.Fatalf("expected spend marker to be cleared, got %+v", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "spendBlockNumber") {
		t.Fatalf("expected spend block marker to be removed, got\n%s", raw)
	}
}

func TestFileStateStoreRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet-state.json")
	if err := os.WriteFile(path, []byte(`{"txos":[{"nullifier":"n","value":"not-a-number"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewFileStateStore(path).ListTXOs(context.Background())
	if err == nil {
		t.Fatal("expected invalid value to fail")
	}
}

func testBalancePOIManager() *railpoi.Manager {
	return railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, nil)
}

func assertBalance(t *testing.T, balances TokenBalances, tokenHash string, value string, utxoCount int) {
	t.Helper()
	balance, ok := balances[tokenHash]
	if !ok {
		t.Fatalf("missing balance for token hash %s", tokenHash)
	}
	if balance.Balance.String() != value {
		t.Fatalf("expected balance %s, got %s", value, balance.Balance)
	}
	if len(balance.UTXOs) != utxoCount {
		t.Fatalf("expected %d utxos, got %d", utxoCount, len(balance.UTXOs))
	}
}
