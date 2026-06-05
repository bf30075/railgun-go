package wallet

import (
	"context"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
)

func TestSyncV2FromCheckpointScansThenSavesCheckpoint(t *testing.T) {
	ctx := context.Background()
	provider := &walletSyncProvider{latest: 15}
	checkpoints := railevents.NewMemoryCheckpointStore()
	if err := checkpoints.SaveCheckpoint(ctx, "v2", railevents.ScanCheckpoint{NextBlock: 10}); err != nil {
		t.Fatal(err)
	}

	result, err := SyncV2FromCheckpoint(ctx, provider, checkpoints, NewMemoryStateStore(), testSyncKeys(), railevents.CheckpointedScan{
		Key:           "v2",
		Addresses:     []string{"0x1111111111111111111111111111111111111111"},
		StartBlock:    1,
		ChunkSize:     2,
		Confirmations: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, result, SyncResult{
		FromBlock: 10,
		ToBlock:   13,
		Scanned:   true,
		Checkpoint: railevents.ScanCheckpoint{
			NextBlock: 14,
		},
		Import: ImportSummary{},
	})
	saved, ok, err := checkpoints.LoadCheckpoint(ctx, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected saved checkpoint")
	}
	assertJSONEqual(t, saved, railevents.ScanCheckpoint{NextBlock: 14})
	assertWalletSyncFilters(t, provider.calls, []railevents.LogFilter{
		{
			Addresses: []string{"0x1111111111111111111111111111111111111111"},
			FromBlock: 10,
			ToBlock:   11,
		},
		{
			Addresses: []string{"0x1111111111111111111111111111111111111111"},
			FromBlock: 12,
			ToBlock:   13,
		},
	})
}

func TestSyncV3FromCheckpointSkipsWhenNoFinalizedBlock(t *testing.T) {
	ctx := context.Background()
	provider := &walletSyncProvider{latest: 3}
	checkpoints := railevents.NewMemoryCheckpointStore()

	result, err := SyncV3FromCheckpoint(ctx, provider, checkpoints, NewMemoryStateStore(), testSyncKeys(), railevents.CheckpointedScan{
		Key:           "v3",
		StartBlock:    10,
		Confirmations: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, result, SyncResult{
		FromBlock:  10,
		Checkpoint: railevents.ScanCheckpoint{NextBlock: 10},
	})
	if len(provider.calls) != 0 {
		t.Fatalf("expected no log scans, got %d", len(provider.calls))
	}
	if _, ok, err := checkpoints.LoadCheckpoint(ctx, "v3"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected checkpoint to remain unsaved")
	}
}

func TestSyncV2FromCheckpointDoesNotSaveOnFailure(t *testing.T) {
	ctx := context.Background()
	provider := &walletSyncProvider{latest: 15}
	checkpoints := railevents.NewMemoryCheckpointStore()
	_, err := SyncV2FromCheckpoint(ctx, provider, checkpoints, NewMemoryStateStore(), ScanKeys{}, railevents.CheckpointedScan{
		Key:        "v2",
		StartBlock: 10,
	})
	if err == nil || !strings.Contains(err.Error(), "master public key") {
		t.Fatalf("expected key validation error, got %v", err)
	}
	if len(provider.calls) != 0 {
		t.Fatalf("expected validation to fail before scanning, got %d scans", len(provider.calls))
	}
	if _, ok, err := checkpoints.LoadCheckpoint(ctx, "v2"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected checkpoint to remain unsaved")
	}
}

func TestSyncV2FromCheckpointSavesCheckpointAfterEachChunk(t *testing.T) {
	ctx := context.Background()
	provider := &walletSyncProvider{latest: 15, failOnCall: 2}
	checkpoints := railevents.NewMemoryCheckpointStore()

	_, err := SyncV2FromCheckpoint(ctx, provider, checkpoints, NewMemoryStateStore(), testSyncKeys(), railevents.CheckpointedScan{
		Key:        "v2",
		StartBlock: 10,
		ChunkSize:  2,
	})
	if err == nil || !strings.Contains(err.Error(), "temporary failure") {
		t.Fatalf("expected second chunk failure, got %v", err)
	}
	saved, ok, err := checkpoints.LoadCheckpoint(ctx, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checkpoint after first chunk")
	}
	assertJSONEqual(t, saved, railevents.ScanCheckpoint{NextBlock: 12})
}

func TestRollbackWalletSyncRollsBackStateAndCheckpoint(t *testing.T) {
	ctx := context.Background()
	checkpoints := railevents.NewMemoryCheckpointStore()
	if err := checkpoints.SaveCheckpoint(ctx, "v2", railevents.ScanCheckpoint{NextBlock: 50}); err != nil {
		t.Fatal(err)
	}
	state := NewMemoryStateStore()
	if err := state.UpsertTXO(ctx, StoredTXO{
		Tree:        0,
		Position:    1,
		BlockNumber: 10,
		Nullifier:   "old",
		Value:       big.NewInt(1),
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.UpsertTXO(ctx, StoredTXO{
		Tree:        0,
		Position:    2,
		BlockNumber: 45,
		Nullifier:   "new",
		Value:       big.NewInt(2),
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkTXOSpentAtBlock(ctx, "old", "spend", 42); err != nil {
		t.Fatal(err)
	}

	if err := RollbackWalletSync(ctx, checkpoints, state, "v2", 40); err != nil {
		t.Fatal(err)
	}
	saved, ok, err := checkpoints.LoadCheckpoint(ctx, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checkpoint")
	}
	assertJSONEqual(t, saved, railevents.ScanCheckpoint{NextBlock: 40})
	if _, ok, err := state.GetTXO(ctx, "new"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected new txo to be removed")
	}
	old, ok, err := state.GetTXO(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected old txo")
	}
	if old.SpendTXID != "" || old.SpendBlockNumber != nil {
		t.Fatalf("expected spend marker to roll back, got %+v", old)
	}
}

func TestRollbackWalletSyncWithAllStoresRollsBackUTXOTree(t *testing.T) {
	ctx := context.Background()
	checkpoints := railevents.NewMemoryCheckpointStore()
	if err := checkpoints.SaveCheckpoint(ctx, "v2", railevents.ScanCheckpoint{NextBlock: 50}); err != nil {
		t.Fatal(err)
	}
	state := NewMemoryStateStore()
	utxoTree := railutxotree.NewMemoryStore()
	if err := utxoTree.UpsertLeaf(ctx, railutxotree.Leaf{Tree: 0, Index: 0, Hash: mustSyncHash(t, 1), BlockNumber: 20}); err != nil {
		t.Fatal(err)
	}
	if err := utxoTree.UpsertLeaf(ctx, railutxotree.Leaf{Tree: 0, Index: 1, Hash: mustSyncHash(t, 2), BlockNumber: 45}); err != nil {
		t.Fatal(err)
	}

	if err := RollbackWalletSyncWithAllStores(ctx, checkpoints, state, nil, nil, utxoTree, nil, "v2", 40); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := utxoTree.GetLeaf(ctx, 0, 1); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove new utxo tree leaf")
	}
	if _, ok, err := utxoTree.GetLeaf(ctx, 0, 0); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected older utxo tree leaf to remain")
	}
}

type walletSyncProvider struct {
	latest     uint64
	calls      []railevents.LogFilter
	failOnCall int
}

func (provider *walletSyncProvider) BlockNumber(context.Context) (uint64, error) {
	return provider.latest, nil
}

func (provider *walletSyncProvider) FilterLogs(_ context.Context, filter railevents.LogFilter) ([]railevents.ContractLog, error) {
	provider.calls = append(provider.calls, filter)
	if provider.failOnCall > 0 && len(provider.calls) == provider.failOnCall {
		return nil, fmt.Errorf("temporary failure")
	}
	return nil, nil
}

func testSyncKeys() ScanKeys {
	return ScanKeys{
		MasterPublicKey:   big.NewInt(1),
		ViewingPrivateKey: []byte{1},
		ViewingPublicKey:  []byte{2},
		NullifyingKey:     big.NewInt(3),
	}
}

func mustSyncHash(t *testing.T, value int64) string {
	t.Helper()
	hash, err := railcrypto.BigIntToHex(big.NewInt(value), 32, false)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func assertWalletSyncFilters(t *testing.T, got []railevents.LogFilter, expected []railevents.LogFilter) {
	t.Helper()
	if len(got) != len(expected) {
		t.Fatalf("expected %d filters, got %d", len(expected), len(got))
	}
	for i := range expected {
		if got[i].FromBlock != expected[i].FromBlock || got[i].ToBlock != expected[i].ToBlock {
			t.Fatalf("filter[%d] expected range %d-%d, got %d-%d", i, expected[i].FromBlock, expected[i].ToBlock, got[i].FromBlock, got[i].ToBlock)
		}
		if !reflect.DeepEqual(got[i].Addresses, expected[i].Addresses) {
			t.Fatalf("filter[%d] expected addresses %v, got %v", i, expected[i].Addresses, got[i].Addresses)
		}
		if len(got[i].Topics) != 1 {
			t.Fatalf("filter[%d] expected one topic group, got %d", i, len(got[i].Topics))
		}
		if len(got[i].Topics[0]) == 0 {
			t.Fatalf("filter[%d] expected event topics", i)
		}
	}
}

func ExampleRollbackWalletSync_requiresRollbackStore() {
	err := RollbackWalletSync(context.Background(), railevents.NewMemoryCheckpointStore(), nil, "v2", 10)
	fmt.Println(err != nil)
	// Output: true
}
