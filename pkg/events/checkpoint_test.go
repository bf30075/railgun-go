package events

import (
	"context"
	"path/filepath"
	"testing"
)

func TestScanV2EventsFromCheckpointScansFinalizedRangeAndSaves(t *testing.T) {
	fixture := loadEventFixtures(t).V2
	provider := &stubLogProvider{
		latest: 13,
		logs: [][]ContractLog{
			{fixture.Shield.Log},
			{fixture.Transact.Log, fixture.Unshield.Log},
		},
	}
	store := NewMemoryCheckpointStore()
	if err := store.SaveCheckpoint(context.Background(), "v2:test", ScanCheckpoint{NextBlock: 10}); err != nil {
		t.Fatal(err)
	}

	got, checkpoint, err := ScanV2EventsFromCheckpoint(context.Background(), provider, store, CheckpointedScan{
		Key:           "v2:test",
		Addresses:     []string{"0x1111111111111111111111111111111111111111"},
		StartBlock:    1,
		ChunkSize:     2,
		Confirmations: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := V2AccumulatedEvents{
		CommitmentEvents: []CommitmentEvent{
			fixture.Shield.Formatted,
			fixture.Transact.Formatted,
		},
		NullifierEvents: []Nullifier{},
		UnshieldEvents: []UnshieldStoredEvent{
			fixture.Unshield.Formatted,
		},
	}
	assertJSONEqual(t, got, expected)
	assertJSONEqual(t, checkpoint, ScanCheckpoint{NextBlock: 13})

	saved, ok, err := store.LoadCheckpoint(context.Background(), "v2:test")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected saved checkpoint")
	}
	assertJSONEqual(t, saved, ScanCheckpoint{NextBlock: 13})

	if len(provider.calls) != 2 {
		t.Fatalf("expected 2 provider calls, got %d", len(provider.calls))
	}
	assertFilter(t, provider.calls[0], 10, 11, []string{"0x1111111111111111111111111111111111111111"}, []string{
		fixture.Topics.Shield,
		fixture.Topics.Transact,
		fixture.Topics.Unshield,
		fixture.Topics.Nullified,
	})
	assertFilter(t, provider.calls[1], 12, 12, []string{"0x1111111111111111111111111111111111111111"}, []string{
		fixture.Topics.Shield,
		fixture.Topics.Transact,
		fixture.Topics.Unshield,
		fixture.Topics.Nullified,
	})
}

func TestScanV3EventsFromCheckpointSkipsWhenNoFinalizedBlock(t *testing.T) {
	provider := &stubLogProvider{latest: 3}
	store := NewMemoryCheckpointStore()

	got, checkpoint, err := ScanV3EventsFromCheckpoint(context.Background(), provider, store, CheckpointedScan{
		Key:           "v3:test",
		StartBlock:    10,
		Confirmations: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, got, emptyV3AccumulatorEvents())
	assertJSONEqual(t, checkpoint, ScanCheckpoint{NextBlock: 10})
	if len(provider.calls) != 0 {
		t.Fatalf("expected no log provider calls, got %d", len(provider.calls))
	}
	if _, ok, err := store.LoadCheckpoint(context.Background(), "v3:test"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected checkpoint to remain unsaved")
	}
}

func TestFileCheckpointStoreRoundTrips(t *testing.T) {
	store := FileCheckpointStore{Path: filepath.Join(t.TempDir(), "checkpoints.json")}
	ctx := context.Background()
	if _, ok, err := store.LoadCheckpoint(ctx, "scan"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected missing checkpoint")
	}
	if err := store.SaveCheckpoint(ctx, "scan", ScanCheckpoint{NextBlock: 123}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadCheckpoint(ctx, "scan")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checkpoint")
	}
	assertJSONEqual(t, got, ScanCheckpoint{NextBlock: 123})
}

func TestMemoryCheckpointStoreRollbackOnlyMovesBackward(t *testing.T) {
	store := NewMemoryCheckpointStore()
	ctx := context.Background()
	if err := store.SaveCheckpoint(ctx, "scan", ScanCheckpoint{NextBlock: 100}); err != nil {
		t.Fatal(err)
	}
	if err := store.RollbackCheckpoint(ctx, "scan", 80); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadCheckpoint(ctx, "scan")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checkpoint")
	}
	assertJSONEqual(t, got, ScanCheckpoint{NextBlock: 80})

	if err := store.RollbackCheckpoint(ctx, "scan", 120); err != nil {
		t.Fatal(err)
	}
	got, ok, err = store.LoadCheckpoint(ctx, "scan")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checkpoint")
	}
	assertJSONEqual(t, got, ScanCheckpoint{NextBlock: 80})
}

func TestFileCheckpointStoreRollbackPreservesOtherCheckpoints(t *testing.T) {
	store := FileCheckpointStore{Path: filepath.Join(t.TempDir(), "checkpoints.json")}
	ctx := context.Background()
	if err := store.SaveCheckpoint(ctx, "scan", ScanCheckpoint{NextBlock: 100}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCheckpoint(ctx, "other", ScanCheckpoint{NextBlock: 25}); err != nil {
		t.Fatal(err)
	}
	if err := RollbackScanCheckpoint(ctx, store, "scan", 60); err != nil {
		t.Fatal(err)
	}
	if err := RollbackScanCheckpoint(ctx, store, "scan", 90); err != nil {
		t.Fatal(err)
	}

	got, ok, err := store.LoadCheckpoint(ctx, "scan")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checkpoint")
	}
	assertJSONEqual(t, got, ScanCheckpoint{NextBlock: 60})
	other, ok, err := store.LoadCheckpoint(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected other checkpoint")
	}
	assertJSONEqual(t, other, ScanCheckpoint{NextBlock: 25})
}
