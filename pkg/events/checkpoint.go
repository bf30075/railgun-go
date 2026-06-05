package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type BlockNumberProvider interface {
	BlockNumber(ctx context.Context) (uint64, error)
}

type CheckpointedLogProvider interface {
	LogProvider
	BlockNumberProvider
}

type ScanCheckpoint struct {
	NextBlock uint64 `json:"nextBlock"`
}

type CheckpointStore interface {
	LoadCheckpoint(ctx context.Context, key string) (ScanCheckpoint, bool, error)
	SaveCheckpoint(ctx context.Context, key string, checkpoint ScanCheckpoint) error
}

type CheckpointRollbackStore interface {
	RollbackCheckpoint(ctx context.Context, key string, nextBlock uint64) error
}

type CheckpointedScan struct {
	Key           string
	Addresses     []string
	StartBlock    uint64
	ChunkSize     uint64
	Confirmations uint64
}

type MemoryCheckpointStore struct {
	mu          sync.Mutex
	checkpoints map[string]ScanCheckpoint
}

func NewMemoryCheckpointStore() *MemoryCheckpointStore {
	return &MemoryCheckpointStore{checkpoints: map[string]ScanCheckpoint{}}
}

func (store *MemoryCheckpointStore) LoadCheckpoint(ctx context.Context, key string) (ScanCheckpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return ScanCheckpoint{}, false, err
	}
	if store == nil {
		return ScanCheckpoint{}, false, fmt.Errorf("checkpoint store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	checkpoint, ok := store.checkpoints[key]
	return checkpoint, ok, nil
}

func (store *MemoryCheckpointStore) SaveCheckpoint(ctx context.Context, key string, checkpoint ScanCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("checkpoint store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoints == nil {
		store.checkpoints = map[string]ScanCheckpoint{}
	}
	store.checkpoints[key] = checkpoint
	return nil
}

func (store *MemoryCheckpointStore) RollbackCheckpoint(ctx context.Context, key string, nextBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("checkpoint store is required")
	}
	if key == "" {
		return fmt.Errorf("checkpoint key is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoints == nil {
		store.checkpoints = map[string]ScanCheckpoint{}
	}
	checkpoint, ok := store.checkpoints[key]
	if ok && nextBlock >= checkpoint.NextBlock {
		return nil
	}
	store.checkpoints[key] = ScanCheckpoint{NextBlock: nextBlock}
	return nil
}

type FileCheckpointStore struct {
	Path string
}

func (store FileCheckpointStore) LoadCheckpoint(ctx context.Context, key string) (ScanCheckpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return ScanCheckpoint{}, false, err
	}
	if store.Path == "" {
		return ScanCheckpoint{}, false, fmt.Errorf("checkpoint file path is required")
	}
	checkpoints, err := store.loadAll()
	if err != nil {
		return ScanCheckpoint{}, false, err
	}
	checkpoint, ok := checkpoints[key]
	return checkpoint, ok, nil
}

func (store FileCheckpointStore) SaveCheckpoint(ctx context.Context, key string, checkpoint ScanCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store.Path == "" {
		return fmt.Errorf("checkpoint file path is required")
	}
	checkpoints, err := store.loadAll()
	if err != nil {
		return err
	}
	checkpoints[key] = checkpoint
	return store.saveAll(checkpoints)
}

func (store FileCheckpointStore) RollbackCheckpoint(ctx context.Context, key string, nextBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store.Path == "" {
		return fmt.Errorf("checkpoint file path is required")
	}
	if key == "" {
		return fmt.Errorf("checkpoint key is required")
	}
	checkpoints, err := store.loadAll()
	if err != nil {
		return err
	}
	checkpoint, ok := checkpoints[key]
	if ok && nextBlock >= checkpoint.NextBlock {
		return nil
	}
	checkpoints[key] = ScanCheckpoint{NextBlock: nextBlock}
	return store.saveAll(checkpoints)
}

func RollbackScanCheckpoint(ctx context.Context, store CheckpointStore, key string, nextBlock uint64) error {
	if store == nil {
		return fmt.Errorf("checkpoint store is required")
	}
	if rollbackStore, ok := store.(CheckpointRollbackStore); ok {
		return rollbackStore.RollbackCheckpoint(ctx, key, nextBlock)
	}
	if key == "" {
		return fmt.Errorf("checkpoint key is required")
	}
	checkpoint, ok, err := store.LoadCheckpoint(ctx, key)
	if err != nil {
		return err
	}
	if ok && nextBlock >= checkpoint.NextBlock {
		return nil
	}
	return store.SaveCheckpoint(ctx, key, ScanCheckpoint{NextBlock: nextBlock})
}

func ScanV2EventsFromCheckpoint(ctx context.Context, provider CheckpointedLogProvider, store CheckpointStore, scan CheckpointedScan) (V2AccumulatedEvents, ScanCheckpoint, error) {
	out := emptyV2AccumulatedEvents()
	from, err := checkpointStartBlock(ctx, store, scan)
	if err != nil {
		return V2AccumulatedEvents{}, ScanCheckpoint{}, err
	}
	to, ok, err := finalizedToBlock(ctx, provider, scan.Confirmations)
	if err != nil {
		return V2AccumulatedEvents{}, ScanCheckpoint{}, err
	}
	checkpoint := ScanCheckpoint{NextBlock: from}
	if !ok || to < from {
		return out, checkpoint, nil
	}
	out, err = ScanV2Events(ctx, provider, ScanRange{
		Addresses: scan.Addresses,
		FromBlock: from,
		ToBlock:   to,
		ChunkSize: scan.ChunkSize,
	})
	if err != nil {
		return V2AccumulatedEvents{}, ScanCheckpoint{}, err
	}
	checkpoint.NextBlock = to + 1
	if err := store.SaveCheckpoint(ctx, scan.Key, checkpoint); err != nil {
		return V2AccumulatedEvents{}, ScanCheckpoint{}, err
	}
	return out, checkpoint, nil
}

func ScanV3EventsFromCheckpoint(ctx context.Context, provider CheckpointedLogProvider, store CheckpointStore, scan CheckpointedScan) (V3AccumulatorEvents, ScanCheckpoint, error) {
	out := emptyV3AccumulatorEvents()
	from, err := checkpointStartBlock(ctx, store, scan)
	if err != nil {
		return V3AccumulatorEvents{}, ScanCheckpoint{}, err
	}
	to, ok, err := finalizedToBlock(ctx, provider, scan.Confirmations)
	if err != nil {
		return V3AccumulatorEvents{}, ScanCheckpoint{}, err
	}
	checkpoint := ScanCheckpoint{NextBlock: from}
	if !ok || to < from {
		return out, checkpoint, nil
	}
	out, err = ScanV3Events(ctx, provider, ScanRange{
		Addresses: scan.Addresses,
		FromBlock: from,
		ToBlock:   to,
		ChunkSize: scan.ChunkSize,
	})
	if err != nil {
		return V3AccumulatorEvents{}, ScanCheckpoint{}, err
	}
	checkpoint.NextBlock = to + 1
	if err := store.SaveCheckpoint(ctx, scan.Key, checkpoint); err != nil {
		return V3AccumulatorEvents{}, ScanCheckpoint{}, err
	}
	return out, checkpoint, nil
}

func checkpointStartBlock(ctx context.Context, store CheckpointStore, scan CheckpointedScan) (uint64, error) {
	if store == nil {
		return 0, fmt.Errorf("checkpoint store is required")
	}
	if scan.Key == "" {
		return 0, fmt.Errorf("checkpoint key is required")
	}
	checkpoint, ok, err := store.LoadCheckpoint(ctx, scan.Key)
	if err != nil {
		return 0, err
	}
	if ok {
		return checkpoint.NextBlock, nil
	}
	return scan.StartBlock, nil
}

func finalizedToBlock(ctx context.Context, provider BlockNumberProvider, confirmations uint64) (uint64, bool, error) {
	if provider == nil {
		return 0, false, fmt.Errorf("block number provider is required")
	}
	latest, err := provider.BlockNumber(ctx)
	if err != nil {
		return 0, false, err
	}
	if latest < confirmations {
		return 0, false, nil
	}
	return latest - confirmations, true, nil
}

func (store FileCheckpointStore) loadAll() (map[string]ScanCheckpoint, error) {
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]ScanCheckpoint{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return map[string]ScanCheckpoint{}, nil
	}
	var checkpoints map[string]ScanCheckpoint
	if err := json.Unmarshal(data, &checkpoints); err != nil {
		return nil, err
	}
	if checkpoints == nil {
		checkpoints = map[string]ScanCheckpoint{}
	}
	return checkpoints, nil
}

func (store FileCheckpointStore) saveAll(checkpoints map[string]ScanCheckpoint) error {
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(checkpoints, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := store.Path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, store.Path)
}
