package wallet

import (
	"context"
	"fmt"

	railevents "github.com/bf30075/railgun-go/pkg/events"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
)

type SyncResult struct {
	FromBlock uint64
	ToBlock   uint64
	Scanned   bool

	Checkpoint railevents.ScanCheckpoint
	Import     ImportSummary
}

func SyncV2FromCheckpoint(
	ctx context.Context,
	provider railevents.CheckpointedLogProvider,
	checkpoints railevents.CheckpointStore,
	state StateStore,
	keys ScanKeys,
	scan railevents.CheckpointedScan,
) (SyncResult, error) {
	return SyncV2FromCheckpointWithStores(ctx, provider, checkpoints, state, nil, keys, scan)
}

func SyncV2FromCheckpointWithStores(
	ctx context.Context,
	provider railevents.CheckpointedLogProvider,
	checkpoints railevents.CheckpointStore,
	state StateStore,
	spentPOIEvents SpentPOIEventStore,
	keys ScanKeys,
	scan railevents.CheckpointedScan,
) (SyncResult, error) {
	return SyncV2FromCheckpointWithAllStores(ctx, provider, checkpoints, state, spentPOIEvents, nil, keys, scan)
}

func SyncV2FromCheckpointWithAllStores(
	ctx context.Context,
	provider railevents.CheckpointedLogProvider,
	checkpoints railevents.CheckpointStore,
	state StateStore,
	spentPOIEvents SpentPOIEventStore,
	utxoTree railutxotree.Store,
	keys ScanKeys,
	scan railevents.CheckpointedScan,
) (SyncResult, error) {
	if err := validateSyncInputs(provider, checkpoints, state, keys, scan); err != nil {
		return SyncResult{}, err
	}
	from, err := syncStartBlock(ctx, checkpoints, scan)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{FromBlock: from, Checkpoint: railevents.ScanCheckpoint{NextBlock: from}}
	to, ok, err := syncFinalizedToBlock(ctx, provider, scan.Confirmations)
	if err != nil {
		return SyncResult{}, err
	}
	if !ok || to < from {
		return result, nil
	}
	summary := ImportSummary{}
	if err := railevents.ScanV2EventChunks(ctx, provider, railevents.ScanRange{
		Addresses: scan.Addresses,
		FromBlock: from,
		ToBlock:   to,
		ChunkSize: scan.ChunkSize,
	}, func(accumulated railevents.V2AccumulatedEvents, chunk railevents.ScannedLogChunk) error {
		part, err := ImportV2AccumulatedEventsWithAllStores(ctx, state, spentPOIEvents, utxoTree, keys, accumulated)
		if err != nil {
			return err
		}
		addImportSummary(&summary, part)
		result.ToBlock = chunk.ToBlock
		result.Scanned = true
		result.Import = summary
		result.Checkpoint.NextBlock = chunk.ToBlock + 1
		return checkpoints.SaveCheckpoint(ctx, scan.Key, result.Checkpoint)
	}); err != nil {
		return SyncResult{}, err
	}
	return result, nil
}

func SyncV3FromCheckpoint(
	ctx context.Context,
	provider railevents.CheckpointedLogProvider,
	checkpoints railevents.CheckpointStore,
	state StateStore,
	keys ScanKeys,
	scan railevents.CheckpointedScan,
) (SyncResult, error) {
	return SyncV3FromCheckpointWithTXIDStore(ctx, provider, checkpoints, state, nil, keys, scan)
}

func SyncV3FromCheckpointWithTXIDStore(
	ctx context.Context,
	provider railevents.CheckpointedLogProvider,
	checkpoints railevents.CheckpointStore,
	state StateStore,
	txidStore railtxid.TransactionStore,
	keys ScanKeys,
	scan railevents.CheckpointedScan,
) (SyncResult, error) {
	return SyncV3FromCheckpointWithTXIDStores(ctx, provider, checkpoints, state, txidStore, nil, keys, scan)
}

func SyncV3FromCheckpointWithTXIDStores(
	ctx context.Context,
	provider railevents.CheckpointedLogProvider,
	checkpoints railevents.CheckpointStore,
	state StateStore,
	txidStore railtxid.TransactionStore,
	txidMerkleTree railtxid.MerkleTreeStore,
	keys ScanKeys,
	scan railevents.CheckpointedScan,
) (SyncResult, error) {
	return SyncV3FromCheckpointWithStores(ctx, provider, checkpoints, state, txidStore, txidMerkleTree, nil, keys, scan)
}

func SyncV3FromCheckpointWithStores(
	ctx context.Context,
	provider railevents.CheckpointedLogProvider,
	checkpoints railevents.CheckpointStore,
	state StateStore,
	txidStore railtxid.TransactionStore,
	txidMerkleTree railtxid.MerkleTreeStore,
	spentPOIEvents SpentPOIEventStore,
	keys ScanKeys,
	scan railevents.CheckpointedScan,
) (SyncResult, error) {
	return SyncV3FromCheckpointWithAllStores(ctx, provider, checkpoints, state, txidStore, txidMerkleTree, nil, spentPOIEvents, keys, scan)
}

func SyncV3FromCheckpointWithAllStores(
	ctx context.Context,
	provider railevents.CheckpointedLogProvider,
	checkpoints railevents.CheckpointStore,
	state StateStore,
	txidStore railtxid.TransactionStore,
	txidMerkleTree railtxid.MerkleTreeStore,
	utxoTree railutxotree.Store,
	spentPOIEvents SpentPOIEventStore,
	keys ScanKeys,
	scan railevents.CheckpointedScan,
) (SyncResult, error) {
	if err := validateSyncInputs(provider, checkpoints, state, keys, scan); err != nil {
		return SyncResult{}, err
	}
	from, err := syncStartBlock(ctx, checkpoints, scan)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{FromBlock: from, Checkpoint: railevents.ScanCheckpoint{NextBlock: from}}
	to, ok, err := syncFinalizedToBlock(ctx, provider, scan.Confirmations)
	if err != nil {
		return SyncResult{}, err
	}
	if !ok || to < from {
		return result, nil
	}
	summary := ImportSummary{}
	if err := railevents.ScanV3EventChunks(ctx, provider, railevents.ScanRange{
		Addresses: scan.Addresses,
		FromBlock: from,
		ToBlock:   to,
		ChunkSize: scan.ChunkSize,
	}, func(accumulated railevents.V3AccumulatorEvents, chunk railevents.ScannedLogChunk) error {
		part, err := ImportV3AccumulatedEventsWithAllStores(ctx, state, txidStore, txidMerkleTree, utxoTree, spentPOIEvents, keys, accumulated)
		if err != nil {
			return err
		}
		addImportSummary(&summary, part)
		result.ToBlock = chunk.ToBlock
		result.Scanned = true
		result.Import = summary
		result.Checkpoint.NextBlock = chunk.ToBlock + 1
		return checkpoints.SaveCheckpoint(ctx, scan.Key, result.Checkpoint)
	}); err != nil {
		return SyncResult{}, err
	}
	return result, nil
}

func RollbackWalletSync(ctx context.Context, checkpoints railevents.CheckpointStore, state StateStore, checkpointKey string, fromBlock uint64) error {
	return RollbackWalletSyncWithTXIDStore(ctx, checkpoints, state, nil, checkpointKey, fromBlock)
}

func RollbackWalletSyncWithTXIDStore(ctx context.Context, checkpoints railevents.CheckpointStore, state StateStore, txidStore railtxid.ReorgTransactionStore, checkpointKey string, fromBlock uint64) error {
	return RollbackWalletSyncWithTXIDStores(ctx, checkpoints, state, txidStore, nil, checkpointKey, fromBlock)
}

func RollbackWalletSyncWithTXIDStores(ctx context.Context, checkpoints railevents.CheckpointStore, state StateStore, txidStore railtxid.ReorgTransactionStore, txidMerkleTree railtxid.ReorgMerkleTreeStore, checkpointKey string, fromBlock uint64) error {
	return RollbackWalletSyncWithStores(ctx, checkpoints, state, txidStore, txidMerkleTree, nil, checkpointKey, fromBlock)
}

func RollbackWalletSyncWithStores(ctx context.Context, checkpoints railevents.CheckpointStore, state StateStore, txidStore railtxid.ReorgTransactionStore, txidMerkleTree railtxid.ReorgMerkleTreeStore, spentPOIEvents ReorgSpentPOIEventStore, checkpointKey string, fromBlock uint64) error {
	return RollbackWalletSyncWithAllStores(ctx, checkpoints, state, txidStore, txidMerkleTree, nil, spentPOIEvents, checkpointKey, fromBlock)
}

func RollbackWalletSyncWithAllStores(ctx context.Context, checkpoints railevents.CheckpointStore, state StateStore, txidStore railtxid.ReorgTransactionStore, txidMerkleTree railtxid.ReorgMerkleTreeStore, utxoTree railutxotree.ReorgStore, spentPOIEvents ReorgSpentPOIEventStore, checkpointKey string, fromBlock uint64) error {
	reorgState, ok := state.(ReorgStateStore)
	if !ok {
		return fmt.Errorf("state store does not support rollback")
	}
	if err := reorgState.RollbackToBlock(ctx, fromBlock); err != nil {
		return err
	}
	if txidStore != nil {
		if err := txidStore.RollbackToBlock(ctx, fromBlock); err != nil {
			return err
		}
	}
	if txidMerkleTree != nil {
		if err := txidMerkleTree.RollbackToBlock(ctx, fromBlock); err != nil {
			return err
		}
	}
	if utxoTree != nil {
		if err := utxoTree.RollbackToBlock(ctx, fromBlock); err != nil {
			return err
		}
	}
	if spentPOIEvents != nil {
		if err := spentPOIEvents.RollbackToBlock(ctx, fromBlock); err != nil {
			return err
		}
	}
	return railevents.RollbackScanCheckpoint(ctx, checkpoints, checkpointKey, fromBlock)
}

func validateSyncInputs(provider railevents.CheckpointedLogProvider, checkpoints railevents.CheckpointStore, state StateStore, keys ScanKeys, scan railevents.CheckpointedScan) error {
	if provider == nil {
		return fmt.Errorf("event provider is required")
	}
	if checkpoints == nil {
		return fmt.Errorf("checkpoint store is required")
	}
	if scan.Key == "" {
		return fmt.Errorf("checkpoint key is required")
	}
	return validateImportInputs(state, keys)
}

func syncStartBlock(ctx context.Context, checkpoints railevents.CheckpointStore, scan railevents.CheckpointedScan) (uint64, error) {
	checkpoint, ok, err := checkpoints.LoadCheckpoint(ctx, scan.Key)
	if err != nil {
		return 0, err
	}
	if ok {
		return checkpoint.NextBlock, nil
	}
	return scan.StartBlock, nil
}

func syncFinalizedToBlock(ctx context.Context, provider railevents.BlockNumberProvider, confirmations uint64) (uint64, bool, error) {
	latest, err := provider.BlockNumber(ctx)
	if err != nil {
		return 0, false, err
	}
	if latest < confirmations {
		return 0, false, nil
	}
	return latest - confirmations, true, nil
}
