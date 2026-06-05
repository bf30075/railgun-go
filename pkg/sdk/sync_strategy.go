package sdk

import (
	"context"
	"fmt"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railquick "github.com/bf30075/railgun-go/pkg/quicksync"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

// SyncCursor 报告整体和 per-TXID-version checkpoint 位置。
//
// SyncedBlock 和 NextBlock 是所有 active version 的低水位。Versions 保存每个
// active TXID version 的精确 cursor。
type SyncCursor struct {
	SyncedBlock uint64
	NextBlock   uint64
	Versions    map[string]SyncVersionCursor
}

// SyncVersionCursor 报告某个 TXID version 的 checkpoint 位置。
//
// NextBlock 是下一个待扫描区块；当 NextBlock 大于 0 时，SyncedBlock 等于
// NextBlock 减 1。
type SyncVersionCursor struct {
	SyncedBlock uint64
	NextBlock   uint64
}

// SyncStrategy 实现 runtime 同步策略。
//
// 策略可以先从替代来源导入，再回退到 RPC；但必须保证钱包 store 和 checkpoint
// 保持一致。
type SyncStrategy interface {
	Sync(ctx context.Context, runtime *Runtime, keyPrefix string) (SyncResultsAllTXIDVersions, error)
}

// RPCSyncStrategy 直接通过 runtime provider 扫描 active TXID version。
type RPCSyncStrategy struct{}

func (RPCSyncStrategy) Sync(ctx context.Context, runtime *Runtime, keyPrefix string) (SyncResultsAllTXIDVersions, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, err
	}
	scans, err := runtime.DefaultScans(keyPrefix)
	if err != nil {
		return nil, err
	}
	return engine.SyncActiveTXIDVersions(ctx, scans)
}

// V2QuickSyncFetcher 拉取用于 quick sync 的历史 V2 accumulated event。
type V2QuickSyncFetcher func(context.Context, railquick.V2GraphOptions) (railevents.V2AccumulatedEvents, error)

// BSCV2QuickSyncStrategy 从 Railgun GraphQL endpoint bootstrap BNB Chain V2
// 数据，然后运行 fallback strategy 扫描 RPC 尾部。
type BSCV2QuickSyncStrategy struct {
	// Fetcher 覆盖 GraphQL fetcher，用于测试或自定义传输。
	Fetcher V2QuickSyncFetcher
	// Endpoint 覆盖默认 BNB Chain V2 GraphQL endpoint。
	Endpoint string
	// MaxItems 限制 quick-sync 拉取数量；0 表示使用 fetcher 默认值。
	MaxItems int
	// Fallback 在 quick sync 后扫描 RPC 尾部；nil 表示使用 RPCSyncStrategy。
	Fallback SyncStrategy
}

func (strategy BSCV2QuickSyncStrategy) Sync(ctx context.Context, runtime *Runtime, keyPrefix string) (SyncResultsAllTXIDVersions, error) {
	fallback := strategy.Fallback
	if fallback == nil {
		fallback = RPCSyncStrategy{}
	}
	quickSyncResults, err := strategy.quickSync(ctx, runtime, keyPrefix)
	if err != nil {
		return fallback.Sync(ctx, runtime, keyPrefix)
	}
	syncResults, err := fallback.Sync(ctx, runtime, keyPrefix)
	if err != nil {
		return nil, err
	}
	return mergeSyncResults(quickSyncResults, syncResults), nil
}

func (strategy BSCV2QuickSyncStrategy) quickSync(ctx context.Context, runtime *Runtime, keyPrefix string) (SyncResultsAllTXIDVersions, error) {
	if !runtimeSupportsBSCV2QuickSync(runtime) {
		return SyncResultsAllTXIDVersions{}, nil
	}
	result, err := strategy.quickSyncBSCV2(ctx, runtime, keyPrefix)
	if err != nil {
		return nil, err
	}
	if !result.Scanned {
		return SyncResultsAllTXIDVersions{}, nil
	}
	return SyncResultsAllTXIDVersions{
		railcrypto.TXIDVersionV2PoseidonMerkle: result,
	}, nil
}

func (strategy BSCV2QuickSyncStrategy) quickSyncBSCV2(ctx context.Context, runtime *Runtime, keyPrefix string) (railwallet.SyncResult, error) {
	fetcher := strategy.Fetcher
	if fetcher == nil {
		fetcher = railquick.FetchV2Graph
	}
	scans, err := runtime.DefaultScans(keyPrefix)
	if err != nil {
		return railwallet.SyncResult{}, err
	}
	scan, ok := scans[railcrypto.TXIDVersionV2PoseidonMerkle]
	if !ok {
		return railwallet.SyncResult{}, nil
	}
	engine := runtime.engine
	startBlock, err := quickSyncStartBlock(ctx, engine.stores.Checkpoints, engine.stores.UTXOMerkleTree, scan.Key, scan.StartBlock)
	if err != nil {
		return railwallet.SyncResult{}, err
	}
	endpoint := strategy.Endpoint
	if endpoint == "" {
		endpoint = railquick.BSCV2GraphQLEndpoint
	}
	accumulated, err := fetcher(ctx, railquick.V2GraphOptions{
		Endpoint:   endpoint,
		StartBlock: startBlock,
		MaxItems:   strategy.MaxItems,
	})
	if err != nil {
		return railwallet.SyncResult{}, err
	}
	if v2AccumulatedEventsEmpty(accumulated) {
		return railwallet.SyncResult{
			FromBlock:  startBlock,
			Checkpoint: railevents.ScanCheckpoint{NextBlock: startBlock},
		}, nil
	}
	summary, err := railwallet.ImportV2AccumulatedEventsWithAllStores(
		ctx,
		engine.stores.State,
		engine.stores.SpentPOIEvents,
		engine.stores.UTXOMerkleTree,
		engine.wallet.Keys,
		accumulated,
	)
	if err != nil {
		return railwallet.SyncResult{}, err
	}
	toBlock := maxV2AccumulatedBlock(accumulated, startBlock)
	checkpoint := railevents.ScanCheckpoint{NextBlock: toBlock + 1}
	if err := engine.stores.Checkpoints.SaveCheckpoint(ctx, scan.Key, checkpoint); err != nil {
		return railwallet.SyncResult{}, err
	}
	return railwallet.SyncResult{
		FromBlock:  startBlock,
		ToBlock:    toBlock,
		Scanned:    true,
		Checkpoint: checkpoint,
		Import:     summary,
	}, nil
}

func runtimeSupportsBSCV2QuickSync(runtime *Runtime) bool {
	return runtime != nil &&
		runtime.network.Name == "BNB_Chain" &&
		runtime.engine != nil &&
		runtime.engine.wallet != nil &&
		runtime.engine.stores.Checkpoints != nil &&
		runtime.engine.stores.UTXOMerkleTree != nil
}

func quickSyncStartBlock(ctx context.Context, checkpoints railevents.CheckpointStore, utxoTree railutxotree.Store, checkpointKey string, defaultStartBlock uint64) (uint64, error) {
	if checkpoints == nil {
		return 0, fmt.Errorf("checkpoint store is required")
	}
	if utxoTree == nil {
		return 0, fmt.Errorf("utxo merkle tree store is required")
	}
	leaves, err := utxoTree.ListLeaves(ctx)
	if err != nil {
		return 0, err
	}
	if len(leaves) == 0 {
		return defaultStartBlock, nil
	}
	checkpoint, ok, err := checkpoints.LoadCheckpoint(ctx, checkpointKey)
	if err != nil {
		return 0, err
	}
	if !ok || checkpoint.NextBlock < defaultStartBlock {
		return defaultStartBlock, nil
	}
	return checkpoint.NextBlock, nil
}

func v2AccumulatedEventsEmpty(accumulated railevents.V2AccumulatedEvents) bool {
	return len(accumulated.CommitmentEvents) == 0 &&
		len(accumulated.NullifierEvents) == 0 &&
		len(accumulated.UnshieldEvents) == 0
}

func maxV2AccumulatedBlock(accumulated railevents.V2AccumulatedEvents, fallback uint64) uint64 {
	maxBlock := fallback
	for _, event := range accumulated.CommitmentEvents {
		if event.BlockNumber > maxBlock {
			maxBlock = event.BlockNumber
		}
	}
	for _, event := range accumulated.NullifierEvents {
		if event.BlockNumber > maxBlock {
			maxBlock = event.BlockNumber
		}
	}
	for _, event := range accumulated.UnshieldEvents {
		if event.BlockNumber > maxBlock {
			maxBlock = event.BlockNumber
		}
	}
	return maxBlock
}

func mergeSyncResults(quickSyncResults SyncResultsAllTXIDVersions, syncResults SyncResultsAllTXIDVersions) SyncResultsAllTXIDVersions {
	if len(quickSyncResults) == 0 {
		return syncResults
	}
	if syncResults == nil {
		syncResults = SyncResultsAllTXIDVersions{}
	}
	for txidVersion, result := range quickSyncResults {
		if _, ok := syncResults[txidVersion]; !ok {
			syncResults[txidVersion] = result
		}
	}
	return syncResults
}
