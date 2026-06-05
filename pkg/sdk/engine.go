package sdk

import (
	"context"
	"fmt"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

// EngineConfig 将钱包 bundle、链和用于同步/链读取的事件 provider 连接起来。
type EngineConfig struct {
	Bundle   WalletBundle
	Chain    railchain.Chain
	Provider railevents.CheckpointedLogProvider
	// TXIDVersions 覆盖该 engine 的 active TXID version。为空时，NewEngine 使用
	// chain package 的全局 active version。
	TXIDVersions []string
}

// Engine 是 Runtime 之下带链上下文的钱包 facade。
//
// Engine 方法操作钱包状态和 checkpoint。结构体字段保持私有，让调用方通过
// Runtime 或 Engine 方法访问，而不是直接修改 store、链配置或 provider。
type Engine struct {
	wallet        *railwallet.Wallet
	stores        StoreSet
	indexedWallet railwallet.IndexedWallet
	chain         railchain.Chain
	provider      railevents.CheckpointedLogProvider
	txidVersions  []string
}

// SyncResultsAllTXIDVersions 将 TXID version 映射到对应同步结果。
type SyncResultsAllTXIDVersions map[string]railwallet.SyncResult

// NewEngine 验证并创建带链上下文的钱包 engine。
func NewEngine(config EngineConfig) (*Engine, error) {
	if config.Bundle.Wallet == nil {
		return nil, fmt.Errorf("wallet is required")
	}
	if _, err := railchain.FullNetworkIDHex(config.Chain); err != nil {
		return nil, err
	}
	txidVersions, err := engineTXIDVersions(config.Chain, config.TXIDVersions)
	if err != nil {
		return nil, err
	}
	return &Engine{
		wallet:        config.Bundle.Wallet,
		stores:        config.Bundle.Stores,
		indexedWallet: config.Bundle.IndexedWallet,
		chain:         config.Chain,
		provider:      config.Provider,
		txidVersions:  txidVersions,
	}, nil
}

func (engine *Engine) SyncV2(ctx context.Context, scan railevents.CheckpointedScan) (railwallet.SyncResult, error) {
	if err := engine.validateSync(); err != nil {
		return railwallet.SyncResult{}, err
	}
	return engine.wallet.SyncV2(ctx, engine.provider, scan)
}

func (engine *Engine) SyncV3(ctx context.Context, scan railevents.CheckpointedScan) (railwallet.SyncResult, error) {
	if err := engine.validateSync(); err != nil {
		return railwallet.SyncResult{}, err
	}
	if !engine.supportsTXIDVersion(railcrypto.TXIDVersionV3PoseidonMerkle) {
		return railwallet.SyncResult{}, fmt.Errorf("Chain does not support V3: %d:%d. Set supportsV3 'true' in loadNetwork.", engine.chain.Type, engine.chain.ID)
	}
	return engine.wallet.SyncV3(ctx, engine.provider, scan)
}

func (engine *Engine) SyncActiveTXIDVersions(ctx context.Context, scans map[string]railevents.CheckpointedScan) (SyncResultsAllTXIDVersions, error) {
	if err := engine.validate(); err != nil {
		return nil, err
	}
	results := SyncResultsAllTXIDVersions{}
	for _, txidVersion := range engine.activeTXIDVersions() {
		scan, ok := scans[txidVersion]
		if !ok {
			return nil, fmt.Errorf("missing scan for txid version %s", txidVersion)
		}
		var result railwallet.SyncResult
		var err error
		switch txidVersion {
		case railcrypto.TXIDVersionV2PoseidonMerkle:
			result, err = engine.SyncV2(ctx, scan)
		case railcrypto.TXIDVersionV3PoseidonMerkle:
			result, err = engine.SyncV3(ctx, scan)
		default:
			err = fmt.Errorf("unsupported txid version %s", txidVersion)
		}
		if err != nil {
			return nil, err
		}
		results[txidVersion] = result
	}
	return results, nil
}

func (engine *Engine) Rollback(ctx context.Context, checkpointKey string, fromBlock uint64) error {
	if err := engine.validate(); err != nil {
		return err
	}
	return engine.wallet.Rollback(ctx, checkpointKey, fromBlock)
}

func (engine *Engine) RescanLocalUTXOTree(ctx context.Context) (railwallet.ImportSummary, error) {
	if err := engine.validate(); err != nil {
		return railwallet.ImportSummary{}, err
	}
	return engine.wallet.RescanLocalUTXOTree(ctx, railwallet.LocalRescanOptions{
		TXIDVersions: engine.activeTXIDVersions(),
	})
}

func (engine *Engine) Balances(ctx context.Context, includedBuckets []string) (railwallet.TokenBalancesAllTXIDVersions, error) {
	if err := engine.validate(); err != nil {
		return nil, err
	}
	return engine.wallet.BalancesForTXIDVersions(ctx, engine.activeTXIDVersions(), includedBuckets)
}

func (engine *Engine) BalancesByBucket(ctx context.Context, txidVersion string) (railwallet.TokenBalancesByBucket, error) {
	if err := engine.validate(); err != nil {
		return nil, err
	}
	return engine.wallet.BalancesByBucket(ctx, txidVersion)
}

func (engine *Engine) SpendableBalances(ctx context.Context) (railwallet.TokenBalancesAllTXIDVersions, error) {
	if err := engine.validate(); err != nil {
		return nil, err
	}
	return engine.wallet.SpendableBalancesForTXIDVersions(ctx, engine.chain, engine.activeTXIDVersions())
}

func (engine *Engine) TransactionHistory(ctx context.Context, startingBlock *uint64) ([]railwallet.TransactionHistoryEntry, error) {
	if err := engine.validate(); err != nil {
		return nil, err
	}
	return engine.wallet.TransactionHistoryForTXIDVersions(ctx, engine.activeTXIDVersions(), startingBlock)
}

func (engine *Engine) RefreshPOIs(ctx context.Context, txidVersion string) (railwallet.RefreshPOIsSummary, error) {
	if err := engine.validate(); err != nil {
		return railwallet.RefreshPOIsSummary{}, err
	}
	return engine.wallet.RefreshPOIs(ctx, txidVersion, engine.chain)
}

func (engine *Engine) RefreshSpentPOIEvents(ctx context.Context, txidVersion string) (railwallet.RefreshSpentPOIEventsSummary, error) {
	if err := engine.validate(); err != nil {
		return railwallet.RefreshSpentPOIEventsSummary{}, err
	}
	return engine.wallet.RefreshSpentPOIEvents(ctx, txidVersion, engine.chain)
}

func (engine *Engine) ReceivedPOIStatus(ctx context.Context) ([]railwallet.ReceivedPOIStatusInfo, error) {
	if err := engine.validate(); err != nil {
		return nil, err
	}
	return engine.wallet.ReceivedPOIStatus(ctx)
}

func (engine *Engine) SpentPOIStatus(ctx context.Context) ([]railwallet.SpentPOIStatusInfo, error) {
	if err := engine.validate(); err != nil {
		return nil, err
	}
	return engine.wallet.SpentPOIStatusFromStore(ctx, engine.chain)
}

func (engine *Engine) UTXOMerkleRoot(ctx context.Context, tree uint64) (string, error) {
	if err := engine.validate(); err != nil {
		return "", err
	}
	return engine.wallet.UTXOMerkleRoot(ctx, tree)
}

func (engine *Engine) UTXOMerkleProof(ctx context.Context, nullifier string) (merkletree.MerkleProof, error) {
	if err := engine.validate(); err != nil {
		return merkletree.MerkleProof{}, err
	}
	return engine.wallet.UTXOMerkleProof(ctx, nullifier)
}

func (engine *Engine) validate() error {
	if engine == nil {
		return fmt.Errorf("engine is required")
	}
	if engine.wallet == nil {
		return fmt.Errorf("wallet is required")
	}
	return nil
}

func (engine *Engine) validateSync() error {
	if err := engine.validate(); err != nil {
		return err
	}
	if engine.provider == nil {
		return fmt.Errorf("event provider is required")
	}
	return nil
}

func (engine *Engine) activeTXIDVersions() []string {
	if engine == nil {
		return nil
	}
	return cloneStringSlice(engine.txidVersions)
}

func (engine *Engine) supportsTXIDVersion(txidVersion string) bool {
	for _, activeVersion := range engine.activeTXIDVersions() {
		if activeVersion == txidVersion {
			return true
		}
	}
	return false
}

func engineTXIDVersions(chain railchain.Chain, configured []string) ([]string, error) {
	if len(configured) == 0 {
		return cloneStringSlice(railwallet.ActiveTXIDVersions(chain)), nil
	}
	versions := []string{}
	for _, txidVersion := range configured {
		switch txidVersion {
		case railcrypto.TXIDVersionV2PoseidonMerkle, railcrypto.TXIDVersionV3PoseidonMerkle:
		default:
			return nil, fmt.Errorf("unsupported txid version %s", txidVersion)
		}
		if !stringSliceContains(versions, txidVersion) {
			versions = append(versions, txidVersion)
		}
	}
	return versions, nil
}

func stringSliceContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
