package sdk

import (
	"context"
	"fmt"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

// Sync 通过已配置的同步策略，为每个 active TXID version 导入链上事件。
func (runtime *Runtime) Sync(ctx context.Context, keyPrefix string) (SyncResultsAllTXIDVersions, error) {
	if runtime == nil {
		return nil, fmt.Errorf("runtime is required")
	}
	strategy := runtime.syncStrategy
	if strategy == nil {
		strategy = RPCSyncStrategy{}
	}
	return strategy.Sync(ctx, runtime, keyPrefix)
}

// Balances 返回指定 POI bucket 下的钱包余额。
func (runtime *Runtime) Balances(ctx context.Context, includedBuckets []string) (railwallet.TokenBalancesAllTXIDVersions, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, err
	}
	return engine.Balances(ctx, includedBuckets)
}

// BalancesByBucket 返回按 POI bucket 分组的钱包余额。
func (runtime *Runtime) BalancesByBucket(ctx context.Context, txidVersion string) (railwallet.TokenBalancesByBucket, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, err
	}
	return engine.BalancesByBucket(ctx, txidVersion)
}

// SpendableBalances 返回当前按 POI 策略可花费的余额。
func (runtime *Runtime) SpendableBalances(ctx context.Context) (railwallet.TokenBalancesAllTXIDVersions, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, err
	}
	return engine.SpendableBalances(ctx)
}

// TransactionHistory 返回本地索引的钱包交易历史。
func (runtime *Runtime) TransactionHistory(ctx context.Context, startingBlock *uint64) ([]railwallet.TransactionHistoryEntry, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, err
	}
	return engine.TransactionHistory(ctx, startingBlock)
}

// RescanLocalUTXOTree 从本地 UTXO Merkle store 重建钱包 TXO 状态。
func (runtime *Runtime) RescanLocalUTXOTree(ctx context.Context) (railwallet.ImportSummary, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return railwallet.ImportSummary{}, err
	}
	return engine.RescanLocalUTXOTree(ctx)
}

// RefreshPOIs 刷新某个 TXID version 的 received TXO POI 状态。
func (runtime *Runtime) RefreshPOIs(ctx context.Context, txidVersion string) (railwallet.RefreshPOIsSummary, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return railwallet.RefreshPOIsSummary{}, err
	}
	return engine.RefreshPOIs(ctx, txidVersion)
}

// RefreshSpentPOIEvents 刷新某个 TXID version 的本地 spent-POI event 状态。
func (runtime *Runtime) RefreshSpentPOIEvents(ctx context.Context, txidVersion string) (railwallet.RefreshSpentPOIEventsSummary, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return railwallet.RefreshSpentPOIEventsSummary{}, err
	}
	return engine.RefreshSpentPOIEvents(ctx, txidVersion)
}

// ReceivedPOIStatus 返回 received TXO 的本地 POI 状态。
func (runtime *Runtime) ReceivedPOIStatus(ctx context.Context) ([]railwallet.ReceivedPOIStatusInfo, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, err
	}
	return engine.ReceivedPOIStatus(ctx)
}

// SpentPOIStatus 返回 sent commitment 和 unshield 的本地 POI 状态。
func (runtime *Runtime) SpentPOIStatus(ctx context.Context) ([]railwallet.SpentPOIStatusInfo, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, err
	}
	return engine.SpentPOIStatus(ctx)
}

// SubmitLegacyTransactPOIEvents 为某个 TXID version 提交 legacy transact POI event。
func (runtime *Runtime) SubmitLegacyTransactPOIEvents(ctx context.Context, txidVersion string) (railwallet.SubmitLegacyTransactPOIEventsSummary, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return railwallet.SubmitLegacyTransactPOIEventsSummary{}, err
	}
	return engine.wallet.SubmitLegacyTransactPOIEvents(ctx, txidVersion, engine.chain)
}

// SubmitLegacyTransactPOIEventsAndRefresh 提交 legacy transact POI event，并在之后
// 刷新 received POI 状态。
func (runtime *Runtime) SubmitLegacyTransactPOIEventsAndRefresh(ctx context.Context, txidVersion string) (railwallet.SubmitLegacyTransactPOIEventsAndRefreshSummary, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return railwallet.SubmitLegacyTransactPOIEventsAndRefreshSummary{}, err
	}
	return engine.wallet.SubmitLegacyTransactPOIEventsAndRefresh(ctx, txidVersion, engine.chain)
}

// GenerateAndSubmitPreTransactionPOI 使用 runtime prover 构建并提交一个预交易 POI
// proof 证明。
func (runtime *Runtime) GenerateAndSubmitPreTransactionPOI(ctx context.Context, request railpoi.GenerateAndSubmitPreTransactionPOIRequest, progress railproof.ProgressCallback) (railpoi.SubmittedPreTransactionPOI, error) {
	engine, manager, err := runtime.requirePOIManager()
	if err != nil {
		return railpoi.SubmittedPreTransactionPOI{}, err
	}
	prover, err := runtime.RequireProver()
	if err != nil {
		return railpoi.SubmittedPreTransactionPOI{}, err
	}
	request.Chain = defaultRuntimeChain(request.Chain, engine.chain)
	if request.TXIDMerkleTree == nil {
		request.TXIDMerkleTree = engine.wallet.TXIDMerkleTree
	}
	return railpoi.GenerateAndSubmitPreTransactionPOI(ctx, manager, prover, request, progress)
}

// GenerateAndSubmitPreTransactionPOIs 使用 runtime prover 为多个 list 构建并提交预交易
// POI proof 证明。
func (runtime *Runtime) GenerateAndSubmitPreTransactionPOIs(ctx context.Context, request railpoi.GenerateAndSubmitPreTransactionPOIsRequest, progress railproof.ProgressCallback) ([]railpoi.SubmittedPreTransactionPOI, error) {
	engine, manager, err := runtime.requirePOIManager()
	if err != nil {
		return nil, err
	}
	prover, err := runtime.RequireProver()
	if err != nil {
		return nil, err
	}
	request.Chain = defaultRuntimeChain(request.Chain, engine.chain)
	if request.TXIDMerkleTree == nil {
		request.TXIDMerkleTree = engine.wallet.TXIDMerkleTree
	}
	return railpoi.GenerateAndSubmitPreTransactionPOIs(ctx, manager, prover, request, progress)
}

func (runtime *Runtime) requireEngine() (*Engine, error) {
	if runtime == nil {
		return nil, fmt.Errorf("runtime is required")
	}
	if runtime.engine == nil {
		return nil, fmt.Errorf("engine is required")
	}
	if runtime.engine.wallet == nil {
		return nil, fmt.Errorf("wallet is required")
	}
	return runtime.engine, nil
}

func (runtime *Runtime) requirePOIManager() (*Engine, *railpoi.Manager, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, nil, err
	}
	if engine.wallet.POIManager == nil {
		return nil, nil, fmt.Errorf("POI manager is required")
	}
	return engine, engine.wallet.POIManager, nil
}

func defaultRuntimeChain(requestChain railchain.Chain, runtimeChain railchain.Chain) railchain.Chain {
	if requestChain == (railchain.Chain{}) {
		return runtimeChain
	}
	return requestChain
}
