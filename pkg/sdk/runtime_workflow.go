package sdk

import (
	"context"
	"time"

	railtransaction "github.com/bf30075/railgun-go/pkg/transaction"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

// SyncAndRefreshResult 是同步并刷新 POI 状态后的钱包快照。
type SyncAndRefreshResult struct {
	Sync                  SyncResultsAllTXIDVersions
	RefreshPOIs           map[string]railwallet.RefreshPOIsSummary
	RefreshSpentPOIEvents map[string]railwallet.RefreshSpentPOIEventsSummary
	Balances              railwallet.TokenBalancesAllTXIDVersions
	SpendableBalances     railwallet.TokenBalancesAllTXIDVersions
	TransactionHistory    []railwallet.TransactionHistoryEntry
	ReceivedPOIStatus     []railwallet.ReceivedPOIStatusInfo
	SpentPOIStatus        []railwallet.SpentPOIStatusInfo
}

// SentTransactionSyncResult 记录交易提交前后的钱包状态。
type SentTransactionSyncResult struct {
	BeforeSync SyncAndRefreshResult
	Submitted  SubmittedTransactionWithReceipt
	AfterSync  SyncAndRefreshResult
}

// SyncAndRefresh 同步链上事件、刷新 POI 状态，并返回钱包状态快照。
func (runtime *Runtime) SyncAndRefresh(ctx context.Context, keyPrefix string) (SyncAndRefreshResult, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return SyncAndRefreshResult{}, err
	}
	result := SyncAndRefreshResult{
		RefreshPOIs:           map[string]railwallet.RefreshPOIsSummary{},
		RefreshSpentPOIEvents: map[string]railwallet.RefreshSpentPOIEventsSummary{},
	}
	result.Sync, err = runtime.Sync(ctx, keyPrefix)
	if err != nil {
		return SyncAndRefreshResult{}, err
	}
	for _, txidVersion := range engine.activeTXIDVersions() {
		refresh, err := runtime.RefreshPOIs(ctx, txidVersion)
		if err != nil {
			return SyncAndRefreshResult{}, err
		}
		result.RefreshPOIs[txidVersion] = refresh

		spentRefresh, err := runtime.RefreshSpentPOIEvents(ctx, txidVersion)
		if err != nil {
			return SyncAndRefreshResult{}, err
		}
		result.RefreshSpentPOIEvents[txidVersion] = spentRefresh
	}
	result.Balances, err = runtime.Balances(ctx, nil)
	if err != nil {
		return SyncAndRefreshResult{}, err
	}
	result.SpendableBalances, err = runtime.SpendableBalances(ctx)
	if err != nil {
		return SyncAndRefreshResult{}, err
	}
	result.TransactionHistory, err = runtime.TransactionHistory(ctx, nil)
	if err != nil {
		return SyncAndRefreshResult{}, err
	}
	result.ReceivedPOIStatus, err = runtime.ReceivedPOIStatus(ctx)
	if err != nil {
		return SyncAndRefreshResult{}, err
	}
	result.SpentPOIStatus, err = runtime.SpentPOIStatus(ctx)
	if err != nil {
		return SyncAndRefreshResult{}, err
	}
	return result, nil
}

// SendEIP1559TransactionAndSync 在发送前同步，等待交易 receipt，然后再次同步。
func (runtime *Runtime) SendEIP1559TransactionAndSync(ctx context.Context, request railtransaction.SendEIP1559TransactionRequest, keyPrefix string, pollInterval time.Duration) (SentTransactionSyncResult, error) {
	before, err := runtime.SyncAndRefresh(ctx, keyPrefix)
	if err != nil {
		return SentTransactionSyncResult{}, err
	}
	submitted, err := runtime.SendEIP1559TransactionAndWait(ctx, request, pollInterval)
	if err != nil {
		return SentTransactionSyncResult{}, err
	}
	after, err := runtime.SyncAndRefresh(ctx, keyPrefix)
	if err != nil {
		return SentTransactionSyncResult{}, err
	}
	return SentTransactionSyncResult{
		BeforeSync: before,
		Submitted:  submitted,
		AfterSync:  after,
	}, nil
}

// SendEIP1559TransactionWithLatestNonceAndSync 在发送前同步，遇到 nonce-too-low 时
// 从最新 nonce 重试，等待 receipt 后再次同步。
func (runtime *Runtime) SendEIP1559TransactionWithLatestNonceAndSync(ctx context.Context, request railtransaction.SendEIP1559TransactionRequest, keyPrefix string, maxRetries int, pollInterval time.Duration) (SentTransactionSyncResult, error) {
	before, err := runtime.SyncAndRefresh(ctx, keyPrefix)
	if err != nil {
		return SentTransactionSyncResult{}, err
	}
	submitted, err := runtime.SendEIP1559TransactionWithLatestNonceAndWait(ctx, request, maxRetries, pollInterval)
	if err != nil {
		return SentTransactionSyncResult{}, err
	}
	after, err := runtime.SyncAndRefresh(ctx, keyPrefix)
	if err != nil {
		return SentTransactionSyncResult{}, err
	}
	return SentTransactionSyncResult{
		BeforeSync: before,
		Submitted:  submitted,
		AfterSync:  after,
	}, nil
}
