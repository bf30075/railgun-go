package wallet

import (
	"context"
	"fmt"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
)

type Wallet struct {
	State          StateStore
	Checkpoints    railevents.CheckpointStore
	Keys           ScanKeys
	POIManager     *railpoi.Manager
	TXIDStore      railtxid.TransactionStore
	TXIDMerkleTree railtxid.MerkleTreeStore
	UTXOMerkleTree railutxotree.Store
	SpentPOIEvents SpentPOIEventStore
	Details        WalletDetailsStore
}

func NewWallet(state StateStore, checkpoints railevents.CheckpointStore, keys ScanKeys, poiManager *railpoi.Manager) (*Wallet, error) {
	return NewWalletWithTXIDStores(state, checkpoints, keys, poiManager, nil, nil)
}

func NewWalletWithTXIDStore(state StateStore, checkpoints railevents.CheckpointStore, keys ScanKeys, poiManager *railpoi.Manager, txidStore railtxid.TransactionStore) (*Wallet, error) {
	return NewWalletWithTXIDStores(state, checkpoints, keys, poiManager, txidStore, nil)
}

func NewWalletWithTXIDStores(state StateStore, checkpoints railevents.CheckpointStore, keys ScanKeys, poiManager *railpoi.Manager, txidStore railtxid.TransactionStore, txidMerkleTree railtxid.MerkleTreeStore) (*Wallet, error) {
	return NewWalletWithStores(state, checkpoints, keys, poiManager, txidStore, txidMerkleTree, nil)
}

func NewWalletWithStores(state StateStore, checkpoints railevents.CheckpointStore, keys ScanKeys, poiManager *railpoi.Manager, txidStore railtxid.TransactionStore, txidMerkleTree railtxid.MerkleTreeStore, spentPOIEvents SpentPOIEventStore) (*Wallet, error) {
	return NewWalletWithStoresAndDetails(state, checkpoints, keys, poiManager, txidStore, txidMerkleTree, spentPOIEvents, nil)
}

func NewWalletWithAllStores(state StateStore, checkpoints railevents.CheckpointStore, keys ScanKeys, poiManager *railpoi.Manager, txidStore railtxid.TransactionStore, txidMerkleTree railtxid.MerkleTreeStore, utxoTree railutxotree.Store, spentPOIEvents SpentPOIEventStore) (*Wallet, error) {
	return NewWalletWithAllStoresAndDetails(state, checkpoints, keys, poiManager, txidStore, txidMerkleTree, utxoTree, spentPOIEvents, nil)
}

func NewWalletWithStoresAndDetails(state StateStore, checkpoints railevents.CheckpointStore, keys ScanKeys, poiManager *railpoi.Manager, txidStore railtxid.TransactionStore, txidMerkleTree railtxid.MerkleTreeStore, spentPOIEvents SpentPOIEventStore, details WalletDetailsStore) (*Wallet, error) {
	return NewWalletWithAllStoresAndDetails(state, checkpoints, keys, poiManager, txidStore, txidMerkleTree, nil, spentPOIEvents, details)
}

func NewWalletWithAllStoresAndDetails(state StateStore, checkpoints railevents.CheckpointStore, keys ScanKeys, poiManager *railpoi.Manager, txidStore railtxid.TransactionStore, txidMerkleTree railtxid.MerkleTreeStore, utxoTree railutxotree.Store, spentPOIEvents SpentPOIEventStore, details WalletDetailsStore) (*Wallet, error) {
	if details == nil {
		details = NewMemoryWalletDetailsStore()
	}
	wallet := &Wallet{
		State:          state,
		Checkpoints:    checkpoints,
		Keys:           keys,
		POIManager:     poiManager,
		TXIDStore:      txidStore,
		TXIDMerkleTree: txidMerkleTree,
		UTXOMerkleTree: utxoTree,
		SpentPOIEvents: spentPOIEvents,
		Details:        details,
	}
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	return wallet, nil
}

func (wallet *Wallet) SyncV2(ctx context.Context, provider railevents.CheckpointedLogProvider, scan railevents.CheckpointedScan) (SyncResult, error) {
	if err := wallet.validate(); err != nil {
		return SyncResult{}, err
	}
	return SyncV2FromCheckpointWithAllStores(ctx, provider, wallet.Checkpoints, wallet.State, wallet.SpentPOIEvents, wallet.UTXOMerkleTree, wallet.Keys, scan)
}

func (wallet *Wallet) SyncV3(ctx context.Context, provider railevents.CheckpointedLogProvider, scan railevents.CheckpointedScan) (SyncResult, error) {
	if err := wallet.validate(); err != nil {
		return SyncResult{}, err
	}
	return SyncV3FromCheckpointWithAllStores(ctx, provider, wallet.Checkpoints, wallet.State, wallet.TXIDStore, wallet.TXIDMerkleTree, wallet.UTXOMerkleTree, wallet.SpentPOIEvents, wallet.Keys, scan)
}

func (wallet *Wallet) Rollback(ctx context.Context, checkpointKey string, fromBlock uint64) error {
	if err := wallet.validate(); err != nil {
		return err
	}
	txidStore, err := wallet.reorgTXIDStore()
	if err != nil {
		return err
	}
	txidMerkleTree, err := wallet.reorgTXIDMerkleTree()
	if err != nil {
		return err
	}
	utxoTree, err := wallet.reorgUTXOMerkleTree()
	if err != nil {
		return err
	}
	spentPOIEvents, err := wallet.reorgSpentPOIEventStore()
	if err != nil {
		return err
	}
	return RollbackWalletSyncWithAllStores(ctx, wallet.Checkpoints, wallet.State, txidStore, txidMerkleTree, utxoTree, spentPOIEvents, checkpointKey, fromBlock)
}

func (wallet *Wallet) Balances(ctx context.Context, includedBuckets []string) (TokenBalances, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	return wallet.State.TokenBalances(ctx, wallet.POIManager, includedBuckets)
}

func (wallet *Wallet) BalancesForTXIDVersion(ctx context.Context, txidVersion string, includedBuckets []string) (TokenBalances, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	if txidVersion == "" {
		return nil, fmt.Errorf("txid version is required")
	}
	txos, err := wallet.State.ListTXOs(ctx)
	if err != nil {
		return nil, err
	}
	return tokenBalancesFromTXOs(txosForTXIDVersion(txos, txidVersion), wallet.POIManager, includedBuckets)
}

func (wallet *Wallet) SpendableBalances(ctx context.Context, txidVersion string, chain railchain.Chain) (TokenBalances, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	buckets, err := wallet.POIManager.GetSpendableBalanceBuckets(ctx, chain)
	if err != nil {
		return nil, err
	}
	return wallet.BalancesForTXIDVersion(ctx, txidVersion, buckets)
}

func (wallet *Wallet) RefreshPOIs(ctx context.Context, txidVersion string, chain railchain.Chain) (RefreshPOIsSummary, error) {
	if err := wallet.validate(); err != nil {
		return RefreshPOIsSummary{}, err
	}
	return RefreshPOIs(ctx, wallet.State, wallet.POIManager, txidVersion, chain)
}

func (wallet *Wallet) RefreshSpentPOIEvents(ctx context.Context, txidVersion string, chain railchain.Chain) (RefreshSpentPOIEventsSummary, error) {
	if err := wallet.validate(); err != nil {
		return RefreshSpentPOIEventsSummary{}, err
	}
	return RefreshSpentPOIEvents(ctx, wallet.SpentPOIEvents, wallet.POIManager, txidVersion, chain)
}

func (wallet *Wallet) validate() error {
	if wallet == nil {
		return fmt.Errorf("wallet is required")
	}
	if wallet.State == nil {
		return fmt.Errorf("state store is required")
	}
	if wallet.Checkpoints == nil {
		return fmt.Errorf("checkpoint store is required")
	}
	if wallet.POIManager == nil {
		return fmt.Errorf("poi manager is required")
	}
	return validateImportInputs(wallet.State, wallet.Keys)
}

func (wallet *Wallet) reorgTXIDStore() (railtxid.ReorgTransactionStore, error) {
	if wallet == nil || wallet.TXIDStore == nil {
		return nil, nil
	}
	store, ok := wallet.TXIDStore.(railtxid.ReorgTransactionStore)
	if !ok {
		return nil, fmt.Errorf("txid store does not support rollback")
	}
	return store, nil
}

func (wallet *Wallet) reorgTXIDMerkleTree() (railtxid.ReorgMerkleTreeStore, error) {
	if wallet == nil || wallet.TXIDMerkleTree == nil {
		return nil, nil
	}
	store, ok := wallet.TXIDMerkleTree.(railtxid.ReorgMerkleTreeStore)
	if !ok {
		return nil, fmt.Errorf("txid merkle tree store does not support rollback")
	}
	return store, nil
}

func (wallet *Wallet) reorgUTXOMerkleTree() (railutxotree.ReorgStore, error) {
	if wallet == nil || wallet.UTXOMerkleTree == nil {
		return nil, nil
	}
	store, ok := wallet.UTXOMerkleTree.(railutxotree.ReorgStore)
	if !ok {
		return nil, fmt.Errorf("utxo merkle tree store does not support rollback")
	}
	return store, nil
}

func (wallet *Wallet) reorgSpentPOIEventStore() (ReorgSpentPOIEventStore, error) {
	if wallet == nil || wallet.SpentPOIEvents == nil {
		return nil, nil
	}
	store, ok := wallet.SpentPOIEvents.(ReorgSpentPOIEventStore)
	if !ok {
		return nil, fmt.Errorf("spent poi event store does not support rollback")
	}
	return store, nil
}
