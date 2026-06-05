package wallet

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"sync"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

type StoredTXO struct {
	TXIDVersion                 string
	Tree                        uint64
	Position                    uint64
	TXID                        string
	Timestamp                   *uint64
	BlockNumber                 uint64
	SpendTXID                   string
	SpendBlockNumber            *uint64
	Nullifier                   string
	CommitmentHash              string
	NotePublicKey               string
	NoteRandom                  string
	TokenHash                   string
	TokenData                   railcrypto.TokenData
	Value                       *big.Int
	OutputType                  *int
	WalletSource                string
	MemoText                    string
	SenderAddress               string
	RecipientAddress            string
	ShieldFee                   string
	CommitmentType              string
	POIsPerList                 railpoi.POIsPerList
	BlindedCommitment           string
	TransactCreationRailgunTxid string
}

type TokenBalance struct {
	Balance   *big.Int
	TokenData railcrypto.TokenData
	UTXOs     []StoredTXO
}

type TokenBalances map[string]TokenBalance

type StateStore interface {
	UpsertTXO(ctx context.Context, txo StoredTXO) error
	GetTXO(ctx context.Context, nullifier string) (StoredTXO, bool, error)
	ListTXOs(ctx context.Context) ([]StoredTXO, error)
	MarkTXOSpent(ctx context.Context, nullifier string, spendTXID string) error
	UpdateTXOPOIs(ctx context.Context, nullifier string, pois railpoi.POIsPerList) error
	TokenBalances(ctx context.Context, poiManager *railpoi.Manager, includedBuckets []string) (TokenBalances, error)
}

type ReorgStateStore interface {
	MarkTXOSpentAtBlock(ctx context.Context, nullifier string, spendTXID string, blockNumber uint64) error
	RollbackToBlock(ctx context.Context, fromBlock uint64) error
}

type MemoryStateStore struct {
	mu   sync.RWMutex
	txos map[string]StoredTXO
}

func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{txos: map[string]StoredTXO{}}
}

func (store *MemoryStateStore) UpsertTXO(ctx context.Context, txo StoredTXO) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("state store is required")
	}
	if txo.Nullifier == "" {
		return fmt.Errorf("txo nullifier is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.txos == nil {
		store.txos = map[string]StoredTXO{}
	}
	store.txos[txo.Nullifier] = cloneStoredTXO(txo)
	return nil
}

func (store *MemoryStateStore) GetTXO(ctx context.Context, nullifier string) (StoredTXO, bool, error) {
	if err := ctx.Err(); err != nil {
		return StoredTXO{}, false, err
	}
	if store == nil {
		return StoredTXO{}, false, fmt.Errorf("state store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	txo, ok := store.txos[nullifier]
	if !ok {
		return StoredTXO{}, false, nil
	}
	return cloneStoredTXO(txo), true, nil
}

func (store *MemoryStateStore) ListTXOs(ctx context.Context) ([]StoredTXO, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("state store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return sortedTXOs(store.txos), nil
}

func (store *MemoryStateStore) MarkTXOSpent(ctx context.Context, nullifier string, spendTXID string) error {
	return store.markTXOSpent(ctx, nullifier, spendTXID, nil)
}

func (store *MemoryStateStore) MarkTXOSpentAtBlock(ctx context.Context, nullifier string, spendTXID string, blockNumber uint64) error {
	return store.markTXOSpent(ctx, nullifier, spendTXID, &blockNumber)
}

func (store *MemoryStateStore) markTXOSpent(ctx context.Context, nullifier string, spendTXID string, blockNumber *uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("state store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	txo, ok := store.txos[nullifier]
	if !ok {
		return fmt.Errorf("missing txo for nullifier %s", nullifier)
	}
	txo.SpendTXID = spendTXID
	txo.SpendBlockNumber = cloneUint64Ptr(blockNumber)
	store.txos[nullifier] = txo
	return nil
}

func (store *MemoryStateStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("state store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for nullifier, txo := range store.txos {
		if txo.BlockNumber >= fromBlock {
			delete(store.txos, nullifier)
			continue
		}
		if txo.SpendBlockNumber != nil && *txo.SpendBlockNumber >= fromBlock {
			txo.SpendTXID = ""
			txo.SpendBlockNumber = nil
			store.txos[nullifier] = txo
		}
	}
	return nil
}

func (store *MemoryStateStore) UpdateTXOPOIs(ctx context.Context, nullifier string, pois railpoi.POIsPerList) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("state store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	txo, ok := store.txos[nullifier]
	if !ok {
		return fmt.Errorf("missing txo for nullifier %s", nullifier)
	}
	txo.POIsPerList = clonePOIsPerList(pois)
	store.txos[nullifier] = txo
	return nil
}

func (store *MemoryStateStore) TokenBalances(ctx context.Context, poiManager *railpoi.Manager, includedBuckets []string) (TokenBalances, error) {
	if poiManager == nil {
		return nil, fmt.Errorf("poi manager is required")
	}
	txos, err := store.ListTXOs(ctx)
	if err != nil {
		return nil, err
	}
	return tokenBalancesFromTXOs(txos, poiManager, includedBuckets)
}

func tokenBalancesFromTXOs(txos []StoredTXO, poiManager *railpoi.Manager, includedBuckets []string) (TokenBalances, error) {
	included := map[string]bool{}
	for _, bucket := range includedBuckets {
		included[bucket] = true
	}
	out := TokenBalances{}
	for _, txo := range txos {
		if txo.Value == nil {
			return nil, fmt.Errorf("txo %s value is required", txo.Nullifier)
		}
		bucket := poiManager.GetBalanceBucket(railpoi.TXO{
			SpendTXID:                   txo.SpendTXID,
			POIsPerList:                 clonePOIsPerList(txo.POIsPerList),
			CommitmentType:              txo.CommitmentType,
			OutputType:                  cloneIntPtr(txo.OutputType),
			Value:                       new(big.Int).Set(txo.Value),
			BlindedCommitment:           txo.BlindedCommitment,
			BlockNumber:                 txo.BlockNumber,
			TransactCreationRailgunTxid: txo.TransactCreationRailgunTxid,
		})
		if len(included) > 0 && !included[bucket] {
			continue
		}
		tokenHash := txo.TokenHash
		if tokenHash == "" {
			var err error
			tokenHash, err = railcrypto.TokenDataHash(txo.TokenData)
			if err != nil {
				return nil, err
			}
		}
		balance := out[tokenHash]
		if balance.Balance == nil {
			balance.Balance = big.NewInt(0)
			balance.TokenData = txo.TokenData
		}
		balance.Balance.Add(balance.Balance, txo.Value)
		balance.UTXOs = append(balance.UTXOs, cloneStoredTXO(txo))
		out[tokenHash] = balance
	}
	return out, nil
}

func sortedTXOs(txos map[string]StoredTXO) []StoredTXO {
	out := make([]StoredTXO, 0, len(txos))
	for _, txo := range txos {
		out = append(out, cloneStoredTXO(txo))
	}
	sort.Slice(out, func(i int, j int) bool {
		if out[i].Tree != out[j].Tree {
			return out[i].Tree < out[j].Tree
		}
		if out[i].Position != out[j].Position {
			return out[i].Position < out[j].Position
		}
		return out[i].Nullifier < out[j].Nullifier
	})
	return out
}

func cloneStoredTXO(txo StoredTXO) StoredTXO {
	txo.Timestamp = cloneUint64Ptr(txo.Timestamp)
	txo.SpendBlockNumber = cloneUint64Ptr(txo.SpendBlockNumber)
	txo.Value = cloneBigInt(txo.Value)
	txo.OutputType = cloneIntPtr(txo.OutputType)
	txo.POIsPerList = clonePOIsPerList(txo.POIsPerList)
	return txo
}

func clonePOIsPerList(pois railpoi.POIsPerList) railpoi.POIsPerList {
	if pois == nil {
		return nil
	}
	out := make(railpoi.POIsPerList, len(pois))
	for key, value := range pois {
		out[key] = value
	}
	return out
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func cloneUint64Ptr(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneIntPtr(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
