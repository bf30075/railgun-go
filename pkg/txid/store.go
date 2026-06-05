package txid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

type UnshieldData struct {
	TokenData railcrypto.TokenData `json:"tokenData"`
	ToAddress string               `json:"toAddress"`
	Value     string               `json:"value"`
	Fee       string               `json:"fee,omitempty"`
}

type Transaction struct {
	Version                   string        `json:"version"`
	RailgunTxid               string        `json:"railgunTxid"`
	Txid                      string        `json:"txid"`
	BlockNumber               uint64        `json:"blockNumber"`
	Commitments               []string      `json:"commitments"`
	Nullifiers                []string      `json:"nullifiers"`
	BoundParamsHash           string        `json:"boundParamsHash"`
	Unshield                  *UnshieldData `json:"unshield,omitempty"`
	UTXOTreeIn                int           `json:"utxoTreeIn"`
	UTXOTreeOut               int           `json:"utxoTreeOut"`
	UTXOBatchStartPositionOut int           `json:"utxoBatchStartPositionOut"`
	VerificationHash          string        `json:"verificationHash,omitempty"`
}

type TransactionStore interface {
	UpsertTransaction(ctx context.Context, transaction Transaction) error
	GetByRailgunTxid(ctx context.Context, railgunTxid string) (Transaction, bool, error)
	ListTransactions(ctx context.Context) ([]Transaction, error)
}

type ReorgTransactionStore interface {
	TransactionStore
	RollbackToBlock(ctx context.Context, fromBlock uint64) error
}

type MemoryTransactionStore struct {
	mu           sync.RWMutex
	transactions map[string]Transaction
}

func NewMemoryTransactionStore() *MemoryTransactionStore {
	return &MemoryTransactionStore{transactions: map[string]Transaction{}}
}

func (store *MemoryTransactionStore) UpsertTransaction(ctx context.Context, transaction Transaction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("transaction store is required")
	}
	if transaction.RailgunTxid == "" {
		return fmt.Errorf("railgun txid is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.transactions == nil {
		store.transactions = map[string]Transaction{}
	}
	store.transactions[transaction.RailgunTxid] = cloneTransaction(transaction)
	return nil
}

func (store *MemoryTransactionStore) GetByRailgunTxid(ctx context.Context, railgunTxid string) (Transaction, bool, error) {
	if err := ctx.Err(); err != nil {
		return Transaction{}, false, err
	}
	if store == nil {
		return Transaction{}, false, fmt.Errorf("transaction store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	transaction, ok := store.transactions[railgunTxid]
	if !ok {
		return Transaction{}, false, nil
	}
	return cloneTransaction(transaction), true, nil
}

func (store *MemoryTransactionStore) ListTransactions(ctx context.Context) ([]Transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("transaction store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return sortedTransactions(store.transactions), nil
}

func (store *MemoryTransactionStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("transaction store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for railgunTxid, transaction := range store.transactions {
		if transaction.BlockNumber >= fromBlock {
			delete(store.transactions, railgunTxid)
		}
	}
	return nil
}

type FileTransactionStore struct {
	Path string
	mu   sync.Mutex
}

func NewFileTransactionStore(path string) *FileTransactionStore {
	return &FileTransactionStore{Path: path}
}

func (store *FileTransactionStore) UpsertTransaction(ctx context.Context, transaction Transaction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if transaction.RailgunTxid == "" {
		return fmt.Errorf("railgun txid is required")
	}
	return store.update(func(transactions map[string]Transaction) error {
		transactions[transaction.RailgunTxid] = cloneTransaction(transaction)
		return nil
	})
}

func (store *FileTransactionStore) GetByRailgunTxid(ctx context.Context, railgunTxid string) (Transaction, bool, error) {
	if err := ctx.Err(); err != nil {
		return Transaction{}, false, err
	}
	transactions, err := store.load()
	if err != nil {
		return Transaction{}, false, err
	}
	transaction, ok := transactions[railgunTxid]
	if !ok {
		return Transaction{}, false, nil
	}
	return cloneTransaction(transaction), true, nil
}

func (store *FileTransactionStore) ListTransactions(ctx context.Context) ([]Transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	transactions, err := store.load()
	if err != nil {
		return nil, err
	}
	return sortedTransactions(transactions), nil
}

func (store *FileTransactionStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.update(func(transactions map[string]Transaction) error {
		for railgunTxid, transaction := range transactions {
			if transaction.BlockNumber >= fromBlock {
				delete(transactions, railgunTxid)
			}
		}
		return nil
	})
}

func (store *FileTransactionStore) update(update func(map[string]Transaction) error) error {
	if store == nil {
		return fmt.Errorf("transaction store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	transactions, err := store.loadLocked()
	if err != nil {
		return err
	}
	if err := update(transactions); err != nil {
		return err
	}
	return store.saveLocked(transactions)
}

func (store *FileTransactionStore) load() (map[string]Transaction, error) {
	if store == nil {
		return nil, fmt.Errorf("transaction store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked()
}

func (store *FileTransactionStore) loadLocked() (map[string]Transaction, error) {
	if store.Path == "" {
		return nil, fmt.Errorf("transaction store file path is required")
	}
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Transaction{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return map[string]Transaction{}, nil
	}
	var state transactionFileState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	transactions := make(map[string]Transaction, len(state.Transactions))
	for i, transaction := range state.Transactions {
		if transaction.RailgunTxid == "" {
			return nil, fmt.Errorf("transactions[%d]: railgun txid is required", i)
		}
		transactions[transaction.RailgunTxid] = cloneTransaction(transaction)
	}
	return transactions, nil
}

func (store *FileTransactionStore) saveLocked(transactions map[string]Transaction) error {
	if store.Path == "" {
		return fmt.Errorf("transaction store file path is required")
	}
	data, err := json.MarshalIndent(transactionFileState{Transactions: sortedTransactions(transactions)}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o755); err != nil {
		return err
	}
	tmpPath := store.Path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, store.Path)
}

type transactionFileState struct {
	Transactions []Transaction `json:"transactions"`
}

func sortedTransactions(transactions map[string]Transaction) []Transaction {
	out := make([]Transaction, 0, len(transactions))
	for _, transaction := range transactions {
		out = append(out, cloneTransaction(transaction))
	}
	sort.Slice(out, func(i int, j int) bool {
		if out[i].BlockNumber != out[j].BlockNumber {
			return out[i].BlockNumber < out[j].BlockNumber
		}
		if out[i].Txid != out[j].Txid {
			return out[i].Txid < out[j].Txid
		}
		return out[i].RailgunTxid < out[j].RailgunTxid
	})
	return out
}

func cloneTransaction(transaction Transaction) Transaction {
	transaction.Commitments = append([]string(nil), transaction.Commitments...)
	transaction.Nullifiers = append([]string(nil), transaction.Nullifiers...)
	if transaction.Unshield != nil {
		unshield := *transaction.Unshield
		transaction.Unshield = &unshield
	}
	return transaction
}
