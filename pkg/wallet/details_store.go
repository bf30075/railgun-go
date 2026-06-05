package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
)

type WalletDetails struct {
	TreeScannedHeights []uint64 `json:"treeScannedHeights"`
	CreationTree       *uint64  `json:"creationTree,omitempty"`
	CreationTreeHeight *uint64  `json:"creationTreeHeight,omitempty"`
}

type WalletDetailsMap map[string]WalletDetails

type WalletDetailsStore interface {
	LoadWalletDetailsMap(ctx context.Context, chain railchain.Chain) (WalletDetailsMap, error)
	SaveWalletDetailsMap(ctx context.Context, chain railchain.Chain, details WalletDetailsMap) error
}

type MemoryWalletDetailsStore struct {
	mu      sync.RWMutex
	details map[string]WalletDetailsMap
}

func NewMemoryWalletDetailsStore() *MemoryWalletDetailsStore {
	return &MemoryWalletDetailsStore{details: map[string]WalletDetailsMap{}}
}

func (store *MemoryWalletDetailsStore) LoadWalletDetailsMap(ctx context.Context, chain railchain.Chain) (WalletDetailsMap, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("wallet details store is required")
	}
	key, err := walletDetailsChainKey(chain)
	if err != nil {
		return nil, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return cloneWalletDetailsMap(store.details[key]), nil
}

func (store *MemoryWalletDetailsStore) SaveWalletDetailsMap(ctx context.Context, chain railchain.Chain, details WalletDetailsMap) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("wallet details store is required")
	}
	key, err := walletDetailsChainKey(chain)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.details == nil {
		store.details = map[string]WalletDetailsMap{}
	}
	store.details[key] = cloneWalletDetailsMap(details)
	return nil
}

type FileWalletDetailsStore struct {
	Path string
	mu   sync.Mutex
}

func NewFileWalletDetailsStore(path string) *FileWalletDetailsStore {
	return &FileWalletDetailsStore{Path: path}
}

func (store *FileWalletDetailsStore) LoadWalletDetailsMap(ctx context.Context, chain railchain.Chain) (WalletDetailsMap, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := walletDetailsChainKey(chain)
	if err != nil {
		return nil, err
	}
	state, err := store.load()
	if err != nil {
		return nil, err
	}
	return cloneWalletDetailsMap(state.Chains[key].Details), nil
}

func (store *FileWalletDetailsStore) SaveWalletDetailsMap(ctx context.Context, chain railchain.Chain, details WalletDetailsMap) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := walletDetailsChainKey(chain)
	if err != nil {
		return err
	}
	return store.update(func(state walletDetailsFileState) (walletDetailsFileState, error) {
		if state.Chains == nil {
			state.Chains = map[string]walletDetailsChainRecord{}
		}
		state.Chains[key] = walletDetailsChainRecord{
			Chain:   chain,
			Details: cloneWalletDetailsMap(details),
		}
		return state, nil
	})
}

func (store *FileWalletDetailsStore) update(update func(walletDetailsFileState) (walletDetailsFileState, error)) error {
	if store == nil {
		return fmt.Errorf("wallet details store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.loadLocked()
	if err != nil {
		return err
	}
	state, err = update(state)
	if err != nil {
		return err
	}
	return store.saveLocked(state)
}

func (store *FileWalletDetailsStore) load() (walletDetailsFileState, error) {
	if store == nil {
		return walletDetailsFileState{}, fmt.Errorf("wallet details store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked()
}

func (store *FileWalletDetailsStore) loadLocked() (walletDetailsFileState, error) {
	if store.Path == "" {
		return walletDetailsFileState{}, fmt.Errorf("wallet details store file path is required")
	}
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return newWalletDetailsFileState(), nil
	}
	if err != nil {
		return walletDetailsFileState{}, err
	}
	if len(data) == 0 {
		return newWalletDetailsFileState(), nil
	}
	var records walletDetailsFileRecords
	if err := json.Unmarshal(data, &records); err != nil {
		return walletDetailsFileState{}, err
	}
	state := newWalletDetailsFileState()
	for i, record := range records.Chains {
		key, err := walletDetailsChainKey(record.Chain)
		if err != nil {
			return walletDetailsFileState{}, fmt.Errorf("chains[%d]: %w", i, err)
		}
		state.Chains[key] = walletDetailsChainRecord{
			Chain:   record.Chain,
			Details: cloneWalletDetailsMap(record.Details),
		}
	}
	return state, nil
}

func (store *FileWalletDetailsStore) saveLocked(state walletDetailsFileState) error {
	if store.Path == "" {
		return fmt.Errorf("wallet details store file path is required")
	}
	records := walletDetailsFileRecordsFromState(state)
	data, err := json.MarshalIndent(records, "", "  ")
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

type walletDetailsFileState struct {
	Chains map[string]walletDetailsChainRecord
}

type walletDetailsFileRecords struct {
	Chains []walletDetailsChainRecord `json:"chains"`
}

type walletDetailsChainRecord struct {
	Chain   railchain.Chain  `json:"chain"`
	Details WalletDetailsMap `json:"details"`
}

func newWalletDetailsFileState() walletDetailsFileState {
	return walletDetailsFileState{Chains: map[string]walletDetailsChainRecord{}}
}

func walletDetailsFileRecordsFromState(state walletDetailsFileState) walletDetailsFileRecords {
	keys := make([]string, 0, len(state.Chains))
	for key := range state.Chains {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	chains := make([]walletDetailsChainRecord, len(keys))
	for i, key := range keys {
		record := state.Chains[key]
		record.Details = cloneWalletDetailsMap(record.Details)
		chains[i] = record
	}
	return walletDetailsFileRecords{Chains: chains}
}

func walletDetailsChainKey(chain railchain.Chain) (string, error) {
	key, err := railchain.FullNetworkIDHex(chain)
	if err != nil {
		return "", err
	}
	return key, nil
}

func defaultWalletDetails() WalletDetails {
	return WalletDetails{TreeScannedHeights: []uint64{}}
}

func cloneWalletDetailsMap(details WalletDetailsMap) WalletDetailsMap {
	out := WalletDetailsMap{}
	for txidVersion, detail := range details {
		out[txidVersion] = cloneWalletDetails(detail)
	}
	return out
}

func cloneWalletDetails(details WalletDetails) WalletDetails {
	details.TreeScannedHeights = append([]uint64(nil), details.TreeScannedHeights...)
	details.CreationTree = cloneUint64Ptr(details.CreationTree)
	details.CreationTreeHeight = cloneUint64Ptr(details.CreationTreeHeight)
	if details.TreeScannedHeights == nil {
		details.TreeScannedHeights = []uint64{}
	}
	return details
}
