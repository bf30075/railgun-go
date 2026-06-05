package utxotree

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"
)

const TreeMaxItems = 65536

type Leaf struct {
	Tree           uint64 `json:"tree"`
	Index          uint64 `json:"index"`
	Hash           string `json:"hash"`
	TXID           string `json:"txid,omitempty"`
	CommitmentType string `json:"commitmentType,omitempty"`
	BlockNumber    uint64 `json:"blockNumber,omitempty"`
}

type Store interface {
	UpsertLeaf(ctx context.Context, leaf Leaf) error
	GetLeaf(ctx context.Context, tree uint64, index uint64) (Leaf, bool, error)
	ListLeaves(ctx context.Context) ([]Leaf, error)
	Root(ctx context.Context, tree uint64) (string, error)
	Proof(ctx context.Context, tree uint64, index uint64) (merkletree.MerkleProof, error)
}

type BulkStore interface {
	UpsertLeaves(ctx context.Context, leaves []Leaf) error
}

type V2CommitmentEventStore interface {
	UpsertV2CommitmentEvents(ctx context.Context, events []railevents.CommitmentEvent) (int, error)
}

type V2CommitmentReader interface {
	GetV2Commitment(ctx context.Context, tree uint64, index uint64) (railevents.Commitment, bool, error)
	ListV2Commitments(ctx context.Context) ([]railevents.Commitment, error)
}

type V3CommitmentEventStore interface {
	UpsertV3CommitmentEvents(ctx context.Context, events []railevents.V3CommitmentEvent) (int, error)
}

type V3CommitmentReader interface {
	GetV3Commitment(ctx context.Context, tree uint64, index uint64) (railevents.V3Commitment, bool, error)
	ListV3Commitments(ctx context.Context) ([]railevents.V3Commitment, error)
}

type NullifierEventStore interface {
	UpsertNullifiers(ctx context.Context, nullifiers []railevents.Nullifier) (int, error)
}

type NullifierReader interface {
	GetNullifierTxid(ctx context.Context, nullifier string, tree *uint64) (string, bool, error)
	ListNullifiers(ctx context.Context) ([]railevents.Nullifier, error)
}

type UnshieldEventStore interface {
	UpsertUnshieldEvents(ctx context.Context, unshields []railevents.UnshieldStoredEvent, replaceExisting bool) (int, error)
}

type UnshieldEventReader interface {
	GetUnshieldEventsByTxid(ctx context.Context, txid string) ([]railevents.UnshieldStoredEvent, error)
	ListUnshieldEvents(ctx context.Context) ([]railevents.UnshieldStoredEvent, error)
}

type ReorgStore interface {
	Store
	RollbackToBlock(ctx context.Context, fromBlock uint64) error
}

func IndexV2CommitmentEvents(ctx context.Context, store Store, events []railevents.CommitmentEvent) (int, error) {
	if store == nil {
		return 0, fmt.Errorf("utxo merkle tree store is required")
	}
	if commitmentStore, ok := store.(V2CommitmentEventStore); ok {
		return commitmentStore.UpsertV2CommitmentEvents(ctx, events)
	}
	leaves := []Leaf{}
	for _, event := range events {
		for _, commitment := range event.Commitments {
			if err := ctx.Err(); err != nil {
				return len(leaves), err
			}
			leaf, err := LeafFromV2Commitment(commitment)
			if err != nil {
				return len(leaves), err
			}
			leaves = append(leaves, leaf)
		}
	}
	if bulkStore, ok := store.(BulkStore); ok {
		if err := bulkStore.UpsertLeaves(ctx, leaves); err != nil {
			return 0, err
		}
		return len(leaves), nil
	}
	for i, leaf := range leaves {
		if err := store.UpsertLeaf(ctx, leaf); err != nil {
			return i, err
		}
	}
	return len(leaves), nil
}

func IndexV3CommitmentEvents(ctx context.Context, store Store, events []railevents.V3CommitmentEvent) (int, error) {
	if store == nil {
		return 0, fmt.Errorf("utxo merkle tree store is required")
	}
	if commitmentStore, ok := store.(V3CommitmentEventStore); ok {
		return commitmentStore.UpsertV3CommitmentEvents(ctx, events)
	}
	leaves := []Leaf{}
	for _, event := range events {
		for _, commitment := range event.Commitments {
			if err := ctx.Err(); err != nil {
				return len(leaves), err
			}
			leaf, err := LeafFromV3Commitment(commitment)
			if err != nil {
				return len(leaves), err
			}
			leaves = append(leaves, leaf)
		}
	}
	if bulkStore, ok := store.(BulkStore); ok {
		if err := bulkStore.UpsertLeaves(ctx, leaves); err != nil {
			return 0, err
		}
		return len(leaves), nil
	}
	for i, leaf := range leaves {
		if err := store.UpsertLeaf(ctx, leaf); err != nil {
			return i, err
		}
	}
	return len(leaves), nil
}

func LeafFromV2Commitment(commitment railevents.Commitment) (Leaf, error) {
	return leafFromCommitment(
		commitment.Hash,
		commitment.Txid,
		commitment.CommitmentType,
		commitment.BlockNumber,
		commitment.UTXOTree,
		commitment.UTXOIndex,
	)
}

func LeafFromV3Commitment(commitment railevents.V3Commitment) (Leaf, error) {
	return leafFromCommitment(
		commitment.Hash,
		commitment.Txid,
		commitment.CommitmentType,
		commitment.BlockNumber,
		commitment.UTXOTree,
		commitment.UTXOIndex,
	)
}

type MemoryStore struct {
	mu     sync.RWMutex
	leaves map[uint64]map[uint64]Leaf
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{leaves: map[uint64]map[uint64]Leaf{}}
}

func (store *MemoryStore) UpsertLeaf(ctx context.Context, leaf Leaf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("utxo merkle tree store is required")
	}
	if err := validateLeaf(leaf); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.leaves == nil {
		store.leaves = map[uint64]map[uint64]Leaf{}
	}
	if store.leaves[leaf.Tree] == nil {
		store.leaves[leaf.Tree] = map[uint64]Leaf{}
	}
	store.leaves[leaf.Tree][leaf.Index] = leaf
	return nil
}

func (store *MemoryStore) UpsertLeaves(ctx context.Context, leaves []Leaf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("utxo merkle tree store is required")
	}
	for i, leaf := range leaves {
		if err := validateLeaf(leaf); err != nil {
			return fmt.Errorf("leaves[%d]: %w", i, err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.leaves == nil {
		store.leaves = map[uint64]map[uint64]Leaf{}
	}
	for _, leaf := range leaves {
		if store.leaves[leaf.Tree] == nil {
			store.leaves[leaf.Tree] = map[uint64]Leaf{}
		}
		store.leaves[leaf.Tree][leaf.Index] = leaf
	}
	return nil
}

func (store *MemoryStore) GetLeaf(ctx context.Context, tree uint64, index uint64) (Leaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return Leaf{}, false, err
	}
	if store == nil {
		return Leaf{}, false, fmt.Errorf("utxo merkle tree store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	leaf, ok := store.leaves[tree][index]
	return leaf, ok, nil
}

func (store *MemoryStore) ListLeaves(ctx context.Context) ([]Leaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("utxo merkle tree store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return sortedLeaves(store.leaves), nil
}

func (store *MemoryStore) Root(ctx context.Context, tree uint64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if store == nil {
		return "", fmt.Errorf("utxo merkle tree store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	levels, err := buildTreeLevels(store.leaves[tree])
	if err != nil {
		return "", err
	}
	return nodeAtLevel(levels, merkletree.TreeDepth, 0), nil
}

func (store *MemoryStore) Proof(ctx context.Context, tree uint64, index uint64) (merkletree.MerkleProof, error) {
	if err := ctx.Err(); err != nil {
		return merkletree.MerkleProof{}, err
	}
	if store == nil {
		return merkletree.MerkleProof{}, fmt.Errorf("utxo merkle tree store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return proofFromLeaves(store.leaves[tree], index)
}

func (store *MemoryStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("utxo merkle tree store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for tree, leaves := range store.leaves {
		for index, leaf := range leaves {
			if leaf.BlockNumber >= fromBlock {
				delete(leaves, index)
			}
		}
		if len(leaves) == 0 {
			delete(store.leaves, tree)
		}
	}
	return nil
}

type FileStore struct {
	Path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore {
	return &FileStore{Path: path}
}

func (store *FileStore) UpsertLeaf(ctx context.Context, leaf Leaf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateLeaf(leaf); err != nil {
		return err
	}
	return store.update(func(leaves map[uint64]map[uint64]Leaf) error {
		if leaves[leaf.Tree] == nil {
			leaves[leaf.Tree] = map[uint64]Leaf{}
		}
		leaves[leaf.Tree][leaf.Index] = leaf
		return nil
	})
}

func (store *FileStore) UpsertLeaves(ctx context.Context, leaves []Leaf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for i, leaf := range leaves {
		if err := validateLeaf(leaf); err != nil {
			return fmt.Errorf("leaves[%d]: %w", i, err)
		}
	}
	return store.update(func(existing map[uint64]map[uint64]Leaf) error {
		for _, leaf := range leaves {
			if existing[leaf.Tree] == nil {
				existing[leaf.Tree] = map[uint64]Leaf{}
			}
			existing[leaf.Tree][leaf.Index] = leaf
		}
		return nil
	})
}

func (store *FileStore) GetLeaf(ctx context.Context, tree uint64, index uint64) (Leaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return Leaf{}, false, err
	}
	leaves, err := store.load()
	if err != nil {
		return Leaf{}, false, err
	}
	leaf, ok := leaves[tree][index]
	return leaf, ok, nil
}

func (store *FileStore) ListLeaves(ctx context.Context) ([]Leaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	leaves, err := store.load()
	if err != nil {
		return nil, err
	}
	return sortedLeaves(leaves), nil
}

func (store *FileStore) Root(ctx context.Context, tree uint64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	leaves, err := store.load()
	if err != nil {
		return "", err
	}
	levels, err := buildTreeLevels(leaves[tree])
	if err != nil {
		return "", err
	}
	return nodeAtLevel(levels, merkletree.TreeDepth, 0), nil
}

func (store *FileStore) Proof(ctx context.Context, tree uint64, index uint64) (merkletree.MerkleProof, error) {
	if err := ctx.Err(); err != nil {
		return merkletree.MerkleProof{}, err
	}
	leaves, err := store.load()
	if err != nil {
		return merkletree.MerkleProof{}, err
	}
	return proofFromLeaves(leaves[tree], index)
}

func (store *FileStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.update(func(leaves map[uint64]map[uint64]Leaf) error {
		for tree, treeLeaves := range leaves {
			for index, leaf := range treeLeaves {
				if leaf.BlockNumber >= fromBlock {
					delete(treeLeaves, index)
				}
			}
			if len(treeLeaves) == 0 {
				delete(leaves, tree)
			}
		}
		return nil
	})
}

func (store *FileStore) update(update func(map[uint64]map[uint64]Leaf) error) error {
	if store == nil {
		return fmt.Errorf("utxo merkle tree store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	leaves, err := store.loadLocked()
	if err != nil {
		return err
	}
	if err := update(leaves); err != nil {
		return err
	}
	return store.saveLocked(leaves)
}

func (store *FileStore) load() (map[uint64]map[uint64]Leaf, error) {
	if store == nil {
		return nil, fmt.Errorf("utxo merkle tree store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked()
}

func (store *FileStore) loadLocked() (map[uint64]map[uint64]Leaf, error) {
	if store.Path == "" {
		return nil, fmt.Errorf("utxo merkle tree store file path is required")
	}
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[uint64]map[uint64]Leaf{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return map[uint64]map[uint64]Leaf{}, nil
	}
	var state fileState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	leaves := map[uint64]map[uint64]Leaf{}
	for i, leaf := range state.Leaves {
		if err := validateLeaf(leaf); err != nil {
			return nil, fmt.Errorf("leaves[%d]: %w", i, err)
		}
		if leaves[leaf.Tree] == nil {
			leaves[leaf.Tree] = map[uint64]Leaf{}
		}
		leaves[leaf.Tree][leaf.Index] = leaf
	}
	return leaves, nil
}

func (store *FileStore) saveLocked(leaves map[uint64]map[uint64]Leaf) error {
	if store.Path == "" {
		return fmt.Errorf("utxo merkle tree store file path is required")
	}
	data, err := json.MarshalIndent(fileState{Leaves: sortedLeaves(leaves)}, "", "  ")
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

type fileState struct {
	Leaves []Leaf `json:"leaves"`
}

func leafFromCommitment(hash string, txid string, commitmentType string, blockNumber uint64, tree int, index int) (Leaf, error) {
	if tree < 0 || index < 0 {
		return Leaf{}, fmt.Errorf("utxo tree and index must be non-negative")
	}
	formattedHash, err := railcrypto.FormatHexToByteLength(hash, 32, false)
	if err != nil {
		return Leaf{}, fmt.Errorf("commitment hash: %w", err)
	}
	leaf := Leaf{
		Tree:           uint64(tree),
		Index:          uint64(index),
		Hash:           formattedHash,
		TXID:           txid,
		CommitmentType: commitmentType,
		BlockNumber:    blockNumber,
	}
	if err := validateLeaf(leaf); err != nil {
		return Leaf{}, err
	}
	return leaf, nil
}

func proofFromLeaves(leaves map[uint64]Leaf, index uint64) (merkletree.MerkleProof, error) {
	if index >= TreeMaxItems {
		return merkletree.MerkleProof{}, fmt.Errorf("utxo merkle tree index exceeds tree size")
	}
	leaf, ok := leaves[index]
	if !ok {
		return merkletree.MerkleProof{}, fmt.Errorf("missing utxo merkle leaf at index %d", index)
	}
	levels, err := buildTreeLevels(leaves)
	if err != nil {
		return merkletree.MerkleProof{}, err
	}
	elements := make([]string, merkletree.TreeDepth)
	proofIndex := index
	for level := 0; level < merkletree.TreeDepth; level++ {
		elements[level] = nodeAtLevel(levels, level, proofIndex^1)
		proofIndex >>= 1
	}
	indices, err := railcrypto.BigIntToHex(new(big.Int).SetUint64(leaf.Index), 32, false)
	if err != nil {
		return merkletree.MerkleProof{}, err
	}
	return merkletree.MerkleProof{
		Leaf:     leaf.Hash,
		Indices:  indices,
		Elements: elements,
		Root:     nodeAtLevel(levels, merkletree.TreeDepth, 0),
	}, nil
}

func buildTreeLevels(leaves map[uint64]Leaf) ([]map[uint64]string, error) {
	levels := make([]map[uint64]string, merkletree.TreeDepth+1)
	levels[0] = map[uint64]string{}
	for index, leaf := range leaves {
		if err := validateLeaf(leaf); err != nil {
			return nil, err
		}
		levels[0][index] = leaf.Hash
	}
	for level := 0; level < merkletree.TreeDepth; level++ {
		next := map[uint64]string{}
		seenParents := map[uint64]bool{}
		for index := range levels[level] {
			parent := index >> 1
			if seenParents[parent] {
				continue
			}
			seenParents[parent] = true
			leftIndex := parent << 1
			rightIndex := leftIndex + 1
			left := nodeAtLevel(levels, level, leftIndex)
			right := nodeAtLevel(levels, level, rightIndex)
			hash, err := hashHexPair(left, right)
			if err != nil {
				return nil, err
			}
			if hash != ZeroHash(level+1) {
				next[parent] = hash
			}
		}
		levels[level+1] = next
	}
	return levels, nil
}

func nodeAtLevel(levels []map[uint64]string, level int, index uint64) string {
	if level < len(levels) {
		if value, ok := levels[level][index]; ok {
			return value
		}
	}
	return ZeroHash(level)
}

func hashHexPair(left string, right string) (string, error) {
	leftBigInt, err := railcrypto.HexToBigInt(left)
	if err != nil {
		return "", err
	}
	rightBigInt, err := railcrypto.HexToBigInt(right)
	if err != nil {
		return "", err
	}
	hash, err := railcrypto.Poseidon(leftBigInt, rightBigInt)
	if err != nil {
		return "", err
	}
	return railcrypto.BigIntToHex(hash, 32, false)
}

func ZeroHash(level int) string {
	if level < 0 {
		level = 0
	}
	zeros := zeroHashes()
	if level >= len(zeros) {
		return zeros[len(zeros)-1]
	}
	return zeros[level]
}

var (
	zeroHashOnce sync.Once
	zeroHashList []string
	zeroHashErr  error
)

func zeroHashes() []string {
	zeroHashOnce.Do(func() {
		zeroHashList = make([]string, merkletree.TreeDepth+1)
		zeroHashList[0], zeroHashErr = railcrypto.BigIntToHex(railcrypto.MerkleZeroValue, 32, false)
		if zeroHashErr != nil {
			return
		}
		for level := 1; level <= merkletree.TreeDepth; level++ {
			zeroHashList[level], zeroHashErr = hashHexPair(zeroHashList[level-1], zeroHashList[level-1])
			if zeroHashErr != nil {
				return
			}
		}
	})
	if zeroHashErr != nil {
		panic(zeroHashErr)
	}
	return zeroHashList
}

func validateLeaf(leaf Leaf) error {
	if leaf.Index >= TreeMaxItems {
		return fmt.Errorf("utxo merkle tree index exceeds tree size")
	}
	if leaf.Hash == "" {
		return fmt.Errorf("utxo merkle leaf hash is required")
	}
	if _, err := railcrypto.HexToBigInt(leaf.Hash); err != nil {
		return fmt.Errorf("utxo merkle leaf hash: %w", err)
	}
	return nil
}

func sortedLeaves(leaves map[uint64]map[uint64]Leaf) []Leaf {
	out := []Leaf{}
	for _, treeLeaves := range leaves {
		for _, leaf := range treeLeaves {
			out = append(out, leaf)
		}
	}
	sort.Slice(out, func(i int, j int) bool {
		if out[i].Tree != out[j].Tree {
			return out[i].Tree < out[j].Tree
		}
		return out[i].Index < out[j].Index
	})
	return out
}
