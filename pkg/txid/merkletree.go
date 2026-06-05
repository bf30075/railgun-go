package txid

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
	"github.com/bf30075/railgun-go/pkg/merkletree"
)

type MerkleLeaf struct {
	Tree        uint64 `json:"tree"`
	Index       uint64 `json:"index"`
	Hash        string `json:"hash"`
	RailgunTxid string `json:"railgunTxid,omitempty"`
	BlockNumber uint64 `json:"blockNumber,omitempty"`
}

type MerkleTreeStore interface {
	UpsertLeaf(ctx context.Context, leaf MerkleLeaf) error
	GetLeaf(ctx context.Context, tree uint64, index uint64) (MerkleLeaf, bool, error)
	ListLeaves(ctx context.Context) ([]MerkleLeaf, error)
	Root(ctx context.Context, tree uint64) (string, error)
	Proof(ctx context.Context, tree uint64, index uint64) (merkletree.MerkleProof, error)
}

type ReorgMerkleTreeStore interface {
	MerkleTreeStore
	RollbackToBlock(ctx context.Context, fromBlock uint64) error
}

func AppendTransactionLeaf(ctx context.Context, store MerkleTreeStore, transaction Transaction) (MerkleLeaf, error) {
	if store == nil {
		return MerkleLeaf{}, fmt.Errorf("txid merkle tree store is required")
	}
	tree, index, err := NextMerkleTreePosition(ctx, store)
	if err != nil {
		return MerkleLeaf{}, err
	}
	leaf, err := MerkleLeafFromTransaction(transaction, tree, index)
	if err != nil {
		return MerkleLeaf{}, err
	}
	if err := store.UpsertLeaf(ctx, leaf); err != nil {
		return MerkleLeaf{}, err
	}
	return leaf, nil
}

func NextMerkleTreePosition(ctx context.Context, store MerkleTreeStore) (uint64, uint64, error) {
	if store == nil {
		return 0, 0, fmt.Errorf("txid merkle tree store is required")
	}
	leaves, err := store.ListLeaves(ctx)
	if err != nil {
		return 0, 0, err
	}
	if len(leaves) == 0 {
		return 0, 0, nil
	}
	var maxPosition *big.Int
	for _, leaf := range leaves {
		position := GetGlobalTreePosition(leaf.Tree, leaf.Index)
		if maxPosition == nil || position.Cmp(maxPosition) > 0 {
			maxPosition = position
		}
	}
	next := new(big.Int).Add(maxPosition, big.NewInt(1))
	divisor := big.NewInt(TreeMaxItems)
	tree := new(big.Int).Div(next, divisor)
	index := new(big.Int).Mod(next, divisor)
	if !tree.IsUint64() || !index.IsUint64() {
		return 0, 0, fmt.Errorf("txid merkle tree position exceeds uint64")
	}
	return tree.Uint64(), index.Uint64(), nil
}

type MemoryMerkleTreeStore struct {
	mu     sync.RWMutex
	leaves map[uint64]map[uint64]MerkleLeaf
}

func NewMemoryMerkleTreeStore() *MemoryMerkleTreeStore {
	return &MemoryMerkleTreeStore{leaves: map[uint64]map[uint64]MerkleLeaf{}}
}

func (store *MemoryMerkleTreeStore) UpsertLeaf(ctx context.Context, leaf MerkleLeaf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("txid merkle tree store is required")
	}
	if err := validateMerkleLeaf(leaf); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.leaves == nil {
		store.leaves = map[uint64]map[uint64]MerkleLeaf{}
	}
	if store.leaves[leaf.Tree] == nil {
		store.leaves[leaf.Tree] = map[uint64]MerkleLeaf{}
	}
	store.leaves[leaf.Tree][leaf.Index] = leaf
	return nil
}

func (store *MemoryMerkleTreeStore) GetLeaf(ctx context.Context, tree uint64, index uint64) (MerkleLeaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return MerkleLeaf{}, false, err
	}
	if store == nil {
		return MerkleLeaf{}, false, fmt.Errorf("txid merkle tree store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	leaf, ok := store.leaves[tree][index]
	return leaf, ok, nil
}

func (store *MemoryMerkleTreeStore) ListLeaves(ctx context.Context) ([]MerkleLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("txid merkle tree store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return sortedMerkleLeaves(store.leaves), nil
}

func (store *MemoryMerkleTreeStore) Root(ctx context.Context, tree uint64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if store == nil {
		return "", fmt.Errorf("txid merkle tree store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	levels, err := buildTreeLevels(store.leaves[tree])
	if err != nil {
		return "", err
	}
	return nodeAtLevel(levels, merkletree.TreeDepth, 0), nil
}

func (store *MemoryMerkleTreeStore) Proof(ctx context.Context, tree uint64, index uint64) (merkletree.MerkleProof, error) {
	if err := ctx.Err(); err != nil {
		return merkletree.MerkleProof{}, err
	}
	if store == nil {
		return merkletree.MerkleProof{}, fmt.Errorf("txid merkle tree store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return proofFromLeaves(store.leaves[tree], index)
}

func (store *MemoryMerkleTreeStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("txid merkle tree store is required")
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

type FileMerkleTreeStore struct {
	Path string
	mu   sync.Mutex
}

func NewFileMerkleTreeStore(path string) *FileMerkleTreeStore {
	return &FileMerkleTreeStore{Path: path}
}

func (store *FileMerkleTreeStore) UpsertLeaf(ctx context.Context, leaf MerkleLeaf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMerkleLeaf(leaf); err != nil {
		return err
	}
	return store.update(func(leaves map[uint64]map[uint64]MerkleLeaf) error {
		if leaves[leaf.Tree] == nil {
			leaves[leaf.Tree] = map[uint64]MerkleLeaf{}
		}
		leaves[leaf.Tree][leaf.Index] = leaf
		return nil
	})
}

func (store *FileMerkleTreeStore) GetLeaf(ctx context.Context, tree uint64, index uint64) (MerkleLeaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return MerkleLeaf{}, false, err
	}
	leaves, err := store.load()
	if err != nil {
		return MerkleLeaf{}, false, err
	}
	leaf, ok := leaves[tree][index]
	return leaf, ok, nil
}

func (store *FileMerkleTreeStore) ListLeaves(ctx context.Context) ([]MerkleLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	leaves, err := store.load()
	if err != nil {
		return nil, err
	}
	return sortedMerkleLeaves(leaves), nil
}

func (store *FileMerkleTreeStore) Root(ctx context.Context, tree uint64) (string, error) {
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

func (store *FileMerkleTreeStore) Proof(ctx context.Context, tree uint64, index uint64) (merkletree.MerkleProof, error) {
	if err := ctx.Err(); err != nil {
		return merkletree.MerkleProof{}, err
	}
	leaves, err := store.load()
	if err != nil {
		return merkletree.MerkleProof{}, err
	}
	return proofFromLeaves(leaves[tree], index)
}

func (store *FileMerkleTreeStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.update(func(leaves map[uint64]map[uint64]MerkleLeaf) error {
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

func (store *FileMerkleTreeStore) update(update func(map[uint64]map[uint64]MerkleLeaf) error) error {
	if store == nil {
		return fmt.Errorf("txid merkle tree store is required")
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

func (store *FileMerkleTreeStore) load() (map[uint64]map[uint64]MerkleLeaf, error) {
	if store == nil {
		return nil, fmt.Errorf("txid merkle tree store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked()
}

func (store *FileMerkleTreeStore) loadLocked() (map[uint64]map[uint64]MerkleLeaf, error) {
	if store.Path == "" {
		return nil, fmt.Errorf("txid merkle tree store file path is required")
	}
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[uint64]map[uint64]MerkleLeaf{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return map[uint64]map[uint64]MerkleLeaf{}, nil
	}
	var state merkleTreeFileState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	leaves := map[uint64]map[uint64]MerkleLeaf{}
	for i, leaf := range state.Leaves {
		if err := validateMerkleLeaf(leaf); err != nil {
			return nil, fmt.Errorf("leaves[%d]: %w", i, err)
		}
		if leaves[leaf.Tree] == nil {
			leaves[leaf.Tree] = map[uint64]MerkleLeaf{}
		}
		leaves[leaf.Tree][leaf.Index] = leaf
	}
	return leaves, nil
}

func (store *FileMerkleTreeStore) saveLocked(leaves map[uint64]map[uint64]MerkleLeaf) error {
	if store.Path == "" {
		return fmt.Errorf("txid merkle tree store file path is required")
	}
	data, err := json.MarshalIndent(merkleTreeFileState{Leaves: sortedMerkleLeaves(leaves)}, "", "  ")
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

type merkleTreeFileState struct {
	Leaves []MerkleLeaf `json:"leaves"`
}

func MerkleLeafFromTransaction(transaction Transaction, tree uint64, index uint64) (MerkleLeaf, error) {
	hash, err := TransactionLeafHash(transaction)
	if err != nil {
		return MerkleLeaf{}, err
	}
	return MerkleLeaf{
		Tree:        tree,
		Index:       index,
		Hash:        hash,
		RailgunTxid: transaction.RailgunTxid,
		BlockNumber: transaction.BlockNumber,
	}, nil
}

func TransactionLeafHash(transaction Transaction) (string, error) {
	if transaction.RailgunTxid == "" {
		return "", fmt.Errorf("railgun txid is required")
	}
	if transaction.UTXOTreeIn < 0 || transaction.UTXOTreeOut < 0 || transaction.UTXOBatchStartPositionOut < 0 {
		return "", fmt.Errorf("transaction tree fields must be non-negative")
	}
	railgunTxid, err := railcrypto.HexToBigInt(transaction.RailgunTxid)
	if err != nil {
		return "", err
	}
	globalTreePosition := GetGlobalTreePosition(uint64(transaction.UTXOTreeOut), uint64(transaction.UTXOBatchStartPositionOut))
	return RailgunTxidLeafHash(railgunTxid, uint64(transaction.UTXOTreeIn), globalTreePosition)
}

func proofFromLeaves(leaves map[uint64]MerkleLeaf, index uint64) (merkletree.MerkleProof, error) {
	if index >= TreeMaxItems {
		return merkletree.MerkleProof{}, fmt.Errorf("txid merkle tree index exceeds tree size")
	}
	leaf, ok := leaves[index]
	if !ok {
		return merkletree.MerkleProof{}, fmt.Errorf("missing txid merkle leaf at index %d", index)
	}
	levels, err := buildTreeLevels(leaves)
	if err != nil {
		return merkletree.MerkleProof{}, err
	}
	elements := make([]string, merkletree.TreeDepth)
	for level := 0; level < merkletree.TreeDepth; level++ {
		elements[level] = nodeAtLevel(levels, level, index^1)
		index >>= 1
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

func buildTreeLevels(leaves map[uint64]MerkleLeaf) ([]map[uint64]string, error) {
	levels := make([]map[uint64]string, merkletree.TreeDepth+1)
	levels[0] = map[uint64]string{}
	for index, leaf := range leaves {
		if err := validateMerkleLeaf(leaf); err != nil {
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
			if hash != zeroHash(level+1) {
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
	return zeroHash(level)
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

func zeroHash(level int) string {
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

func validateMerkleLeaf(leaf MerkleLeaf) error {
	if leaf.Index >= TreeMaxItems {
		return fmt.Errorf("txid merkle tree index exceeds tree size")
	}
	if leaf.Hash == "" {
		return fmt.Errorf("txid merkle leaf hash is required")
	}
	if _, err := railcrypto.HexToBigInt(leaf.Hash); err != nil {
		return fmt.Errorf("txid merkle leaf hash: %w", err)
	}
	return nil
}

func sortedMerkleLeaves(leaves map[uint64]map[uint64]MerkleLeaf) []MerkleLeaf {
	out := []MerkleLeaf{}
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
