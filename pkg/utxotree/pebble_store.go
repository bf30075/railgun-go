package utxotree

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"

	"github.com/cockroachdb/pebble"
)

const (
	pebbleLeafPrefix         = "leaf:"
	pebbleV2CommitmentPrefix = "commitment:v2:"
	pebbleV3CommitmentPrefix = "commitment:v3:"
	pebbleNullifierPrefix    = "nullifier:"
	pebbleUnshieldPrefix     = "unshield:"
)

type PebbleStore struct {
	Path string
	mu   sync.Mutex
}

type pebbleNoopLogger struct{}

func (pebbleNoopLogger) Infof(string, ...interface{}) {}

func (pebbleNoopLogger) Fatalf(format string, args ...interface{}) {
	panic(fmt.Sprintf(format, args...))
}

func NewPebbleStore(path string) *PebbleStore {
	return &PebbleStore{Path: path}
}

func (store *PebbleStore) UpsertLeaf(ctx context.Context, leaf Leaf) error {
	return store.UpsertLeaves(ctx, []Leaf{leaf})
}

func (store *PebbleStore) UpsertLeaves(ctx context.Context, leaves []Leaf) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for i, leaf := range leaves {
		if err := validateLeaf(leaf); err != nil {
			return fmt.Errorf("leaves[%d]: %w", i, err)
		}
	}
	if len(leaves) == 0 {
		return nil
	}
	return store.withDB(func(db *pebble.DB) error {
		batch := db.NewBatch()
		defer func() { _ = batch.Close() }()
		for _, leaf := range leaves {
			if err := ctx.Err(); err != nil {
				return err
			}
			data, err := json.Marshal(leaf)
			if err != nil {
				return err
			}
			if err := batch.Set(pebbleLeafKey(leaf.Tree, leaf.Index), data, nil); err != nil {
				return err
			}
		}
		return batch.Commit(pebble.Sync)
	})
}

func (store *PebbleStore) UpsertV2CommitmentEvents(ctx context.Context, events []railevents.CommitmentEvent) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if store == nil {
		return 0, fmt.Errorf("utxo merkle tree store is required")
	}
	count := 0
	for _, event := range events {
		count += len(event.Commitments)
	}
	if count == 0 {
		return 0, nil
	}
	returned := 0
	err := store.withDB(func(db *pebble.DB) error {
		batch := db.NewBatch()
		defer func() { _ = batch.Close() }()
		for _, event := range events {
			for _, commitment := range event.Commitments {
				if err := ctx.Err(); err != nil {
					return err
				}
				leaf, err := LeafFromV2Commitment(commitment)
				if err != nil {
					return err
				}
				leafData, err := json.Marshal(leaf)
				if err != nil {
					return err
				}
				commitmentData, err := json.Marshal(commitment)
				if err != nil {
					return err
				}
				if err := batch.Set(pebbleLeafKey(leaf.Tree, leaf.Index), leafData, nil); err != nil {
					return err
				}
				if err := batch.Set(pebbleV2CommitmentKey(leaf.Tree, leaf.Index), commitmentData, nil); err != nil {
					return err
				}
				returned++
			}
		}
		return batch.Commit(pebble.Sync)
	})
	if err != nil {
		return returned, err
	}
	return returned, nil
}

func (store *PebbleStore) UpsertV3CommitmentEvents(ctx context.Context, events []railevents.V3CommitmentEvent) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if store == nil {
		return 0, fmt.Errorf("utxo merkle tree store is required")
	}
	count := 0
	for _, event := range events {
		count += len(event.Commitments)
	}
	if count == 0 {
		return 0, nil
	}
	returned := 0
	err := store.withDB(func(db *pebble.DB) error {
		batch := db.NewBatch()
		defer func() { _ = batch.Close() }()
		for _, event := range events {
			for _, commitment := range event.Commitments {
				if err := ctx.Err(); err != nil {
					return err
				}
				leaf, err := LeafFromV3Commitment(commitment)
				if err != nil {
					return err
				}
				leafData, err := json.Marshal(leaf)
				if err != nil {
					return err
				}
				commitmentData, err := json.Marshal(commitment)
				if err != nil {
					return err
				}
				if err := batch.Set(pebbleLeafKey(leaf.Tree, leaf.Index), leafData, nil); err != nil {
					return err
				}
				if err := batch.Set(pebbleV3CommitmentKey(leaf.Tree, leaf.Index), commitmentData, nil); err != nil {
					return err
				}
				returned++
			}
		}
		return batch.Commit(pebble.Sync)
	})
	if err != nil {
		return returned, err
	}
	return returned, nil
}

func (store *PebbleStore) UpsertNullifiers(ctx context.Context, nullifiers []railevents.Nullifier) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if store == nil {
		return 0, fmt.Errorf("utxo merkle tree store is required")
	}
	if len(nullifiers) == 0 {
		return 0, nil
	}
	returned := 0
	err := store.withDB(func(db *pebble.DB) error {
		batch := db.NewBatch()
		defer func() { _ = batch.Close() }()
		for _, nullifier := range nullifiers {
			if err := ctx.Err(); err != nil {
				return err
			}
			key, err := pebbleNullifierKey(nullifier.TreeNumber, nullifier.Nullifier)
			if err != nil {
				return err
			}
			data, err := json.Marshal(nullifier)
			if err != nil {
				return err
			}
			if err := batch.Set(key, data, nil); err != nil {
				return err
			}
			returned++
		}
		return batch.Commit(pebble.Sync)
	})
	if err != nil {
		return returned, err
	}
	return returned, nil
}

func (store *PebbleStore) UpsertUnshieldEvents(ctx context.Context, unshields []railevents.UnshieldStoredEvent, replaceExisting bool) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if store == nil {
		return 0, fmt.Errorf("utxo merkle tree store is required")
	}
	if len(unshields) == 0 {
		return 0, nil
	}
	returned := 0
	err := store.withDB(func(db *pebble.DB) error {
		batch := db.NewBatch()
		defer func() { _ = batch.Close() }()
		for _, unshield := range unshields {
			if err := ctx.Err(); err != nil {
				return err
			}
			key, err := pebbleUnshieldKey(unshield)
			if err != nil {
				return err
			}
			if !replaceExisting {
				exists, err := pebbleHasKey(db, key)
				if err != nil {
					return err
				}
				if exists {
					continue
				}
			}
			data, err := json.Marshal(unshield)
			if err != nil {
				return err
			}
			if err := batch.Set(key, data, nil); err != nil {
				return err
			}
			returned++
		}
		if returned == 0 {
			return nil
		}
		return batch.Commit(pebble.Sync)
	})
	if err != nil {
		return returned, err
	}
	return returned, nil
}

func (store *PebbleStore) GetLeaf(ctx context.Context, tree uint64, index uint64) (Leaf, bool, error) {
	if err := ctx.Err(); err != nil {
		return Leaf{}, false, err
	}
	var leaf Leaf
	var ok bool
	err := store.withDB(func(db *pebble.DB) error {
		data, closer, err := db.Get(pebbleLeafKey(tree, index))
		if errors.Is(err, pebble.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		defer func() { _ = closer.Close() }()
		decoded, err := decodePebbleLeaf(data)
		if err != nil {
			return err
		}
		leaf = decoded
		ok = true
		return nil
	})
	return leaf, ok, err
}

func (store *PebbleStore) GetV2Commitment(ctx context.Context, tree uint64, index uint64) (railevents.Commitment, bool, error) {
	if err := ctx.Err(); err != nil {
		return railevents.Commitment{}, false, err
	}
	var commitment railevents.Commitment
	var ok bool
	err := store.withDB(func(db *pebble.DB) error {
		data, closer, err := db.Get(pebbleV2CommitmentKey(tree, index))
		if errors.Is(err, pebble.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		defer func() { _ = closer.Close() }()
		if err := json.Unmarshal(data, &commitment); err != nil {
			return err
		}
		ok = true
		return nil
	})
	return commitment, ok, err
}

func (store *PebbleStore) GetV3Commitment(ctx context.Context, tree uint64, index uint64) (railevents.V3Commitment, bool, error) {
	if err := ctx.Err(); err != nil {
		return railevents.V3Commitment{}, false, err
	}
	var commitment railevents.V3Commitment
	var ok bool
	err := store.withDB(func(db *pebble.DB) error {
		data, closer, err := db.Get(pebbleV3CommitmentKey(tree, index))
		if errors.Is(err, pebble.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		defer func() { _ = closer.Close() }()
		if err := json.Unmarshal(data, &commitment); err != nil {
			return err
		}
		ok = true
		return nil
	})
	return commitment, ok, err
}

func (store *PebbleStore) GetNullifierTxid(ctx context.Context, nullifier string, tree *uint64) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	formattedNullifier, err := normalizePebble32Hex(nullifier)
	if err != nil {
		return "", false, err
	}
	var txid string
	var ok bool
	if tree != nil {
		err := store.withDB(func(db *pebble.DB) error {
			key, err := pebbleNullifierKeyFromUint(*tree, formattedNullifier)
			if err != nil {
				return err
			}
			data, closer, err := db.Get(key)
			if errors.Is(err, pebble.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			defer func() { _ = closer.Close() }()
			var event railevents.Nullifier
			if err := json.Unmarshal(data, &event); err != nil {
				return err
			}
			txid = event.Txid
			ok = true
			return nil
		})
		return txid, ok, err
	}
	latestTree := -1
	err = store.withDB(func(db *pebble.DB) error {
		return pebbleIterPrefix(ctx, db, []byte(pebbleNullifierPrefix), func(_, value []byte) error {
			var event railevents.Nullifier
			if err := json.Unmarshal(value, &event); err != nil {
				return err
			}
			eventNullifier, err := normalizePebble32Hex(event.Nullifier)
			if err != nil || eventNullifier != formattedNullifier {
				return err
			}
			if event.TreeNumber >= latestTree {
				latestTree = event.TreeNumber
				txid = event.Txid
				ok = true
			}
			return nil
		})
	})
	return txid, ok, err
}

func (store *PebbleStore) ListLeaves(ctx context.Context) ([]Leaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var leaves []Leaf
	err := store.withDB(func(db *pebble.DB) error {
		loaded, err := pebbleLoadAll(ctx, db)
		if err != nil {
			return err
		}
		leaves = sortedLeaves(loaded)
		return nil
	})
	return leaves, err
}

func (store *PebbleStore) ListNullifiers(ctx context.Context) ([]railevents.Nullifier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var nullifiers []railevents.Nullifier
	err := store.withDB(func(db *pebble.DB) error {
		return pebbleIterPrefix(ctx, db, []byte(pebbleNullifierPrefix), func(_, value []byte) error {
			var nullifier railevents.Nullifier
			if err := json.Unmarshal(value, &nullifier); err != nil {
				return err
			}
			nullifiers = append(nullifiers, nullifier)
			return nil
		})
	})
	return nullifiers, err
}

func (store *PebbleStore) GetUnshieldEventsByTxid(ctx context.Context, txid string) ([]railevents.UnshieldStoredEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix, err := pebbleUnshieldTxidPrefix(txid)
	if err != nil {
		return nil, err
	}
	var unshields []railevents.UnshieldStoredEvent
	err = store.withDB(func(db *pebble.DB) error {
		return pebbleIterPrefix(ctx, db, prefix, func(_, value []byte) error {
			var unshield railevents.UnshieldStoredEvent
			if err := json.Unmarshal(value, &unshield); err != nil {
				return err
			}
			unshields = append(unshields, unshield)
			return nil
		})
	})
	return unshields, err
}

func (store *PebbleStore) ListUnshieldEvents(ctx context.Context) ([]railevents.UnshieldStoredEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var unshields []railevents.UnshieldStoredEvent
	err := store.withDB(func(db *pebble.DB) error {
		return pebbleIterPrefix(ctx, db, []byte(pebbleUnshieldPrefix), func(_, value []byte) error {
			var unshield railevents.UnshieldStoredEvent
			if err := json.Unmarshal(value, &unshield); err != nil {
				return err
			}
			unshields = append(unshields, unshield)
			return nil
		})
	})
	return unshields, err
}

func (store *PebbleStore) ListV2Commitments(ctx context.Context) ([]railevents.Commitment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var commitments []railevents.Commitment
	err := store.withDB(func(db *pebble.DB) error {
		return pebbleIterPrefix(ctx, db, []byte(pebbleV2CommitmentPrefix), func(_, value []byte) error {
			var commitment railevents.Commitment
			if err := json.Unmarshal(value, &commitment); err != nil {
				return err
			}
			commitments = append(commitments, commitment)
			return nil
		})
	})
	return commitments, err
}

func (store *PebbleStore) ListV3Commitments(ctx context.Context) ([]railevents.V3Commitment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var commitments []railevents.V3Commitment
	err := store.withDB(func(db *pebble.DB) error {
		return pebbleIterPrefix(ctx, db, []byte(pebbleV3CommitmentPrefix), func(_, value []byte) error {
			var commitment railevents.V3Commitment
			if err := json.Unmarshal(value, &commitment); err != nil {
				return err
			}
			commitments = append(commitments, commitment)
			return nil
		})
	})
	return commitments, err
}

func (store *PebbleStore) Root(ctx context.Context, tree uint64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var root string
	err := store.withDB(func(db *pebble.DB) error {
		leaves, err := pebbleLoadTree(ctx, db, tree)
		if err != nil {
			return err
		}
		levels, err := buildTreeLevels(leaves)
		if err != nil {
			return err
		}
		root = nodeAtLevel(levels, merkletree.TreeDepth, 0)
		return nil
	})
	return root, err
}

func (store *PebbleStore) Proof(ctx context.Context, tree uint64, index uint64) (merkletree.MerkleProof, error) {
	if err := ctx.Err(); err != nil {
		return merkletree.MerkleProof{}, err
	}
	var proof merkletree.MerkleProof
	err := store.withDB(func(db *pebble.DB) error {
		leaves, err := pebbleLoadTree(ctx, db, tree)
		if err != nil {
			return err
		}
		proof, err = proofFromLeaves(leaves, index)
		return err
	})
	return proof, err
}

func (store *PebbleStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.withDB(func(db *pebble.DB) error {
		batch := db.NewBatch()
		defer func() { _ = batch.Close() }()
		deleted := 0
		if err := pebbleDeleteLeavesFromBlock(ctx, db, batch, fromBlock, &deleted); err != nil {
			return err
		}
		if err := pebbleDeleteV2CommitmentsFromBlock(ctx, db, batch, fromBlock, &deleted); err != nil {
			return err
		}
		if err := pebbleDeleteV3CommitmentsFromBlock(ctx, db, batch, fromBlock, &deleted); err != nil {
			return err
		}
		if err := pebbleDeleteNullifiersFromBlock(ctx, db, batch, fromBlock, &deleted); err != nil {
			return err
		}
		if err := pebbleDeleteUnshieldsFromBlock(ctx, db, batch, fromBlock, &deleted); err != nil {
			return err
		}
		if deleted == 0 {
			return nil
		}
		return batch.Commit(pebble.Sync)
	})
}

func (store *PebbleStore) withDB(update func(*pebble.DB) error) error {
	if store == nil {
		return fmt.Errorf("utxo merkle tree store is required")
	}
	if store.Path == "" {
		return fmt.Errorf("utxo merkle tree pebble path is required")
	}
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o755); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	db, err := pebble.Open(store.Path, &pebble.Options{Logger: pebbleNoopLogger{}})
	if err != nil {
		return err
	}
	updateErr := update(db)
	closeErr := db.Close()
	if updateErr != nil {
		return updateErr
	}
	return closeErr
}

func pebbleLoadAll(ctx context.Context, db *pebble.DB) (map[uint64]map[uint64]Leaf, error) {
	leaves := map[uint64]map[uint64]Leaf{}
	err := pebbleIterPrefix(ctx, db, []byte(pebbleLeafPrefix), func(_, value []byte) error {
		leaf, err := decodePebbleLeaf(value)
		if err != nil {
			return err
		}
		if leaves[leaf.Tree] == nil {
			leaves[leaf.Tree] = map[uint64]Leaf{}
		}
		leaves[leaf.Tree][leaf.Index] = leaf
		return nil
	})
	return leaves, err
}

func pebbleLoadTree(ctx context.Context, db *pebble.DB, tree uint64) (map[uint64]Leaf, error) {
	leaves := map[uint64]Leaf{}
	err := pebbleIterPrefix(ctx, db, pebbleTreePrefix(tree), func(_, value []byte) error {
		leaf, err := decodePebbleLeaf(value)
		if err != nil {
			return err
		}
		leaves[leaf.Index] = leaf
		return nil
	})
	return leaves, err
}

func pebbleDeleteLeavesFromBlock(ctx context.Context, db *pebble.DB, batch *pebble.Batch, fromBlock uint64, deleted *int) error {
	return pebbleIterPrefix(ctx, db, []byte(pebbleLeafPrefix), func(key, value []byte) error {
		leaf, err := decodePebbleLeaf(value)
		if err != nil {
			return err
		}
		if leaf.BlockNumber < fromBlock {
			return nil
		}
		if err := batch.Delete(key, nil); err != nil {
			return err
		}
		(*deleted)++
		return nil
	})
}

func pebbleDeleteV2CommitmentsFromBlock(ctx context.Context, db *pebble.DB, batch *pebble.Batch, fromBlock uint64, deleted *int) error {
	return pebbleIterPrefix(ctx, db, []byte(pebbleV2CommitmentPrefix), func(key, value []byte) error {
		var commitment railevents.Commitment
		if err := json.Unmarshal(value, &commitment); err != nil {
			return err
		}
		if commitment.BlockNumber < fromBlock {
			return nil
		}
		if err := batch.Delete(key, nil); err != nil {
			return err
		}
		(*deleted)++
		return nil
	})
}

func pebbleDeleteV3CommitmentsFromBlock(ctx context.Context, db *pebble.DB, batch *pebble.Batch, fromBlock uint64, deleted *int) error {
	return pebbleIterPrefix(ctx, db, []byte(pebbleV3CommitmentPrefix), func(key, value []byte) error {
		var commitment railevents.V3Commitment
		if err := json.Unmarshal(value, &commitment); err != nil {
			return err
		}
		if commitment.BlockNumber < fromBlock {
			return nil
		}
		if err := batch.Delete(key, nil); err != nil {
			return err
		}
		(*deleted)++
		return nil
	})
}

func pebbleDeleteNullifiersFromBlock(ctx context.Context, db *pebble.DB, batch *pebble.Batch, fromBlock uint64, deleted *int) error {
	return pebbleIterPrefix(ctx, db, []byte(pebbleNullifierPrefix), func(key, value []byte) error {
		var nullifier railevents.Nullifier
		if err := json.Unmarshal(value, &nullifier); err != nil {
			return err
		}
		if nullifier.BlockNumber < fromBlock {
			return nil
		}
		if err := batch.Delete(key, nil); err != nil {
			return err
		}
		(*deleted)++
		return nil
	})
}

func pebbleDeleteUnshieldsFromBlock(ctx context.Context, db *pebble.DB, batch *pebble.Batch, fromBlock uint64, deleted *int) error {
	return pebbleIterPrefix(ctx, db, []byte(pebbleUnshieldPrefix), func(key, value []byte) error {
		var unshield railevents.UnshieldStoredEvent
		if err := json.Unmarshal(value, &unshield); err != nil {
			return err
		}
		if unshield.BlockNumber < fromBlock {
			return nil
		}
		if err := batch.Delete(key, nil); err != nil {
			return err
		}
		(*deleted)++
		return nil
	})
}

func pebbleIterPrefix(ctx context.Context, db *pebble.DB, prefix []byte, visit func(key []byte, value []byte) error) error {
	it, err := db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: pebblePrefixUpperBound(prefix),
	})
	if err != nil {
		return err
	}
	defer func() { _ = it.Close() }()
	for ok := it.First(); ok; ok = it.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := append([]byte(nil), it.Key()...)
		value := append([]byte(nil), it.Value()...)
		if err := visit(key, value); err != nil {
			return err
		}
	}
	return it.Error()
}

func pebbleHasKey(db *pebble.DB, key []byte) (bool, error) {
	_, closer, err := db.Get(key)
	if errors.Is(err, pebble.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = closer.Close() }()
	return true, nil
}

func decodePebbleLeaf(data []byte) (Leaf, error) {
	var leaf Leaf
	if err := json.Unmarshal(data, &leaf); err != nil {
		return Leaf{}, err
	}
	if err := validateLeaf(leaf); err != nil {
		return Leaf{}, err
	}
	return leaf, nil
}

func pebbleLeafKey(tree uint64, index uint64) []byte {
	return []byte(fmt.Sprintf("%s%020d:%020d", pebbleLeafPrefix, tree, index))
}

func pebbleTreePrefix(tree uint64) []byte {
	return []byte(fmt.Sprintf("%s%020d:", pebbleLeafPrefix, tree))
}

func pebbleV2CommitmentKey(tree uint64, index uint64) []byte {
	return []byte(fmt.Sprintf("%s%020d:%020d", pebbleV2CommitmentPrefix, tree, index))
}

func pebbleV3CommitmentKey(tree uint64, index uint64) []byte {
	return []byte(fmt.Sprintf("%s%020d:%020d", pebbleV3CommitmentPrefix, tree, index))
}

func pebbleNullifierKey(tree int, nullifier string) ([]byte, error) {
	if tree < 0 {
		return nil, fmt.Errorf("nullifier tree must be non-negative")
	}
	formattedNullifier, err := normalizePebble32Hex(nullifier)
	if err != nil {
		return nil, err
	}
	return pebbleNullifierKeyFromUint(uint64(tree), formattedNullifier)
}

func pebbleNullifierKeyFromUint(tree uint64, formattedNullifier string) ([]byte, error) {
	formattedNullifier, err := normalizePebble32Hex(formattedNullifier)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%s%020d:%s", pebbleNullifierPrefix, tree, formattedNullifier)), nil
}

func pebbleUnshieldKey(unshield railevents.UnshieldStoredEvent) ([]byte, error) {
	prefix, err := pebbleUnshieldTxidPrefix(unshield.Txid)
	if err != nil {
		return nil, err
	}
	discriminator := "none"
	if unshield.EventLogIndex != nil {
		discriminator = fmt.Sprintf("%020d", *unshield.EventLogIndex)
	} else if unshield.RailgunTxid != "" {
		discriminator, err = normalizePebble32Hex(unshield.RailgunTxid)
		if err != nil {
			return nil, err
		}
	}
	return []byte(fmt.Sprintf("%s%s", string(prefix), discriminator)), nil
}

func pebbleUnshieldTxidPrefix(txid string) ([]byte, error) {
	formattedTxid, err := normalizePebble32Hex(txid)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%s%s:", pebbleUnshieldPrefix, formattedTxid)), nil
}

func normalizePebble32Hex(value string) (string, error) {
	return railcrypto.FormatHexToByteLength(value, 32, false)
}

func pebblePrefixUpperBound(prefix []byte) []byte {
	upper := append([]byte(nil), prefix...)
	for i := len(upper) - 1; i >= 0; i-- {
		if upper[i] != 0xff {
			upper[i]++
			return upper[:i+1]
		}
	}
	return nil
}
