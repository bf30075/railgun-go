package txid

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/merkletree"
)

func TestMemoryMerkleTreeStoreRootProofAndRollback(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryMerkleTreeStore()
	emptyRoot, err := store.Root(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if emptyRoot != zeroHash(merkletree.TreeDepth) {
		t.Fatalf("expected empty root %s, got %s", zeroHash(merkletree.TreeDepth), emptyRoot)
	}

	first := testMerkleLeaf(t, 0, 0, 10)
	second := testMerkleLeaf(t, 0, 3, 20)
	if err := store.UpsertLeaf(ctx, first); err != nil {
		t.Fatal(err)
	}
	first.Hash = "mutated"
	if err := store.UpsertLeaf(ctx, second); err != nil {
		t.Fatal(err)
	}

	got, ok, err := store.GetLeaf(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Hash == "mutated" {
		t.Fatalf("expected stored leaf clone, got %+v", got)
	}

	proof, err := store.Proof(ctx, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = merkletree.VerifyProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected generated proof to verify")
	}
	root, err := store.Root(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if root != proof.Root {
		t.Fatalf("expected root %s to match proof root %s", root, proof.Root)
	}

	if err := store.RollbackToBlock(ctx, 20); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.GetLeaf(ctx, 0, 3); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove second leaf")
	}
	if _, ok, err := store.GetLeaf(ctx, 0, 0); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected older leaf to remain")
	}
}

func TestFileMerkleTreeStorePersistsProofs(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "txid-tree.json")
	store := NewFileMerkleTreeStore(path)
	leaf := testMerkleLeaf(t, 1, 2, 30)
	if err := store.UpsertLeaf(ctx, leaf); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), leaf.RailgunTxid) {
		t.Fatalf("expected persisted railgun txid, got\n%s", raw)
	}
	reopened := NewFileMerkleTreeStore(path)
	proof, err := reopened.Proof(ctx, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := merkletree.VerifyProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected persisted proof to verify")
	}
	if err := reopened.RollbackToBlock(ctx, 30); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := NewFileMerkleTreeStore(path).GetLeaf(ctx, 1, 2); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to persist leaf removal")
	}
}

func TestMerkleLeafFromTransactionMatchesRailgunLeafHash(t *testing.T) {
	transaction := testMerkleTransaction(t, 10)
	leaf, err := MerkleLeafFromTransaction(transaction, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	railgunTxid, err := railcrypto.HexToBigInt(transaction.RailgunTxid)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := RailgunTxidLeafHash(
		railgunTxid,
		uint64(transaction.UTXOTreeIn),
		GetGlobalTreePosition(uint64(transaction.UTXOTreeOut), uint64(transaction.UTXOBatchStartPositionOut)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Hash != expected || leaf.Tree != 2 || leaf.Index != 5 || leaf.BlockNumber != 10 {
		t.Fatalf("unexpected leaf %+v expected hash %s", leaf, expected)
	}
}

func TestAppendTransactionLeafUsesNextSequentialPosition(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryMerkleTreeStore()
	first, err := AppendTransactionLeaf(ctx, store, testMerkleTransaction(t, 10))
	if err != nil {
		t.Fatal(err)
	}
	if first.Tree != 0 || first.Index != 0 {
		t.Fatalf("expected first leaf at 0:0, got %+v", first)
	}
	if err := store.UpsertLeaf(ctx, testMerkleLeaf(t, 0, TreeMaxItems-1, 11)); err != nil {
		t.Fatal(err)
	}
	nextTree, nextIndex, err := NextMerkleTreePosition(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if nextTree != 1 || nextIndex != 0 {
		t.Fatalf("expected next position 1:0, got %d:%d", nextTree, nextIndex)
	}
}

func TestMerkleTreeStoreRejectsInvalidLeaves(t *testing.T) {
	if err := NewMemoryMerkleTreeStore().UpsertLeaf(context.Background(), MerkleLeaf{Index: TreeMaxItems, Hash: "0x01"}); err == nil {
		t.Fatal("expected out-of-range index to fail")
	}
	if _, err := TransactionLeafHash(Transaction{RailgunTxid: "not-hex"}); err == nil {
		t.Fatal("expected invalid railgun txid to fail")
	}
}

func testMerkleLeaf(t *testing.T, tree uint64, index uint64, blockNumber uint64) MerkleLeaf {
	t.Helper()
	leaf, err := MerkleLeafFromTransaction(testMerkleTransaction(t, blockNumber), tree, index)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func testMerkleTransaction(t *testing.T, blockNumber uint64) Transaction {
	t.Helper()
	railgunTxid, err := railcrypto.BigIntToHex(big.NewInt(123), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	return Transaction{
		Version:                   "V3",
		RailgunTxid:               railgunTxid,
		Txid:                      "0xtx",
		BlockNumber:               blockNumber,
		UTXOTreeIn:                1,
		UTXOTreeOut:               2,
		UTXOBatchStartPositionOut: 3,
	}
}
