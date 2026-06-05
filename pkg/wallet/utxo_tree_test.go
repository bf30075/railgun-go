package wallet

import (
	"context"
	"math/big"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
)

func TestWalletUTXOMerkleProofForTXO(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	utxoTree := railutxotree.NewMemoryStore()
	commitmentHash := mustWalletUTXOHash(t, 31)
	if err := utxoTree.UpsertLeaf(ctx, railutxotree.Leaf{
		Tree:           2,
		Index:          7,
		Hash:           commitmentHash,
		TXID:           "0xevm",
		CommitmentType: railevents.CommitmentTypeTransactV3,
		BlockNumber:    100,
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.UpsertTXO(ctx, StoredTXO{
		Tree:           2,
		Position:       7,
		Nullifier:      "nullifier",
		CommitmentHash: commitmentHash,
		Value:          big.NewInt(1),
	}); err != nil {
		t.Fatal(err)
	}
	wallet, err := NewWalletWithAllStores(
		state,
		railevents.NewMemoryCheckpointStore(),
		testSyncKeys(),
		testBalancePOIManager(),
		nil,
		nil,
		utxoTree,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := wallet.UTXOMerkleProof(ctx, "nullifier")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := merkletree.VerifyProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected wallet utxo proof to verify")
	}
	root, err := wallet.UTXOMerkleRoot(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Root != root {
		t.Fatalf("expected proof root %s to match wallet root %s", proof.Root, root)
	}
}

func TestWalletUTXOMerkleProofRejectsMismatchedLeaf(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	utxoTree := railutxotree.NewMemoryStore()
	if err := utxoTree.UpsertLeaf(ctx, railutxotree.Leaf{Tree: 0, Index: 0, Hash: mustWalletUTXOHash(t, 41)}); err != nil {
		t.Fatal(err)
	}
	if err := state.UpsertTXO(ctx, StoredTXO{
		Tree:           0,
		Position:       0,
		Nullifier:      "nullifier",
		CommitmentHash: mustWalletUTXOHash(t, 42),
		Value:          big.NewInt(1),
	}); err != nil {
		t.Fatal(err)
	}
	wallet, err := NewWalletWithAllStores(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), testBalancePOIManager(), nil, nil, utxoTree, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wallet.UTXOMerkleProof(ctx, "nullifier"); err == nil {
		t.Fatal("expected mismatched utxo proof leaf to fail")
	}
}

func mustWalletUTXOHash(t *testing.T, value int64) string {
	t.Helper()
	hash, err := railcrypto.BigIntToHex(big.NewInt(value), 32, false)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
