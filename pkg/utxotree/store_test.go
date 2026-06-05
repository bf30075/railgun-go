package utxotree

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"
)

func TestMemoryStoreIndexesCommitmentsRootProofAndRollback(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	emptyRoot, err := store.Root(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if emptyRoot != ZeroHash(merkletree.TreeDepth) {
		t.Fatalf("expected empty root %s, got %s", ZeroHash(merkletree.TreeDepth), emptyRoot)
	}
	commitment0 := mustHash(t, 11)
	commitment3 := mustHash(t, 12)

	indexed, err := IndexV2CommitmentEvents(ctx, store, []railevents.CommitmentEvent{{
		Commitments: []railevents.Commitment{
			{
				CommitmentType: railevents.CommitmentTypeTransactV2,
				Hash:           commitment0,
				Txid:           "0xv2",
				BlockNumber:    10,
				UTXOTree:       0,
				UTXOIndex:      0,
			},
			{
				CommitmentType: railevents.CommitmentTypeShield,
				Hash:           commitment3,
				Txid:           "0xv2",
				BlockNumber:    20,
				UTXOTree:       0,
				UTXOIndex:      3,
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if indexed != 2 {
		t.Fatalf("expected two indexed leaves, got %d", indexed)
	}

	got, ok, err := store.GetLeaf(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Hash != railcrypto.Strip0x(commitment0) || got.CommitmentType != railevents.CommitmentTypeTransactV2 {
		t.Fatalf("unexpected indexed leaf %+v", got)
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

func TestFileStorePersistsProofsAndIndexesV3Commitments(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "utxo-tree.json")
	store := NewFileStore(path)
	hash := mustHash(t, 21)
	indexed, err := IndexV3CommitmentEvents(ctx, store, []railevents.V3CommitmentEvent{{
		Commitments: []railevents.V3Commitment{{
			CommitmentType: railevents.CommitmentTypeTransactV3,
			Hash:           hash,
			Txid:           "0xv3",
			BlockNumber:    30,
			UTXOTree:       1,
			UTXOIndex:      2,
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if indexed != 1 {
		t.Fatalf("expected one indexed leaf, got %d", indexed)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"txid": "0xv3"`) {
		t.Fatalf("expected persisted txid, got\n%s", raw)
	}

	reopened := NewFileStore(path)
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
	if _, ok, err := NewFileStore(path).GetLeaf(ctx, 1, 2); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to persist leaf removal")
	}
}

func TestPebbleStorePersistsProofsCommitmentsAndRollsBack(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "utxo-tree.pebble")
	store := NewPebbleStore(path)
	hash2 := mustHash(t, 31)
	hash7 := mustHash(t, 32)
	v2Indexed, err := IndexV2CommitmentEvents(ctx, store, []railevents.CommitmentEvent{{
		Commitments: []railevents.Commitment{
			{
				CommitmentType: railevents.CommitmentTypeTransactV2,
				Hash:           hash2,
				Txid:           "0xv2",
				BlockNumber:    41,
				UTXOTree:       2,
				UTXOIndex:      2,
			},
			{
				CommitmentType: railevents.CommitmentTypeShield,
				Hash:           hash7,
				Txid:           "0xv2",
				BlockNumber:    42,
				UTXOTree:       2,
				UTXOIndex:      7,
				EncryptedBundle: []string{
					mustHash(t, 321),
					mustHash(t, 322),
					mustHash(t, 323),
				},
				ShieldKey: mustHash(t, 324),
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if v2Indexed != 2 {
		t.Fatalf("expected two V2 indexed leaves, got %d", v2Indexed)
	}
	v3Hash := mustHash(t, 33)
	v3Indexed, err := IndexV3CommitmentEvents(ctx, store, []railevents.V3CommitmentEvent{{
		Commitments: []railevents.V3Commitment{{
			CommitmentType:   railevents.CommitmentTypeTransactV3,
			Hash:             v3Hash,
			Txid:             "0xv3",
			BlockNumber:      43,
			UTXOTree:         3,
			UTXOIndex:        1,
			SenderCiphertext: "0x1234",
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if v3Indexed != 1 {
		t.Fatalf("expected one V3 indexed leaf, got %d", v3Indexed)
	}
	nullifierHash := mustHash(t, 401)
	olderNullifierTxid := mustHash(t, 402)
	newerNullifierTxid := mustHash(t, 403)
	nullifiersIndexed, err := store.UpsertNullifiers(ctx, []railevents.Nullifier{
		{
			Txid:        olderNullifierTxid,
			Nullifier:   nullifierHash,
			TreeNumber:  1,
			BlockNumber: 41,
		},
		{
			Txid:        newerNullifierTxid,
			Nullifier:   nullifierHash,
			TreeNumber:  2,
			BlockNumber: 42,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if nullifiersIndexed != 2 {
		t.Fatalf("expected two indexed nullifiers, got %d", nullifiersIndexed)
	}
	unshieldTxid := mustHash(t, 404)
	unshieldIndex := uint(5)
	unshieldsIndexed, err := store.UpsertUnshieldEvents(ctx, []railevents.UnshieldStoredEvent{{
		Txid:          unshieldTxid,
		ToAddress:     "0x0000000000000000000000000000000000000001",
		TokenType:     0,
		TokenAddress:  "0x0000000000000000000000000000000000000000",
		TokenSubID:    "0",
		Amount:        "7",
		Fee:           "1",
		BlockNumber:   42,
		EventLogIndex: &unshieldIndex,
		RailgunTxid:   mustHash(t, 405),
	}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if unshieldsIndexed != 1 {
		t.Fatalf("expected one indexed unshield, got %d", unshieldsIndexed)
	}
	unshieldsIndexed, err = store.UpsertUnshieldEvents(ctx, []railevents.UnshieldStoredEvent{{
		Txid:          unshieldTxid,
		ToAddress:     "0x0000000000000000000000000000000000000001",
		TokenType:     0,
		TokenAddress:  "0x0000000000000000000000000000000000000000",
		TokenSubID:    "0",
		Amount:        "7",
		Fee:           "1",
		BlockNumber:   42,
		EventLogIndex: &unshieldIndex,
		RailgunTxid:   mustHash(t, 405),
	}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if unshieldsIndexed != 0 {
		t.Fatalf("expected duplicate unshield to be skipped, got %d", unshieldsIndexed)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	reopened := NewPebbleStore(path)
	leaves, err := reopened.ListLeaves(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 3 || leaves[0].Tree != 2 || leaves[0].Index != 2 || leaves[2].Tree != 3 || leaves[2].Index != 1 {
		t.Fatalf("unexpected persisted leaves %+v", leaves)
	}
	v2Commitment, ok, err := reopened.GetV2Commitment(ctx, 2, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(v2Commitment.EncryptedBundle) != 3 || v2Commitment.ShieldKey == "" {
		t.Fatalf("expected persisted full V2 commitment, got ok=%v %+v", ok, v2Commitment)
	}
	v2Commitments, err := reopened.ListV2Commitments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2Commitments) != 2 {
		t.Fatalf("expected two persisted V2 commitments, got %d", len(v2Commitments))
	}
	v3Commitment, ok, err := reopened.GetV3Commitment(ctx, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || v3Commitment.SenderCiphertext != "0x1234" {
		t.Fatalf("expected persisted full V3 commitment, got ok=%v %+v", ok, v3Commitment)
	}
	treeTwo := uint64(2)
	txid, ok, err := reopened.GetNullifierTxid(ctx, nullifierHash, &treeTwo)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || txid != newerNullifierTxid {
		t.Fatalf("expected tree-specific nullifier txid %s, got ok=%v %s", newerNullifierTxid, ok, txid)
	}
	txid, ok, err = reopened.GetNullifierTxid(ctx, nullifierHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || txid != newerNullifierTxid {
		t.Fatalf("expected latest-tree nullifier txid %s, got ok=%v %s", newerNullifierTxid, ok, txid)
	}
	nullifiers, err := reopened.ListNullifiers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nullifiers) != 2 {
		t.Fatalf("expected two persisted nullifiers, got %d", len(nullifiers))
	}
	unshields, err := reopened.GetUnshieldEventsByTxid(ctx, unshieldTxid)
	if err != nil {
		t.Fatal(err)
	}
	if len(unshields) != 1 || unshields[0].Amount != "7" {
		t.Fatalf("expected persisted unshield event, got %+v", unshields)
	}
	proof, err := reopened.Proof(ctx, 2, 7)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = merkletree.VerifyProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected pebble proof to verify")
	}
	root, err := reopened.Root(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if root != proof.Root {
		t.Fatalf("expected root %s to match proof root %s", root, proof.Root)
	}
	if err := reopened.RollbackToBlock(ctx, 42); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := NewPebbleStore(path).GetLeaf(ctx, 2, 7); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove block 42 leaf")
	}
	if _, ok, err := NewPebbleStore(path).GetV2Commitment(ctx, 2, 7); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove block 42 V2 commitment")
	}
	if _, ok, err := NewPebbleStore(path).GetLeaf(ctx, 3, 1); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove later V3 leaf")
	}
	if _, ok, err := NewPebbleStore(path).GetV3Commitment(ctx, 3, 1); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove later V3 commitment")
	}
	if txid, ok, err := NewPebbleStore(path).GetNullifierTxid(ctx, nullifierHash, nil); err != nil {
		t.Fatal(err)
	} else if !ok || txid != olderNullifierTxid {
		t.Fatalf("expected rollback to keep older nullifier txid %s, got ok=%v %s", olderNullifierTxid, ok, txid)
	}
	if unshields, err := NewPebbleStore(path).GetUnshieldEventsByTxid(ctx, unshieldTxid); err != nil {
		t.Fatal(err)
	} else if len(unshields) != 0 {
		t.Fatalf("expected rollback to remove unshield events, got %+v", unshields)
	}
	if _, ok, err := NewPebbleStore(path).GetLeaf(ctx, 2, 2); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected older leaf to remain")
	}
	if _, ok, err := NewPebbleStore(path).GetV2Commitment(ctx, 2, 2); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected older V2 commitment to remain")
	}
}

func TestStoreRejectsInvalidLeaves(t *testing.T) {
	if err := NewMemoryStore().UpsertLeaf(context.Background(), Leaf{Index: TreeMaxItems, Hash: "0x01"}); err == nil {
		t.Fatal("expected out-of-range index to fail")
	}
	if _, err := LeafFromV2Commitment(railevents.Commitment{Hash: "0x01", UTXOTree: -1}); err == nil {
		t.Fatal("expected negative tree to fail")
	}
	if _, err := LeafFromV3Commitment(railevents.V3Commitment{Hash: "not-hex"}); err == nil {
		t.Fatal("expected invalid hash to fail")
	}
}

func mustHash(t *testing.T, value int64) string {
	t.Helper()
	hash, err := railcrypto.BigIntToHex(big.NewInt(value), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
