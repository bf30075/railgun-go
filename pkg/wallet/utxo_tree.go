package wallet

import (
	"context"
	"fmt"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
)

func (wallet *Wallet) UTXOMerkleRoot(ctx context.Context, tree uint64) (string, error) {
	if err := wallet.validate(); err != nil {
		return "", err
	}
	if wallet.UTXOMerkleTree == nil {
		return "", fmt.Errorf("utxo merkle tree store is required")
	}
	return wallet.UTXOMerkleTree.Root(ctx, tree)
}

func (wallet *Wallet) UTXOMerkleProof(ctx context.Context, nullifier string) (merkletree.MerkleProof, error) {
	if err := wallet.validate(); err != nil {
		return merkletree.MerkleProof{}, err
	}
	if wallet.UTXOMerkleTree == nil {
		return merkletree.MerkleProof{}, fmt.Errorf("utxo merkle tree store is required")
	}
	txo, ok, err := wallet.State.GetTXO(ctx, nullifier)
	if err != nil {
		return merkletree.MerkleProof{}, err
	}
	if !ok {
		return merkletree.MerkleProof{}, fmt.Errorf("missing txo for nullifier %s", nullifier)
	}
	return UTXOMerkleProofForTXO(ctx, wallet.UTXOMerkleTree, txo)
}

func UTXOMerkleProofForTXO(ctx context.Context, store railutxotree.Store, txo StoredTXO) (merkletree.MerkleProof, error) {
	if store == nil {
		return merkletree.MerkleProof{}, fmt.Errorf("utxo merkle tree store is required")
	}
	if txo.CommitmentHash == "" {
		return merkletree.MerkleProof{}, fmt.Errorf("txo commitment hash is required")
	}
	proof, err := store.Proof(ctx, txo.Tree, txo.Position)
	if err != nil {
		return merkletree.MerkleProof{}, err
	}
	expected, err := railcrypto.FormatHexToByteLength(txo.CommitmentHash, 32, false)
	if err != nil {
		return merkletree.MerkleProof{}, fmt.Errorf("txo commitment hash: %w", err)
	}
	got, err := railcrypto.FormatHexToByteLength(proof.Leaf, 32, false)
	if err != nil {
		return merkletree.MerkleProof{}, fmt.Errorf("utxo proof leaf: %w", err)
	}
	if got != expected {
		return merkletree.MerkleProof{}, fmt.Errorf("utxo proof leaf does not match txo commitment hash")
	}
	return proof, nil
}
