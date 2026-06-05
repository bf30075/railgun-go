package wallet

import (
	"context"
	"math/big"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

func TestWalletFacadeSyncBalancesAndRollback(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	checkpoints := railevents.NewMemoryCheckpointStore()
	wallet, err := NewWallet(state, checkpoints, testSyncKeys(), testBalancePOIManager())
	if err != nil {
		t.Fatal(err)
	}

	result, err := wallet.SyncV2(ctx, &walletSyncProvider{latest: 12}, railevents.CheckpointedScan{
		Key:        "v2",
		StartBlock: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, result, SyncResult{
		FromBlock: 10,
		ToBlock:   12,
		Scanned:   true,
		Checkpoint: railevents.ScanCheckpoint{
			NextBlock: 13,
		},
		Import: ImportSummary{},
	})

	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpsertTXO(ctx, StoredTXO{
		Tree:           0,
		Position:       1,
		BlockNumber:    11,
		Nullifier:      "balance",
		TokenHash:      tokenHash,
		TokenData:      tokenData,
		Value:          big.NewInt(10),
		CommitmentType: railpoi.CommitmentTypeTransactV2,
		POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
	}); err != nil {
		t.Fatal(err)
	}
	balances, err := wallet.Balances(ctx, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances, tokenHash, "10", 1)

	if err := wallet.Rollback(ctx, "v2", 11); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := state.GetTXO(ctx, "balance"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove txo")
	}
	saved, ok, err := checkpoints.LoadCheckpoint(ctx, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checkpoint")
	}
	assertJSONEqual(t, saved, railevents.ScanCheckpoint{NextBlock: 11})
}

func TestNewWalletRejectsMissingDependencies(t *testing.T) {
	_, err := NewWallet(nil, railevents.NewMemoryCheckpointStore(), testSyncKeys(), testBalancePOIManager())
	if err == nil || !strings.Contains(err.Error(), "state store") {
		t.Fatalf("expected state store error, got %v", err)
	}
	_, err = NewWallet(NewMemoryStateStore(), nil, testSyncKeys(), testBalancePOIManager())
	if err == nil || !strings.Contains(err.Error(), "checkpoint store") {
		t.Fatalf("expected checkpoint store error, got %v", err)
	}
	_, err = NewWallet(NewMemoryStateStore(), railevents.NewMemoryCheckpointStore(), testSyncKeys(), nil)
	if err == nil || !strings.Contains(err.Error(), "poi manager") {
		t.Fatalf("expected poi manager error, got %v", err)
	}
}

func TestWalletSpendableBalancesUsePOIBucketsAndTXIDVersion(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	state := NewMemoryStateStore()
	node := &walletBalancePOINode{required: true, active: true}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, node)
	wallet, err := NewWallet(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager)
	if err != nil {
		t.Fatal(err)
	}
	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	transfer := railcrypto.OutputTypeTransfer
	for _, txo := range []StoredTXO{
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       1,
			Nullifier:      "v2-spendable",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(10),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       2,
			Nullifier:      "v2-missing",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(5),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV3PoseidonMerkle,
			Tree:           0,
			Position:       3,
			Nullifier:      "v3-spendable",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(100),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV3,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       4,
			Nullifier:      "v2-spent",
			SpendTXID:      "spent-txid",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(99),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
	} {
		if err := state.UpsertTXO(ctx, txo); err != nil {
			t.Fatal(err)
		}
	}

	balances, err := wallet.SpendableBalances(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, chain)
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances, tokenHash, "10", 1)

	node.required = false
	balances, err = wallet.SpendableBalances(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, chain)
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances, tokenHash, "15", 2)
}

func TestWalletBalanceHelpersByBucketTokenAndTree(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, &walletBalancePOINode{required: true, active: true})
	wallet, err := NewWallet(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager)
	if err != nil {
		t.Fatal(err)
	}
	tokenAddress := "0x1111111111111111111111111111111111111111"
	tokenData, err := railcrypto.TokenDataERC20(tokenAddress)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	transfer := railcrypto.OutputTypeTransfer
	for _, txo := range []StoredTXO{
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       1,
			Nullifier:      "tree-0",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(10),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           1,
			Position:       1,
			Nullifier:      "tree-1",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(4),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           1,
			Position:       2,
			Nullifier:      "missing",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(5),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV3PoseidonMerkle,
			Tree:           0,
			Position:       3,
			Nullifier:      "v3",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(100),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV3,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
	} {
		if err := state.UpsertTXO(ctx, txo); err != nil {
			t.Fatal(err)
		}
	}

	byBucket, err := wallet.BalancesByBucket(ctx, railcrypto.TXIDVersionV2PoseidonMerkle)
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, byBucket[railpoi.WalletBalanceBucketSpendable], tokenHash, "14", 2)
	assertBalance(t, byBucket[railpoi.WalletBalanceBucketMissingExternalPOI], tokenHash, "5", 1)

	erc20Balance, ok, err := wallet.BalanceERC20(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, tokenAddress, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || erc20Balance.String() != "14" {
		t.Fatalf("expected ERC20 spendable balance 14, got %v ok=%t", erc20Balance, ok)
	}

	treeBalances, err := wallet.BalancesByTreeForToken(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, tokenHash, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	if len(treeBalances) != 2 {
		t.Fatalf("expected two tree balances, got %+v", treeBalances)
	}
	if treeBalances[0].Balance.String() != "10" || treeBalances[1].Balance.String() != "4" {
		t.Fatalf("unexpected tree balances %+v", treeBalances)
	}
	if total := TokenBalanceAcrossAllTrees(treeBalances); total.String() != "14" {
		t.Fatalf("expected total 14, got %s", total)
	}
}

func TestWalletBalancesForUnshieldToOriginFiltersOriginShieldTXOs(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, &walletBalancePOINode{required: true, active: true})
	wallet, err := NewWallet(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager)
	if err != nil {
		t.Fatal(err)
	}
	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	for _, txo := range []StoredTXO{
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       1,
			TXID:           "0x0abc",
			Nullifier:      "origin-shield",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(20),
			CommitmentType: railpoi.CommitmentTypeShield,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       2,
			TXID:           "0xdef",
			Nullifier:      "other-shield",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(30),
			CommitmentType: railpoi.CommitmentTypeShield,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       3,
			TXID:           "0x0abc",
			Nullifier:      "origin-transact",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(40),
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       4,
			TXID:           "0x0abc",
			SpendTXID:      "0xspent",
			Nullifier:      "spent-shield",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(50),
			CommitmentType: railpoi.CommitmentTypeShield,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV3PoseidonMerkle,
			Tree:           0,
			Position:       5,
			TXID:           "0x0abc",
			Nullifier:      "v3-shield",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(100),
			CommitmentType: railpoi.CommitmentTypeShield,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		},
	} {
		if err := state.UpsertTXO(ctx, txo); err != nil {
			t.Fatal(err)
		}
	}

	balances, err := wallet.BalancesForUnshieldToOrigin(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, "0xabc")
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances, tokenHash, "20", 1)

	treeBalances, err := wallet.BalancesByTreeForTokenForUnshieldToOrigin(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, tokenHash, "0xabc")
	if err != nil {
		t.Fatal(err)
	}
	if total := TokenBalanceAcrossAllTrees(treeBalances); total.String() != "20" {
		t.Fatalf("expected origin tree total 20, got %s", total)
	}
}

func TestWalletAllTXIDVersionFacadesRespectChainV3Support(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, &walletBalancePOINode{required: true, active: true})
	wallet, err := NewWallet(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager)
	if err != nil {
		t.Fatal(err)
	}
	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	transfer := railcrypto.OutputTypeTransfer
	for _, txo := range []StoredTXO{
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       1,
			TXID:           "0xv2",
			Nullifier:      "all-v2",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(2),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV3PoseidonMerkle,
			Tree:           0,
			Position:       2,
			TXID:           "0xv3",
			Nullifier:      "all-v3",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(3),
			OutputType:     &transfer,
			CommitmentType: railpoi.CommitmentTypeTransactV3,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
	} {
		if err := state.UpsertTXO(ctx, txo); err != nil {
			t.Fatal(err)
		}
	}

	unsupportedV3Chain := railchain.Chain{Type: 0, ID: 990000}
	balances, err := wallet.BalancesAllTXIDVersions(ctx, unsupportedV3Chain, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := balances[railcrypto.TXIDVersionV3PoseidonMerkle]; ok {
		t.Fatalf("expected V3 balances to be skipped, got %+v", balances)
	}
	assertBalance(t, balances[railcrypto.TXIDVersionV2PoseidonMerkle], tokenHash, "2", 1)

	supportedV3Chain := railchain.Chain{Type: 0, ID: 990001}
	railchain.AddSupportsV3(supportedV3Chain)
	balances, err = wallet.BalancesAllTXIDVersions(ctx, supportedV3Chain, []string{railpoi.WalletBalanceBucketSpendable})
	if err != nil {
		t.Fatal(err)
	}
	assertBalance(t, balances[railcrypto.TXIDVersionV2PoseidonMerkle], tokenHash, "2", 1)
	assertBalance(t, balances[railcrypto.TXIDVersionV3PoseidonMerkle], tokenHash, "3", 1)

	history, err := wallet.TransactionHistoryAllTXIDVersions(ctx, supportedV3Chain, nil)
	if err != nil {
		t.Fatal(err)
	}
	byTXID := historyByTXID(history)
	if byTXID["0xv2"].TXIDVersion != railcrypto.TXIDVersionV2PoseidonMerkle || byTXID["0xv3"].TXIDVersion != railcrypto.TXIDVersionV3PoseidonMerkle {
		t.Fatalf("unexpected all-version history %+v", history)
	}
}

func TestWalletPOIQueriesMatchReceiveCommitmentAndSpendableTxids(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, &walletBalancePOINode{required: true, active: true})
	wallet, err := NewWallet(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager)
	if err != nil {
		t.Fatal(err)
	}
	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	for _, txo := range []StoredTXO{
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       1,
			TXID:           "0xaaa",
			Nullifier:      "valid",
			CommitmentHash: "0x0123",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(10),
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       2,
			TXID:           "0xbbb",
			Nullifier:      "missing",
			CommitmentHash: "0x0456",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(5),
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       3,
			TXID:           "0xaaa",
			Nullifier:      "duplicate-txid",
			CommitmentHash: "0x0789",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(2),
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV3PoseidonMerkle,
			Tree:           0,
			Position:       4,
			TXID:           "0xccc",
			Nullifier:      "v3",
			CommitmentHash: "0x0123",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(100),
			CommitmentType: railpoi.CommitmentTypeTransactV3,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
	} {
		if err := state.UpsertTXO(ctx, txo); err != nil {
			t.Fatal(err)
		}
	}

	hasValidPOI, err := wallet.ReceiveCommitmentHasValidPOI(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, "0x123")
	if err != nil {
		t.Fatal(err)
	}
	if !hasValidPOI {
		t.Fatal("expected valid commitment POI")
	}
	hasValidPOI, err = wallet.ReceiveCommitmentHasValidPOI(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, "0x456")
	if err != nil {
		t.Fatal(err)
	}
	if hasValidPOI {
		t.Fatal("expected missing commitment POI to be invalid")
	}

	txids, err := wallet.SpendableReceivedChainTXIDs(ctx, railcrypto.TXIDVersionV2PoseidonMerkle)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, txids, []string{"0xaaa"})
}

func TestWalletRollbackAlsoRollsBackTXIDStore(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	checkpoints := railevents.NewMemoryCheckpointStore()
	if err := checkpoints.SaveCheckpoint(ctx, "v3", railevents.ScanCheckpoint{NextBlock: 50}); err != nil {
		t.Fatal(err)
	}
	txidStore := railtxid.NewMemoryTransactionStore()
	txidTree := railtxid.NewMemoryMerkleTreeStore()
	if err := txidStore.UpsertTransaction(ctx, railtxid.Transaction{
		RailgunTxid: "old",
		Txid:        "0xold",
		BlockNumber: 10,
	}); err != nil {
		t.Fatal(err)
	}
	if err := txidStore.UpsertTransaction(ctx, railtxid.Transaction{
		RailgunTxid: "new",
		Txid:        "0xnew",
		BlockNumber: 45,
	}); err != nil {
		t.Fatal(err)
	}
	oldLeafHash, err := railcrypto.BigIntToHex(big.NewInt(1), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	newLeafHash, err := railcrypto.BigIntToHex(big.NewInt(2), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := txidTree.UpsertLeaf(ctx, railtxid.MerkleLeaf{
		Tree:        0,
		Index:       0,
		Hash:        oldLeafHash,
		RailgunTxid: "old",
		BlockNumber: 10,
	}); err != nil {
		t.Fatal(err)
	}
	if err := txidTree.UpsertLeaf(ctx, railtxid.MerkleLeaf{
		Tree:        0,
		Index:       1,
		Hash:        newLeafHash,
		RailgunTxid: "new",
		BlockNumber: 45,
	}); err != nil {
		t.Fatal(err)
	}
	wallet, err := NewWalletWithTXIDStores(state, checkpoints, testSyncKeys(), testBalancePOIManager(), txidStore, txidTree)
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.Rollback(ctx, "v3", 40); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := txidStore.GetByRailgunTxid(ctx, "new"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected txid rollback to remove new transaction")
	}
	if _, ok, err := txidStore.GetByRailgunTxid(ctx, "old"); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected old transaction to remain")
	}
	if _, ok, err := txidTree.GetLeaf(ctx, 0, 1); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected txid tree rollback to remove new leaf")
	}
	if _, ok, err := txidTree.GetLeaf(ctx, 0, 0); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected old txid tree leaf to remain")
	}
}

type walletBalancePOINode struct {
	required bool
	active   bool
}

func (node *walletBalancePOINode) IsActive(railchain.Chain) bool {
	return node.active
}

func (node *walletBalancePOINode) IsRequired(context.Context, railchain.Chain) (bool, error) {
	return node.required, nil
}

func (node *walletBalancePOINode) GetPOIsPerList(context.Context, railpoi.GetPOIsPerListRequest) (map[string]railpoi.POIsPerList, error) {
	return nil, nil
}

func (node *walletBalancePOINode) GetPOIMerkleProofs(context.Context, railpoi.GetPOIMerkleProofsRequest) ([]merkletree.MerkleProof, error) {
	return nil, nil
}

func (node *walletBalancePOINode) ValidatePOIMerkleRoots(context.Context, railpoi.ValidatePOIMerkleRootsRequest) (bool, error) {
	return true, nil
}

func (node *walletBalancePOINode) SubmitPOI(context.Context, railpoi.SubmitPOIRequest) error {
	return nil
}

func (node *walletBalancePOINode) SubmitLegacyTransactProofs(context.Context, railpoi.SubmitLegacyTransactProofsRequest) error {
	return nil
}
