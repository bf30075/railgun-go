package sdk

import (
	"context"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

func TestEngineFacadeSyncBalancesHistoryProofAndRollback(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Bundle:   bundle,
		Chain:    chain,
		Provider: &sdkStubProvider{latest: 12},
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := engine.SyncActiveTXIDVersions(ctx, map[string]railevents.CheckpointedScan{
		railcrypto.TXIDVersionV2PoseidonMerkle: {
			Key:        "v2",
			StartBlock: 10,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := results[railcrypto.TXIDVersionV2PoseidonMerkle]
	if !result.Scanned || result.FromBlock != 10 || result.ToBlock != 12 || result.Checkpoint.NextBlock != 13 {
		t.Fatalf("unexpected sync result %+v", result)
	}

	txo := testStoredTXO(t, "engine-nullifier")
	txo.TXIDVersion = railcrypto.TXIDVersionV2PoseidonMerkle
	txo.TXID = "engine-txid"
	if err := engine.wallet.State.UpsertTXO(ctx, txo); err != nil {
		t.Fatal(err)
	}
	if err := engine.stores.UTXOMerkleTree.UpsertLeaf(ctx, testUTXOLeaf(txo)); err != nil {
		t.Fatal(err)
	}

	balances, err := engine.Balances(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := balances[railcrypto.TXIDVersionV2PoseidonMerkle][txo.TokenHash].Balance.String(); got != "7" {
		t.Fatalf("expected balance 7, got %s", got)
	}
	history, err := engine.TransactionHistory(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].TXID != "engine-txid" {
		t.Fatalf("unexpected history %+v", history)
	}
	status, err := engine.ReceivedPOIStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0].TXID != "engine-txid" {
		t.Fatalf("unexpected received poi status %+v", status)
	}
	if _, err := engine.UTXOMerkleRoot(ctx, txo.Tree); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.UTXOMerkleProof(ctx, txo.Nullifier); err != nil {
		t.Fatal(err)
	}

	if err := engine.Rollback(ctx, "v2", txo.BlockNumber); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := engine.wallet.State.GetTXO(ctx, txo.Nullifier); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("expected rollback to remove txo")
	}
	leaves, err := engine.stores.UTXOMerkleTree.ListLeaves(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 0 {
		t.Fatalf("expected rollback to remove utxo leaves, got %+v", leaves)
	}
}

func TestEngineRejectsMissingDependencies(t *testing.T) {
	if _, err := NewEngine(EngineConfig{}); err == nil || !strings.Contains(err.Error(), "wallet") {
		t.Fatalf("expected wallet error, got %v", err)
	}
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Bundle: bundle,
		Chain:  railchain.Chain{Type: 0, ID: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SyncV2(context.Background(), railevents.CheckpointedScan{Key: "v2"}); err == nil || !strings.Contains(err.Error(), "event provider") {
		t.Fatalf("expected provider error, got %v", err)
	}
	if _, err := engine.SyncV3(context.Background(), railevents.CheckpointedScan{Key: "v3"}); err == nil || !strings.Contains(err.Error(), "event provider") {
		t.Fatalf("expected provider error, got %v", err)
	}
}

func TestEngineSyncV3RequiresSupportedChain(t *testing.T) {
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Bundle:   bundle,
		Chain:    railchain.Chain{Type: 0, ID: 999999},
		Provider: &sdkStubProvider{latest: 12},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.SyncV3(context.Background(), railevents.CheckpointedScan{Key: "v3"})
	if err == nil || !strings.Contains(err.Error(), "does not support V3") {
		t.Fatalf("expected V3 support error, got %v", err)
	}
}

func testUTXOLeaf(txo railwallet.StoredTXO) railutxotree.Leaf {
	return railutxotree.Leaf{
		Tree:        txo.Tree,
		Index:       txo.Position,
		Hash:        txo.CommitmentHash,
		BlockNumber: txo.BlockNumber,
	}
}

type sdkStubProvider struct {
	latest uint64
}

func (provider *sdkStubProvider) FilterLogs(ctx context.Context, filter railevents.LogFilter) ([]railevents.ContractLog, error) {
	return nil, ctx.Err()
}

func (provider *sdkStubProvider) BlockNumber(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return provider.latest, nil
}
