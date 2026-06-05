package sdk

import (
	"context"
	"math/big"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

func TestRuntimeFacadeSyncBalancesHistoryStatusAndLegacy(t *testing.T) {
	ctx := context.Background()
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active"},
	}, &runtimeFacadePOINode{required: false, active: true})
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, manager, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Bundle:   bundle,
		Chain:    testRuntimeChain,
		Provider: &sdkStubProvider{latest: 12},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		engine:  engine,
		bundle:  bundle,
		network: testRuntimeNetworkConfig(),
	}

	results, err := runtime.Sync(ctx, "runtime")
	if err != nil {
		t.Fatal(err)
	}
	result := results[railcrypto.TXIDVersionV2PoseidonMerkle]
	if !result.Scanned || result.ToBlock != 12 || result.Checkpoint.NextBlock != 13 {
		t.Fatalf("unexpected sync result %+v", result)
	}

	txo := testStoredTXO(t, "runtime-nullifier")
	txo.TXIDVersion = railcrypto.TXIDVersionV2PoseidonMerkle
	txo.TXID = "runtime-txid"
	txo.BlindedCommitment = "0x1234"
	txo.CommitmentType = railpoi.CommitmentTypeTransactV2
	if err := runtime.engine.wallet.State.UpsertTXO(ctx, txo); err != nil {
		t.Fatal(err)
	}
	if err := runtime.engine.wallet.UTXOMerkleTree.UpsertLeaf(ctx, testUTXOLeaf(txo)); err != nil {
		t.Fatal(err)
	}

	balances, err := runtime.Balances(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := balances[railcrypto.TXIDVersionV2PoseidonMerkle][txo.TokenHash].Balance.String(); got != "7" {
		t.Fatalf("expected balance 7, got %s", got)
	}
	spendable, err := runtime.SpendableBalances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := spendable[railcrypto.TXIDVersionV2PoseidonMerkle][txo.TokenHash].Balance.String(); got != "7" {
		t.Fatalf("expected spendable balance 7, got %s", got)
	}
	history, err := runtime.TransactionHistory(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].TXID != "runtime-txid" {
		t.Fatalf("unexpected history %+v", history)
	}
	received, err := runtime.ReceivedPOIStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 || received[0].TXID != "runtime-txid" {
		t.Fatalf("unexpected received poi status %+v", received)
	}
	if spent, err := runtime.SpentPOIStatus(ctx); err != nil {
		t.Fatal(err)
	} else if len(spent) != 0 {
		t.Fatalf("unexpected spent poi status %+v", spent)
	}
	if _, err := runtime.RefreshPOIs(ctx, railcrypto.TXIDVersionV2PoseidonMerkle); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RefreshSpentPOIEvents(ctx, railcrypto.TXIDVersionV2PoseidonMerkle); err != nil {
		t.Fatal(err)
	}
	legacy, err := runtime.SubmitLegacyTransactPOIEventsAndRefresh(ctx, railcrypto.TXIDVersionV2PoseidonMerkle)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Submit.TXOsChecked != 1 || legacy.Submit.TXOsMatched != 0 {
		t.Fatalf("unexpected legacy summary %+v", legacy)
	}
}

func TestRuntimePreTransactionPOIWrapperDefaultsChainAndRequiresProver(t *testing.T) {
	ctx := context.Background()
	node := &runtimeFacadePOINode{required: true, active: true}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active"},
	}, node)
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, manager, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Bundle: bundle,
		Chain:  testRuntimeChain,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{engine: engine}

	request := railpoi.GenerateAndSubmitPreTransactionPOIRequest{
		TXIDVersion: railcrypto.TXIDVersionV2PoseidonMerkle,
		ListKey:     "active",
		Inputs: railpoi.PreTransactionPOIInputs{
			PublicInputs: railproof.PublicInputsRailgun{
				BoundParamsHash: big.NewInt(1),
			},
		},
	}
	if _, err := runtime.GenerateAndSubmitPreTransactionPOI(ctx, request, nil); err == nil || !strings.Contains(err.Error(), "prover is not configured") {
		t.Fatalf("expected missing prover error, got %v", err)
	}

	runtime.prover = railproof.NewProver(nil, nil)
	_, err = runtime.GenerateAndSubmitPreTransactionPOI(ctx, request, nil)
	if err == nil {
		t.Fatal("expected invalid input error")
	}
	if node.getProofsRequest.Chain != testRuntimeChain {
		t.Fatalf("expected runtime chain default, got %+v", node.getProofsRequest.Chain)
	}
}

type runtimeFacadePOINode struct {
	required bool
	active   bool

	getProofsRequest railpoi.GetPOIMerkleProofsRequest
	submitPOIRequest railpoi.SubmitPOIRequest
}

func (node *runtimeFacadePOINode) IsActive(railchain.Chain) bool {
	return node.active
}

func (node *runtimeFacadePOINode) IsRequired(context.Context, railchain.Chain) (bool, error) {
	return node.required, nil
}

func (node *runtimeFacadePOINode) GetPOIsPerList(_ context.Context, request railpoi.GetPOIsPerListRequest) (map[string]railpoi.POIsPerList, error) {
	out := map[string]railpoi.POIsPerList{}
	for _, commitment := range request.BlindedCommitmentDatas {
		out[commitment.BlindedCommitment] = railpoi.POIsPerList{}
		for _, listKey := range request.ListKeys {
			out[commitment.BlindedCommitment][listKey] = railpoi.TXOPOIListStatusValid
		}
	}
	return out, nil
}

func (node *runtimeFacadePOINode) GetPOIMerkleProofs(_ context.Context, request railpoi.GetPOIMerkleProofsRequest) ([]merkletree.MerkleProof, error) {
	node.getProofsRequest = request
	proofs := make([]merkletree.MerkleProof, len(request.BlindedCommitments))
	for i, blindedCommitment := range request.BlindedCommitments {
		proof, err := merkletree.CreateDummyProof(blindedCommitment)
		if err != nil {
			return nil, err
		}
		proofs[i] = proof
	}
	return proofs, nil
}

func (node *runtimeFacadePOINode) ValidatePOIMerkleRoots(context.Context, railpoi.ValidatePOIMerkleRootsRequest) (bool, error) {
	return true, nil
}

func (node *runtimeFacadePOINode) SubmitPOI(_ context.Context, request railpoi.SubmitPOIRequest) error {
	node.submitPOIRequest = request
	return nil
}

func (node *runtimeFacadePOINode) SubmitLegacyTransactProofs(context.Context, railpoi.SubmitLegacyTransactProofsRequest) error {
	return nil
}

var _ railpoi.NodeInterface = (*runtimeFacadePOINode)(nil)
