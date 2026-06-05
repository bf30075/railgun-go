package wallet

import (
	"context"
	"math/big"
	"reflect"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

func TestWalletSubmitLegacyTransactPOIEventsBuildsAndSubmitsProofData(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	state := NewMemoryStateStore()
	node := &legacyPOINode{}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
		{Key: "gather", Type: railpoi.ListTypeGather, Name: "gather", Description: "gather"},
	}, node)
	manager.SetLaunchBlock(chain, 10)
	txidTree := railtxid.NewMemoryMerkleTreeStore()
	if err := txidTree.UpsertLeaf(ctx, railtxid.MerkleLeaf{
		Tree:        0,
		Index:       4,
		Hash:        mustLegacyHex(t, big.NewInt(44)),
		RailgunTxid: "railgun-found",
		BlockNumber: 8,
	}); err != nil {
		t.Fatal(err)
	}
	for _, txo := range []StoredTXO{
		{
			TXIDVersion:                 railcrypto.TXIDVersionV2PoseidonMerkle,
			Nullifier:                   "candidate-found",
			NotePublicKey:               "0x01",
			TokenHash:                   "0xtoken",
			Value:                       big.NewInt(7),
			CommitmentType:              railpoi.CommitmentTypeTransactV2,
			POIsPerList:                 railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing, "gather": railpoi.TXOPOIListStatusValid},
			BlindedCommitment:           "0xblind",
			TransactCreationRailgunTxid: "railgun-found",
			BlockNumber:                 8,
		},
		{
			TXIDVersion:                 railcrypto.TXIDVersionV2PoseidonMerkle,
			Nullifier:                   "candidate-missing",
			NotePublicKey:               "0x02",
			TokenHash:                   "0xtoken",
			Value:                       big.NewInt(9),
			CommitmentType:              railpoi.CommitmentTypeTransactV2,
			POIsPerList:                 railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing, "gather": railpoi.TXOPOIListStatusValid},
			BlindedCommitment:           "0xblind-missing",
			TransactCreationRailgunTxid: "railgun-missing",
			BlockNumber:                 8,
		},
		{
			TXIDVersion:                 railcrypto.TXIDVersionV2PoseidonMerkle,
			Nullifier:                   "already-valid",
			NotePublicKey:               "0x03",
			TokenHash:                   "0xtoken",
			Value:                       big.NewInt(1),
			CommitmentType:              railpoi.CommitmentTypeTransactV2,
			POIsPerList:                 railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid, "gather": railpoi.TXOPOIListStatusValid},
			BlindedCommitment:           "0xblind-valid",
			TransactCreationRailgunTxid: "railgun-valid",
			BlockNumber:                 8,
		},
	} {
		if err := state.UpsertTXO(ctx, txo); err != nil {
			t.Fatal(err)
		}
	}
	wallet, err := NewWalletWithStores(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager, nil, txidTree, nil)
	if err != nil {
		t.Fatal(err)
	}

	summary, err := wallet.SubmitLegacyTransactPOIEvents(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, chain)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, SubmitLegacyTransactPOIEventsSummary{
		TXOsChecked:         3,
		TXOsMatched:         2,
		TXIDIndicesMissing:  1,
		ProofDatasSubmitted: 1,
		ListKeysSubmitted:   []string{"active"},
	})
	if node.submitLegacyRequest.TXIDVersion != railcrypto.TXIDVersionV2PoseidonMerkle || node.submitLegacyRequest.Chain != chain {
		t.Fatalf("unexpected submit request %+v", node.submitLegacyRequest)
	}
	if !reflect.DeepEqual(node.submitLegacyRequest.ListKeys, []string{"active"}) {
		t.Fatalf("unexpected list keys %+v", node.submitLegacyRequest.ListKeys)
	}
	if len(node.submitLegacyRequest.LegacyTransactProofDatas) != 1 {
		t.Fatalf("unexpected proof data %+v", node.submitLegacyRequest.LegacyTransactProofDatas)
	}
	proofData := node.submitLegacyRequest.LegacyTransactProofDatas[0]
	if proofData.TXIDIndex != "4" || proofData.Value != "7" || proofData.TokenHash != "0xtoken" || proofData.BlindedCommitment != "0xblind" {
		t.Fatalf("unexpected proof data %+v", proofData)
	}
	if proofData.NPK != "0x0000000000000000000000000000000000000000000000000000000000000001" {
		t.Fatalf("unexpected npk %s", proofData.NPK)
	}
}

func TestWalletSubmitLegacyTransactPOIEventsAndRefreshUpdatesReceivePOIs(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	state := NewMemoryStateStore()
	node := &legacyPOINode{
		poisByCommitment: map[string]railpoi.POIsPerList{
			"0xblind": {"active": railpoi.TXOPOIListStatusValid},
		},
	}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, node)
	manager.SetLaunchBlock(chain, 10)
	txidTree := railtxid.NewMemoryMerkleTreeStore()
	if err := txidTree.UpsertLeaf(ctx, railtxid.MerkleLeaf{
		Tree:        0,
		Index:       4,
		Hash:        mustLegacyHex(t, big.NewInt(44)),
		RailgunTxid: "railgun-found",
		BlockNumber: 8,
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.UpsertTXO(ctx, StoredTXO{
		TXIDVersion:                 railcrypto.TXIDVersionV2PoseidonMerkle,
		Nullifier:                   "candidate",
		NotePublicKey:               "0x01",
		TokenHash:                   "0xtoken",
		Value:                       big.NewInt(7),
		CommitmentType:              railpoi.CommitmentTypeTransactV2,
		POIsPerList:                 railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		BlindedCommitment:           "0xblind",
		TransactCreationRailgunTxid: "railgun-found",
		BlockNumber:                 8,
	}); err != nil {
		t.Fatal(err)
	}
	wallet, err := NewWalletWithStores(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager, nil, txidTree, nil)
	if err != nil {
		t.Fatal(err)
	}

	summary, err := wallet.SubmitLegacyTransactPOIEventsAndRefresh(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, chain)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, SubmitLegacyTransactPOIEventsAndRefreshSummary{
		Submit: SubmitLegacyTransactPOIEventsSummary{
			TXOsChecked:         1,
			TXOsMatched:         1,
			ProofDatasSubmitted: 1,
			ListKeysSubmitted:   []string{"active"},
		},
		Refresh: RefreshPOIsSummary{
			TXOsChecked: 1,
			TXOsMatched: 1,
			Requests:    1,
			TXOsUpdated: 1,
		},
	})
	if len(node.getPOIsRequests) != 1 {
		t.Fatalf("expected one POI refresh request, got %d", len(node.getPOIsRequests))
	}
	if !reflect.DeepEqual(node.getPOIsRequests[0].BlindedCommitmentDatas, []railpoi.BlindedCommitmentData{
		{BlindedCommitment: "0xblind", Type: railpoi.BlindedCommitmentTypeTransact},
	}) {
		t.Fatalf("unexpected POI refresh commitments %+v", node.getPOIsRequests[0].BlindedCommitmentDatas)
	}
	txo, ok, err := state.GetTXO(ctx, "candidate")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || txo.POIsPerList["active"] != railpoi.TXOPOIListStatusValid {
		t.Fatalf("expected refreshed txo POIs, got %+v", txo)
	}
}

type legacyPOINode struct {
	submitLegacyRequest railpoi.SubmitLegacyTransactProofsRequest
	poisByCommitment    map[string]railpoi.POIsPerList
	getPOIsRequests     []railpoi.GetPOIsPerListRequest
}

func (node *legacyPOINode) IsActive(railchain.Chain) bool {
	return true
}

func (node *legacyPOINode) IsRequired(context.Context, railchain.Chain) (bool, error) {
	return true, nil
}

func (node *legacyPOINode) GetPOIsPerList(_ context.Context, request railpoi.GetPOIsPerListRequest) (map[string]railpoi.POIsPerList, error) {
	node.getPOIsRequests = append(node.getPOIsRequests, request)
	out := map[string]railpoi.POIsPerList{}
	for _, commitment := range request.BlindedCommitmentDatas {
		if pois, ok := node.poisByCommitment[commitment.BlindedCommitment]; ok {
			out[commitment.BlindedCommitment] = pois
		}
	}
	return out, nil
}

func (node *legacyPOINode) GetPOIMerkleProofs(context.Context, railpoi.GetPOIMerkleProofsRequest) ([]merkletree.MerkleProof, error) {
	return nil, nil
}

func (node *legacyPOINode) ValidatePOIMerkleRoots(context.Context, railpoi.ValidatePOIMerkleRootsRequest) (bool, error) {
	return true, nil
}

func (node *legacyPOINode) SubmitPOI(context.Context, railpoi.SubmitPOIRequest) error {
	return nil
}

func (node *legacyPOINode) SubmitLegacyTransactProofs(_ context.Context, request railpoi.SubmitLegacyTransactProofsRequest) error {
	node.submitLegacyRequest = request
	return nil
}

func mustLegacyHex(t *testing.T, value *big.Int) string {
	t.Helper()
	out, err := railcrypto.BigIntToHex(value, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
