package wallet

import (
	"context"
	"math/big"
	"reflect"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

func TestWalletRefreshPOIsRetrievesAndStoresMissingPOIs(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	store := NewMemoryStateStore()
	node := &refreshPOINode{
		poisByCommitment: map[string]railpoi.POIsPerList{
			"bc-transact": {"active": railpoi.TXOPOIListStatusValid, "gather": railpoi.TXOPOIListStatusValid},
			"bc-shield":   {"active": railpoi.TXOPOIListStatusShieldBlocked, "gather": railpoi.TXOPOIListStatusValid},
		},
	}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
		{Key: "gather", Type: railpoi.ListTypeGather, Name: "gather", Description: "gather"},
	}, node)
	wallet, err := NewWallet(store, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager)
	if err != nil {
		t.Fatal(err)
	}

	for _, txo := range []StoredTXO{
		{
			TXIDVersion:       "V2_PoseidonMerkle",
			Tree:              0,
			Position:          1,
			Nullifier:         "n-transact",
			Value:             big.NewInt(1),
			CommitmentType:    railpoi.CommitmentTypeTransactV2,
			POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
			BlindedCommitment: "bc-transact",
		},
		{
			TXIDVersion:       "V2_PoseidonMerkle",
			Tree:              0,
			Position:          2,
			Nullifier:         "n-shield",
			Value:             big.NewInt(1),
			CommitmentType:    railpoi.CommitmentTypeShield,
			BlindedCommitment: "bc-shield",
		},
		{
			TXIDVersion:       "V2_PoseidonMerkle",
			Tree:              0,
			Position:          3,
			Nullifier:         "n-valid",
			Value:             big.NewInt(1),
			CommitmentType:    railpoi.CommitmentTypeTransactV2,
			POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid, "gather": railpoi.TXOPOIListStatusValid},
			BlindedCommitment: "bc-valid",
		},
		{
			TXIDVersion:       "V3_PoseidonMerkle",
			Tree:              0,
			Position:          4,
			Nullifier:         "n-v3",
			Value:             big.NewInt(1),
			CommitmentType:    railpoi.CommitmentTypeTransactV3,
			POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
			BlindedCommitment: "bc-v3",
		},
	} {
		if err := store.UpsertTXO(ctx, txo); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := wallet.RefreshPOIs(ctx, "V2_PoseidonMerkle", chain)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, RefreshPOIsSummary{
		TXOsChecked: 4,
		TXOsMatched: 2,
		Requests:    1,
		TXOsUpdated: 2,
	})
	if len(node.requests) != 1 {
		t.Fatalf("expected one POI request, got %d", len(node.requests))
	}
	request := node.requests[0]
	if request.TXIDVersion != "V2_PoseidonMerkle" || request.Chain != chain {
		t.Fatalf("unexpected request %+v", request)
	}
	if !reflect.DeepEqual(request.ListKeys, []string{"active", "gather"}) {
		t.Fatalf("unexpected list keys %+v", request.ListKeys)
	}
	if !reflect.DeepEqual(request.BlindedCommitmentDatas, []railpoi.BlindedCommitmentData{
		{BlindedCommitment: "bc-transact", Type: railpoi.BlindedCommitmentTypeTransact},
		{BlindedCommitment: "bc-shield", Type: railpoi.BlindedCommitmentTypeShield},
	}) {
		t.Fatalf("unexpected blinded commitments %+v", request.BlindedCommitmentDatas)
	}

	transact, ok, err := store.GetTXO(ctx, "n-transact")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || transact.POIsPerList["active"] != railpoi.TXOPOIListStatusValid {
		t.Fatalf("expected transact txo POIs to update, got %+v", transact)
	}
	shield, ok, err := store.GetTXO(ctx, "n-shield")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || shield.POIsPerList["active"] != railpoi.TXOPOIListStatusShieldBlocked {
		t.Fatalf("expected shield txo POIs to update, got %+v", shield)
	}
	v3, ok, err := store.GetTXO(ctx, "n-v3")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || v3.POIsPerList["active"] != railpoi.TXOPOIListStatusMissing {
		t.Fatalf("expected v3 txo to be skipped, got %+v", v3)
	}
}

func TestRefreshPOIsReportsMissingNodeEntries(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	node := &refreshPOINode{poisByCommitment: map[string]railpoi.POIsPerList{}}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, node)
	if err := store.UpsertTXO(ctx, StoredTXO{
		TXIDVersion:       "V2_PoseidonMerkle",
		Nullifier:         "n-missing",
		Value:             big.NewInt(1),
		CommitmentType:    railpoi.CommitmentTypeTransactV2,
		POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		BlindedCommitment: "bc-missing",
	}); err != nil {
		t.Fatal(err)
	}

	summary, err := RefreshPOIs(ctx, store, manager, "V2_PoseidonMerkle", railchain.Chain{Type: 0, ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, RefreshPOIsSummary{
		TXOsChecked: 1,
		TXOsMatched: 1,
		Requests:    1,
		TXOsMissing: 1,
	})
}

func TestRefreshPOIsRejectsUnsupportedCommitmentType(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, &refreshPOINode{})
	if err := store.UpsertTXO(ctx, StoredTXO{
		TXIDVersion:       "V2_PoseidonMerkle",
		Nullifier:         "n-unknown",
		Value:             big.NewInt(1),
		CommitmentType:    "Unknown",
		POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		BlindedCommitment: "bc-unknown",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := RefreshPOIs(ctx, store, manager, "V2_PoseidonMerkle", railchain.Chain{Type: 0, ID: 1})
	if err == nil || !strings.Contains(err.Error(), "unsupported commitment type") {
		t.Fatalf("expected unsupported commitment type error, got %v", err)
	}
}

func TestWalletRefreshSpentPOIEventsRetrievesAndStoresMissingPOIs(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	eventStore := NewMemorySpentPOIEventStore()
	node := &refreshPOINode{
		poisByCommitment: map[string]railpoi.POIsPerList{
			"bc-sent":          {"active": railpoi.TXOPOIListStatusValid, "gather": railpoi.TXOPOIListStatusProofSubmitted},
			"railgun-unshield": {"active": railpoi.TXOPOIListStatusValid, "gather": railpoi.TXOPOIListStatusValid},
		},
	}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
		{Key: "gather", Type: railpoi.ListTypeGather, Name: "gather", Description: "gather"},
	}, node)
	wallet, err := NewWalletWithStores(
		NewMemoryStateStore(),
		railevents.NewMemoryCheckpointStore(),
		testSyncKeys(),
		manager,
		nil,
		nil,
		eventStore,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := eventStore.UpsertSentCommitmentPOIEvent(ctx, SentCommitmentPOIStatusInput{
		TXID:              "0xsent",
		RailgunTxid:       "railgun-sent",
		BlockNumber:       10,
		CommitmentHash:    "0xcommit",
		BlindedCommitment: "bc-sent",
		Value:             big.NewInt(5),
		POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
	}); err != nil {
		t.Fatal(err)
	}
	if err := eventStore.UpsertSentCommitmentPOIEvent(ctx, SentCommitmentPOIStatusInput{
		TXID:              "0xzero",
		RailgunTxid:       "railgun-zero",
		BlockNumber:       11,
		BlindedCommitment: "bc-zero",
		Value:             big.NewInt(0),
		POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
	}); err != nil {
		t.Fatal(err)
	}
	if err := eventStore.UpsertUnshieldPOIEvent(ctx, UnshieldPOIStatusInput{
		TXID:        "0xunshield",
		RailgunTxid: "railgun-unshield",
		BlockNumber: 12,
		POIsPerList: railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
	}); err != nil {
		t.Fatal(err)
	}

	summary, err := wallet.RefreshSpentPOIEvents(ctx, "V3_PoseidonMerkle", chain)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, RefreshSpentPOIEventsSummary{
		SentCommitmentsChecked: 2,
		UnshieldEventsChecked:  1,
		EventsMatched:          2,
		Requests:               1,
		EventsUpdated:          2,
	})
	if len(node.requests) != 1 {
		t.Fatalf("expected one POI request, got %d", len(node.requests))
	}
	request := node.requests[0]
	if request.TXIDVersion != "V3_PoseidonMerkle" || request.Chain != chain {
		t.Fatalf("unexpected request %+v", request)
	}
	if !reflect.DeepEqual(request.BlindedCommitmentDatas, []railpoi.BlindedCommitmentData{
		{BlindedCommitment: "bc-sent", Type: railpoi.BlindedCommitmentTypeTransact},
		{BlindedCommitment: "railgun-unshield", Type: railpoi.BlindedCommitmentTypeUnshield},
	}) {
		t.Fatalf("unexpected spent event commitments %+v", request.BlindedCommitmentDatas)
	}

	sentEvents, err := eventStore.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sentByTxid := map[string]SentCommitmentPOIStatusInput{}
	for _, event := range sentEvents {
		sentByTxid[event.TXID] = event
	}
	if sentByTxid["0xsent"].POIsPerList["gather"] != railpoi.TXOPOIListStatusProofSubmitted {
		t.Fatalf("expected sent POIs to update, got %+v", sentByTxid["0xsent"].POIsPerList)
	}
	if sentByTxid["0xzero"].POIsPerList["active"] != railpoi.TXOPOIListStatusMissing {
		t.Fatalf("expected zero-value sent event to be skipped, got %+v", sentByTxid["0xzero"].POIsPerList)
	}
	unshieldEvents, err := eventStore.ListUnshieldPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unshieldEvents) != 1 || unshieldEvents[0].POIsPerList["gather"] != railpoi.TXOPOIListStatusValid {
		t.Fatalf("expected unshield POIs to update, got %+v", unshieldEvents)
	}
}

type refreshPOINode struct {
	poisByCommitment map[string]railpoi.POIsPerList
	requests         []railpoi.GetPOIsPerListRequest
}

func (node *refreshPOINode) IsActive(railchain.Chain) bool {
	return true
}

func (node *refreshPOINode) IsRequired(context.Context, railchain.Chain) (bool, error) {
	return true, nil
}

func (node *refreshPOINode) GetPOIsPerList(_ context.Context, request railpoi.GetPOIsPerListRequest) (map[string]railpoi.POIsPerList, error) {
	node.requests = append(node.requests, request)
	out := map[string]railpoi.POIsPerList{}
	for _, commitment := range request.BlindedCommitmentDatas {
		if pois, ok := node.poisByCommitment[commitment.BlindedCommitment]; ok {
			out[commitment.BlindedCommitment] = pois
		}
	}
	return out, nil
}

func (node *refreshPOINode) GetPOIMerkleProofs(context.Context, railpoi.GetPOIMerkleProofsRequest) ([]merkletree.MerkleProof, error) {
	return nil, nil
}

func (node *refreshPOINode) ValidatePOIMerkleRoots(context.Context, railpoi.ValidatePOIMerkleRootsRequest) (bool, error) {
	return true, nil
}

func (node *refreshPOINode) SubmitPOI(context.Context, railpoi.SubmitPOIRequest) error {
	return nil
}

func (node *refreshPOINode) SubmitLegacyTransactProofs(context.Context, railpoi.SubmitLegacyTransactProofsRequest) error {
	return nil
}
