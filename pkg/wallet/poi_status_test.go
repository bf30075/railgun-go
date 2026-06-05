package wallet

import (
	"context"
	"math/big"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

func TestFormatReceivedPOIStatusInfoSortsAndFormats(t *testing.T) {
	statuses := FormatReceivedPOIStatusInfo([]StoredTXO{
		{
			Tree:              0,
			Position:          1,
			TXID:              "txid-low",
			CommitmentHash:    "0xcommit-low",
			CommitmentType:    railpoi.CommitmentTypeTransactV2,
			BlindedCommitment: "0xblind-low",
			POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			Tree:           1,
			Position:       0,
			TXID:           "txid-high",
			CommitmentType: railpoi.CommitmentTypeShield,
		},
	})
	if len(statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(statuses))
	}
	if statuses[0].TXID != "txid-high" {
		t.Fatalf("expected highest global position first, got %+v", statuses)
	}
	if statuses[0].Commitment != "Unavailable (ShieldCommitment)" {
		t.Fatalf("unexpected missing commitment formatting %q", statuses[0].Commitment)
	}
	if statuses[0].BlindedCommitment != "Unavailable" {
		t.Fatalf("unexpected missing blinded commitment formatting %q", statuses[0].BlindedCommitment)
	}
	if statuses[1].Commitment != "0xcommit-low (TransactCommitmentV2)" {
		t.Fatalf("unexpected commitment formatting %q", statuses[1].Commitment)
	}
	statuses[1].POIsPerList["active"] = railpoi.TXOPOIListStatusMissing
	if got := FormatReceivedPOIStatusInfo([]StoredTXO{{POIsPerList: railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid}}}); got[0].POIsPerList["active"] != railpoi.TXOPOIListStatusValid {
		t.Fatal("expected POIs map to be cloned")
	}
}

func TestWalletReceivedPOIStatusReadsState(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	if err := store.UpsertTXO(ctx, StoredTXO{
		Tree:              0,
		Position:          2,
		TXID:              "txid",
		Nullifier:         "nullifier",
		Value:             big.NewInt(1),
		CommitmentHash:    "0xcommit",
		CommitmentType:    railpoi.CommitmentTypeTransactV2,
		BlindedCommitment: "0xblind",
		POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
	}); err != nil {
		t.Fatal(err)
	}
	wallet, err := NewWallet(store, railevents.NewMemoryCheckpointStore(), testSyncKeys(), testBalancePOIManager())
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := wallet.ReceivedPOIStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].Commitment != "0xcommit (TransactCommitmentV2)" {
		t.Fatalf("unexpected statuses %+v", statuses)
	}
}

func TestFormatSpentPOIStatusInfoMatchesCoreTypeScriptRules(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
		{Key: "gather", Type: railpoi.ListTypeGather, Name: "gather", Description: "gather"},
	}, nil)
	manager.SetLaunchBlock(chain, 100)
	txidStore := railtxid.NewMemoryTransactionStore()
	if err := txidStore.UpsertTransaction(ctx, railtxid.Transaction{
		RailgunTxid:     "railgun-legacy",
		Txid:            "0xevm-legacy",
		BlockNumber:     90,
		Commitments:     []string{"0xccc"},
		Nullifiers:      []string{"0xaaa"},
		BoundParamsHash: "0xbbb",
		UTXOTreeIn:      0,
	}); err != nil {
		t.Fatal(err)
	}
	txos := []StoredTXO{{
		Tree:           0,
		Position:       1,
		Nullifier:      "aaa",
		CommitmentType: railpoi.CommitmentTypeTransactV2,
		POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid, "gather": railpoi.TXOPOIListStatusMissing},
	}}
	sentCommitments := []SentCommitmentPOIStatusInput{
		{
			TXID:              "0xevm-legacy",
			RailgunTxid:       "railgun-legacy",
			BlockNumber:       90,
			CommitmentHash:    "0xccc",
			BlindedCommitment: "0xblind",
			Value:             big.NewInt(1),
			POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid, "gather": railpoi.TXOPOIListStatusMissing},
		},
		{
			TXID:           "0xevm-missing",
			RailgunTxid:    "railgun-not-found",
			BlockNumber:    120,
			CommitmentHash: "0xddd",
			Value:          big.NewInt(1),
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
		},
	}

	statuses, err := FormatSpentPOIStatusInfo(ctx, manager, txidStore, chain, txos, sentCommitments, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(statuses))
	}
	if statuses[0].RailgunTxid != "railgun-not-found" || statuses[0].RailgunTransactionInfo != "Not found" {
		t.Fatalf("expected newest not-found status first, got %+v", statuses[0])
	}
	legacy := statuses[1]
	if legacy.RailgunTransactionInfo != "1 nul: 0xaaa (✓), 1 com/unsh: 0xccc (✓)" {
		t.Fatalf("unexpected railgun transaction info %q", legacy.RailgunTransactionInfo)
	}
	if len(legacy.POIStatusesSpentTXOs) != 1 || legacy.POIStatusesSpentTXOs[0]["gather"] != railpoi.TXOPOIListStatusMissing {
		t.Fatalf("unexpected spent txo statuses %+v", legacy.POIStatusesSpentTXOs)
	}
	if legacy.SentCommitmentsBlinded != "0xblind" {
		t.Fatalf("unexpected sent blinded string %q", legacy.SentCommitmentsBlinded)
	}
	if len(legacy.ListKeysCanGenerateSpentPOIs) != 1 || legacy.ListKeysCanGenerateSpentPOIs[0] != "gather" {
		t.Fatalf("unexpected list keys %+v", legacy.ListKeysCanGenerateSpentPOIs)
	}
}

func TestFormatSpentPOIStatusInfoHandlesMissingRailgunTxidAndLaunchBlock(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active", Description: "active"},
	}, nil)
	txidStore := railtxid.NewMemoryTransactionStore()
	statuses, err := FormatSpentPOIStatusInfo(ctx, manager, txidStore, chain, nil, nil, []UnshieldPOIStatusInput{{
		TXID:        "0xevm",
		BlockNumber: 80,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].RailgunTxid != "Missing" || statuses[0].RailgunTransactionInfo != "Missing" {
		t.Fatalf("unexpected missing railgun txid status %+v", statuses)
	}

	if err := txidStore.UpsertTransaction(ctx, railtxid.Transaction{
		RailgunTxid: "railgun",
		BlockNumber: 110,
		Nullifiers:  []string{"0x01"},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = FormatSpentPOIStatusInfo(ctx, manager, txidStore, chain, nil, []SentCommitmentPOIStatusInput{{
		TXID:        "0xevm",
		RailgunTxid: "railgun",
		BlockNumber: 110,
		Value:       big.NewInt(1),
	}}, nil)
	if err == nil || err.Error() != "No POI launch block for railgun txids" {
		t.Fatalf("expected launch block error, got %v", err)
	}
}

func TestMarkSpentPOIProofSubmittedClonesAndPreservesValid(t *testing.T) {
	sent := []SentCommitmentPOIStatusInput{{
		TXID:  "0xsent",
		Value: big.NewInt(7),
		POIsPerList: railpoi.POIsPerList{
			"active": railpoi.TXOPOIListStatusValid,
			"gather": railpoi.TXOPOIListStatusMissing,
		},
	}}
	unshield := []UnshieldPOIStatusInput{{
		TXID:        "0xunshield",
		POIsPerList: railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
	}}

	updatedSent, updatedUnshield := MarkSpentPOIProofSubmitted(sent, unshield, []string{"active", "gather", "external"})
	if updatedSent[0].POIsPerList["active"] != railpoi.TXOPOIListStatusValid {
		t.Fatalf("expected valid sent status to remain valid, got %+v", updatedSent[0].POIsPerList)
	}
	if updatedSent[0].POIsPerList["gather"] != railpoi.TXOPOIListStatusProofSubmitted || updatedSent[0].POIsPerList["external"] != railpoi.TXOPOIListStatusProofSubmitted {
		t.Fatalf("expected submitted sent statuses, got %+v", updatedSent[0].POIsPerList)
	}
	if updatedUnshield[0].POIsPerList["active"] != railpoi.TXOPOIListStatusProofSubmitted || updatedUnshield[0].POIsPerList["gather"] != railpoi.TXOPOIListStatusProofSubmitted {
		t.Fatalf("expected submitted unshield statuses, got %+v", updatedUnshield[0].POIsPerList)
	}

	updatedSent[0].POIsPerList["gather"] = railpoi.TXOPOIListStatusValid
	updatedSent[0].Value.SetInt64(99)
	if sent[0].POIsPerList["gather"] != railpoi.TXOPOIListStatusMissing || sent[0].Value.Int64() != 7 {
		t.Fatalf("expected original sent input to be unchanged, got %+v value %s", sent[0].POIsPerList, sent[0].Value)
	}
}

func TestApplySubmittedPreTransactionPOIStatusesUsesSubmissionListKeys(t *testing.T) {
	sent := []SentCommitmentPOIStatusInput{{POIsPerList: railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing}}}
	submissions := []railpoi.SubmittedPreTransactionPOI{
		{SubmitRequest: railpoi.SubmitPOIRequest{ListKey: "active"}},
		{SubmitRequest: railpoi.SubmitPOIRequest{ListKey: "gather"}},
	}

	updatedSent, updatedUnshield := ApplySubmittedPreTransactionPOIStatuses(sent, nil, submissions)
	if len(updatedUnshield) != 0 {
		t.Fatalf("expected no unshield events, got %+v", updatedUnshield)
	}
	if updatedSent[0].POIsPerList["active"] != railpoi.TXOPOIListStatusProofSubmitted || updatedSent[0].POIsPerList["gather"] != railpoi.TXOPOIListStatusProofSubmitted {
		t.Fatalf("expected submitted statuses from submissions, got %+v", updatedSent[0].POIsPerList)
	}
}

func TestWalletSpentPOIStatusReadsStateAndTXIDStore(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	state := NewMemoryStateStore()
	if err := state.UpsertTXO(ctx, StoredTXO{
		Tree:      0,
		Position:  1,
		Nullifier: "01",
		Value:     big.NewInt(1),
	}); err != nil {
		t.Fatal(err)
	}
	manager := testBalancePOIManager()
	manager.SetLaunchBlock(chain, 50)
	txidStore := railtxid.NewMemoryTransactionStore()
	if err := txidStore.UpsertTransaction(ctx, railtxid.Transaction{
		RailgunTxid: "railgun",
		BlockNumber: 40,
		Nullifiers:  []string{"0x01"},
		UTXOTreeIn:  0,
	}); err != nil {
		t.Fatal(err)
	}
	wallet, err := NewWalletWithTXIDStore(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager, txidStore)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := wallet.SpentPOIStatus(ctx, chain, []SentCommitmentPOIStatusInput{{
		TXID:        "0xevm",
		RailgunTxid: "railgun",
		BlockNumber: 40,
		Value:       big.NewInt(1),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].RailgunTxid != "railgun" {
		t.Fatalf("unexpected wallet spent statuses %+v", statuses)
	}
}
