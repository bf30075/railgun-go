package wallet

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

func TestMemorySpentPOIEventStoreLifecycleAndRollback(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySpentPOIEventStore()
	sent := testSentCommitmentPOIEvent("0xsent", "railgun", 20)
	if err := store.UpsertSentCommitmentPOIEvent(ctx, sent); err != nil {
		t.Fatal(err)
	}
	sent.POIsPerList["active"] = railpoi.TXOPOIListStatusValid
	sent.Value.SetInt64(99)
	if err := store.UpsertUnshieldPOIEvent(ctx, testUnshieldPOIEvent("0xunshield", "railgun", 30)); err != nil {
		t.Fatal(err)
	}

	sentEvents, err := store.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sentEvents) != 1 || sentEvents[0].POIsPerList["active"] != railpoi.TXOPOIListStatusMissing || sentEvents[0].Value.Int64() != 5 {
		t.Fatalf("expected cloned sent event, got %+v", sentEvents)
	}
	if err := store.MarkProofSubmitted(ctx, []railpoi.SubmittedPreTransactionPOI{{SubmitRequest: railpoi.SubmitPOIRequest{ListKey: "active"}}}); err != nil {
		t.Fatal(err)
	}
	sentEvents, err = store.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sentEvents[0].POIsPerList["active"] != railpoi.TXOPOIListStatusProofSubmitted {
		t.Fatalf("expected submitted sent event, got %+v", sentEvents[0].POIsPerList)
	}
	if err := store.RollbackToBlock(ctx, 25); err != nil {
		t.Fatal(err)
	}
	unshieldEvents, err := store.ListUnshieldPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unshieldEvents) != 0 {
		t.Fatalf("expected rollback to remove unshield event, got %+v", unshieldEvents)
	}
	sentEvents, err = store.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sentEvents) != 1 {
		t.Fatalf("expected older sent event to remain, got %+v", sentEvents)
	}
}

func TestFileSpentPOIEventStorePersistsMarksAndRollsBack(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "spent-poi-events.json")
	store := NewFileSpentPOIEventStore(path)
	if err := store.UpsertSentCommitmentPOIEvent(ctx, testSentCommitmentPOIEvent("0xsent", "railgun", 20)); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertUnshieldPOIEvent(ctx, testUnshieldPOIEvent("0xunshield", "railgun", 30)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"txid": "0xsent"`) {
		t.Fatalf("expected persisted sent event, got\n%s", raw)
	}

	reopened := NewFileSpentPOIEventStore(path)
	sentEvents, err := reopened.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sentEvents) != 1 || sentEvents[0].Value.Int64() != 5 || sentEvents[0].TokenHash == "" || sentEvents[0].OutputType == nil {
		t.Fatalf("unexpected persisted sent events %+v", sentEvents)
	}
	if sentEvents[0].WalletSource != "wallet-source" || sentEvents[0].MemoText != "memo text" || sentEvents[0].SenderAddress != "0zksender" || sentEvents[0].RecipientAddress != "0zkrecipient" {
		t.Fatalf("unexpected persisted sent annotations %+v", sentEvents[0])
	}
	if err := reopened.MarkProofSubmitted(ctx, []railpoi.SubmittedPreTransactionPOI{{SubmitRequest: railpoi.SubmitPOIRequest{ListKey: "active"}}}); err != nil {
		t.Fatal(err)
	}
	sentEvents, err = NewFileSpentPOIEventStore(path).ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sentEvents[0].POIsPerList["active"] != railpoi.TXOPOIListStatusProofSubmitted {
		t.Fatalf("expected persisted submitted status, got %+v", sentEvents[0].POIsPerList)
	}
	if err := reopened.RollbackToBlock(ctx, 25); err != nil {
		t.Fatal(err)
	}
	unshieldEvents, err := NewFileSpentPOIEventStore(path).ListUnshieldPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unshieldEvents) != 0 {
		t.Fatalf("expected rollback to remove unshield events, got %+v", unshieldEvents)
	}
}

func TestWalletSpentPOIStatusFromStoreAndRollback(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	state := NewMemoryStateStore()
	if err := state.UpsertTXO(ctx, StoredTXO{
		Tree:        0,
		Position:    1,
		Nullifier:   "01",
		BlockNumber: 10,
		Value:       big.NewInt(1),
		POIsPerList: railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
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
		Commitments: []string{"0xcommit"},
		UTXOTreeIn:  0,
	}); err != nil {
		t.Fatal(err)
	}
	eventStore := NewMemorySpentPOIEventStore()
	if err := eventStore.UpsertSentCommitmentPOIEvent(ctx, testSentCommitmentPOIEvent("0xsent", "railgun", 40)); err != nil {
		t.Fatal(err)
	}
	checkpoints := railevents.NewMemoryCheckpointStore()
	if err := checkpoints.SaveCheckpoint(ctx, "v3", railevents.ScanCheckpoint{NextBlock: 50}); err != nil {
		t.Fatal(err)
	}
	wallet, err := NewWalletWithStores(state, checkpoints, testSyncKeys(), manager, txidStore, nil, eventStore)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := wallet.SpentPOIStatusFromStore(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].RailgunTxid != "railgun" {
		t.Fatalf("unexpected spent poi statuses %+v", statuses)
	}
	pendingTxids, err := wallet.ChainTXIDsStillPendingSpentPOIs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, pendingTxids, []string{"0xsent"})
	proofsPossible, err := wallet.NumSpendPOIProofsPossible(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	if proofsPossible != 1 {
		t.Fatalf("expected one possible spend POI proof, got %d", proofsPossible)
	}
	if err := wallet.MarkSpentPOIProofsSubmitted(ctx, []railpoi.SubmittedPreTransactionPOI{{SubmitRequest: railpoi.SubmitPOIRequest{ListKey: "active"}}}); err != nil {
		t.Fatal(err)
	}
	sentEvents, err := eventStore.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sentEvents[0].POIsPerList["active"] != railpoi.TXOPOIListStatusProofSubmitted {
		t.Fatalf("expected wallet mark submitted to update store, got %+v", sentEvents[0].POIsPerList)
	}
	pendingTxids, err = wallet.ChainTXIDsStillPendingSpentPOIs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pendingTxids) != 0 {
		t.Fatalf("expected no pending txids after submission, got %+v", pendingTxids)
	}
	if err := wallet.Rollback(ctx, "v3", 40); err != nil {
		t.Fatal(err)
	}
	sentEvents, err = eventStore.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sentEvents) != 0 {
		t.Fatalf("expected rollback to remove spent poi event, got %+v", sentEvents)
	}
}

func testSentCommitmentPOIEvent(txid string, railgunTxid string, blockNumber uint64) SentCommitmentPOIStatusInput {
	outputType := railcrypto.OutputTypeTransfer
	return SentCommitmentPOIStatusInput{
		TXID:              txid,
		RailgunTxid:       railgunTxid,
		BlockNumber:       blockNumber,
		CommitmentHash:    "0xcommit",
		BlindedCommitment: "0xblind",
		TokenHash:         "0000000000000000000000001111111111111111111111111111111111111111",
		TokenData: railcrypto.TokenData{
			TokenAddress: "0x1111111111111111111111111111111111111111",
			TokenType:    railcrypto.TokenTypeERC20,
			TokenSubID:   "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		Value:            big.NewInt(5),
		OutputType:       &outputType,
		WalletSource:     "wallet-source",
		MemoText:         "memo text",
		SenderAddress:    "0zksender",
		RecipientAddress: "0zkrecipient",
		POIsPerList:      railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
	}
}

func testUnshieldPOIEvent(txid string, railgunTxid string, blockNumber uint64) UnshieldPOIStatusInput {
	return UnshieldPOIStatusInput{
		TXID:           txid,
		RailgunTxid:    railgunTxid,
		BlockNumber:    blockNumber,
		CommitmentHash: "0xunshield",
		POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusMissing},
	}
}
