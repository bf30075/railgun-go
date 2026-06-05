package wallet

import (
	"context"
	"math/big"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

func TestWalletTransactionHistoryMergesReceiveSentAndUnshieldEntries(t *testing.T) {
	ctx := context.Background()
	state := NewMemoryStateStore()
	eventStore := NewMemorySpentPOIEventStore()
	txidStore := railtxid.NewMemoryTransactionStore()
	manager := testBalancePOIManager()
	wallet, err := NewWalletWithStores(state, railevents.NewMemoryCheckpointStore(), testSyncKeys(), manager, txidStore, nil, eventStore)
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
	change := railcrypto.OutputTypeChange
	broadcasterFee := railcrypto.OutputTypeBroadcasterFee
	timestamp := uint64(1000)
	for _, txo := range []StoredTXO{
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       1,
			TXID:           "0xreceive",
			Timestamp:      &timestamp,
			BlockNumber:    10,
			Nullifier:      "receive",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(11),
			OutputType:     &transfer,
			WalletSource:   "receive-source",
			MemoText:       "receive memo",
			SenderAddress:  "0zksender",
			ShieldFee:      "2",
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
		{
			TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
			Tree:           0,
			Position:       2,
			TXID:           "0xspend",
			BlockNumber:    20,
			Nullifier:      "change",
			TokenHash:      tokenHash,
			TokenData:      tokenData,
			Value:          big.NewInt(3),
			OutputType:     &change,
			CommitmentType: railpoi.CommitmentTypeTransactV2,
			POIsPerList:    railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
		},
	} {
		if err := state.UpsertTXO(ctx, txo); err != nil {
			t.Fatal(err)
		}
	}
	transferEvent := historySentEvent("0xspend", tokenHash, tokenData, big.NewInt(7), &transfer, 20)
	transferEvent.WalletSource = "sent-source"
	transferEvent.MemoText = "sent memo"
	transferEvent.RecipientAddress = "0zkrecipient"
	if err := eventStore.UpsertSentCommitmentPOIEvent(ctx, transferEvent); err != nil {
		t.Fatal(err)
	}
	if err := eventStore.UpsertSentCommitmentPOIEvent(ctx, historySentEvent("0xspend", tokenHash, tokenData, big.NewInt(3), &change, 20)); err != nil {
		t.Fatal(err)
	}
	if err := eventStore.UpsertSentCommitmentPOIEvent(ctx, historySentEvent("0xspend", tokenHash, tokenData, big.NewInt(1), &broadcasterFee, 20)); err != nil {
		t.Fatal(err)
	}
	if err := txidStore.UpsertTransaction(ctx, railtxid.Transaction{
		RailgunTxid: "railgun-unshield",
		Txid:        "0xunshield",
		BlockNumber: 30,
		Unshield: &railtxid.UnshieldData{
			TokenData: tokenData,
			ToAddress: "0x2222222222222222222222222222222222222222",
			Value:     "5",
			Fee:       "1",
		},
	}); err != nil {
		t.Fatal(err)
	}

	history, err := wallet.TransactionHistory(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, nil)
	if err != nil {
		t.Fatal(err)
	}
	byTXID := historyByTXID(history)
	if len(byTXID) != 3 {
		t.Fatalf("expected three history entries, got %+v", history)
	}
	receive := byTXID["0xreceive"]
	if len(receive.ReceiveTokenAmounts) != 1 || receive.ReceiveTokenAmounts[0].Amount.String() != "11" {
		t.Fatalf("unexpected receive history %+v", receive)
	}
	if receive.ReceiveTokenAmounts[0].MemoText != "receive memo" || receive.ReceiveTokenAmounts[0].WalletSource != "receive-source" || receive.ReceiveTokenAmounts[0].SenderAddress != "0zksender" || receive.ReceiveTokenAmounts[0].ShieldFee != "2" {
		t.Fatalf("unexpected receive annotations %+v", receive.ReceiveTokenAmounts[0])
	}
	spend := byTXID["0xspend"]
	if len(spend.TransferTokenAmounts) != 1 || spend.TransferTokenAmounts[0].Amount.String() != "7" {
		t.Fatalf("unexpected transfer history %+v", spend.TransferTokenAmounts)
	}
	if spend.TransferTokenAmounts[0].RecipientAddress != "0zkrecipient" || spend.TransferTokenAmounts[0].MemoText != "sent memo" || spend.TransferTokenAmounts[0].WalletSource != "sent-source" {
		t.Fatalf("unexpected transfer annotations %+v", spend.TransferTokenAmounts[0])
	}
	if len(spend.ChangeTokenAmounts) != 1 || spend.ChangeTokenAmounts[0].Amount.String() != "3" || len(spend.ReceiveTokenAmounts) != 0 {
		t.Fatalf("expected change output to stay out of receive history, got %+v", spend)
	}
	if spend.BroadcasterFeeTokenAmount == nil || spend.BroadcasterFeeTokenAmount.Amount.String() != "1" {
		t.Fatalf("unexpected broadcaster fee %+v", spend.BroadcasterFeeTokenAmount)
	}
	unshield := byTXID["0xunshield"]
	if len(unshield.UnshieldTokenAmounts) != 1 || unshield.UnshieldTokenAmounts[0].Amount.String() != "5" {
		t.Fatalf("unexpected unshield history %+v", unshield)
	}
	if unshield.UnshieldTokenAmounts[0].UnshieldFee != "1" {
		t.Fatalf("unexpected unshield fee %+v", unshield.UnshieldTokenAmounts[0])
	}

	startingBlock := uint64(25)
	history, err = wallet.TransactionHistory(ctx, railcrypto.TXIDVersionV2PoseidonMerkle, &startingBlock)
	if err != nil {
		t.Fatal(err)
	}
	byTXID = historyByTXID(history)
	if len(byTXID) != 1 || byTXID["0xunshield"].TXID != "0xunshield" {
		t.Fatalf("expected only unshield history after block 25, got %+v", history)
	}
}

func historySentEvent(txid string, tokenHash string, tokenData railcrypto.TokenData, value *big.Int, outputType *int, blockNumber uint64) SentCommitmentPOIStatusInput {
	return SentCommitmentPOIStatusInput{
		TXID:              txid,
		RailgunTxid:       "railgun-" + txid,
		BlockNumber:       blockNumber,
		CommitmentHash:    "commit-" + value.String(),
		BlindedCommitment: "blind-" + value.String(),
		TokenHash:         tokenHash,
		TokenData:         tokenData,
		Value:             value,
		OutputType:        outputType,
		POIsPerList:       railpoi.POIsPerList{"active": railpoi.TXOPOIListStatusValid},
	}
}

func historyByTXID(history []TransactionHistoryEntry) map[string]TransactionHistoryEntry {
	out := map[string]TransactionHistoryEntry{}
	for _, entry := range history {
		out[entry.TXID] = entry
	}
	return out
}
