package wallet

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
)

func TestImportV2AccumulatedEventsDecryptsStoresAndMarksSpent(t *testing.T) {
	fixture := buildWalletImportFixture(t)
	keys := fixture.Keys
	nullifierHex := expectedNullifierHex(t, keys.NullifyingKey, 0, 4)
	store := NewMemoryStateStore()

	summary, err := ImportV2AccumulatedEvents(context.Background(), store, keys, railevents.V2AccumulatedEvents{
		CommitmentEvents: []railevents.CommitmentEvent{{
			Commitments: []railevents.Commitment{{
				CommitmentType: railevents.CommitmentTypeTransactV2,
				Hash:           fixture.CommitmentHash,
				Txid:           "railgun-txid-v2",
				BlockNumber:    100,
				UTXOTree:       0,
				UTXOIndex:      4,
				Ciphertext: &railevents.CommitmentCiphertextV2Event{
					Ciphertext:                fixture.V2.NoteCiphertext,
					BlindedSenderViewingKey:   fixture.BlindedSenderViewingKey,
					BlindedReceiverViewingKey: fixture.BlindedReceiverViewingKey,
					AnnotationData:            fixture.V2.AnnotationData,
					Memo:                      fixture.V2.NoteMemo,
				},
			}},
		}},
		NullifierEvents: []railevents.Nullifier{{
			Txid:        "spend-txid",
			Nullifier:   nullifierHex,
			TreeNumber:  0,
			BlockNumber: 110,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{TXOsImported: 1, SpendsMarked: 1})

	txo, ok, err := store.GetTXO(context.Background(), nullifierHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected imported txo")
	}
	assertImportedTXO(t, txo, importedTXOExpected{
		TXIDVersion:      railcrypto.TXIDVersionV2PoseidonMerkle,
		TXID:             "railgun-txid-v2",
		Nullifier:        nullifierHex,
		TokenHash:        fixture.TokenHash,
		Value:            fixture.Value,
		BlockNumber:      100,
		Tree:             0,
		Position:         4,
		CommitmentType:   railevents.CommitmentTypeTransactV2,
		MemoText:         loadWalletImportFixtures(t).TransactNoteFixtures.Inputs.MemoText,
		RecipientAddress: mustAddressFromScanKeys(t, fixture.Keys),
		SpendTXID:        "spend-txid",
		SpendBlockNumber: 110,
	})
}

func TestRescanLocalUTXOTreeDecryptsPebbleCommitmentsAndMarksSpent(t *testing.T) {
	fixture := buildWalletImportFixture(t)
	keys := fixture.Keys
	nullifierHex := expectedNullifierHex(t, keys.NullifyingKey, 0, 4)
	ctx := context.Background()
	state := NewMemoryStateStore()
	spentPOIEvents := NewMemorySpentPOIEventStore()
	utxoTree := railutxotree.NewPebbleStore(t.TempDir())
	if _, err := railutxotree.IndexV2CommitmentEvents(ctx, utxoTree, []railevents.CommitmentEvent{{
		Commitments: []railevents.Commitment{{
			CommitmentType: railevents.CommitmentTypeTransactV2,
			Hash:           fixture.CommitmentHash,
			Txid:           "railgun-txid-v2",
			BlockNumber:    100,
			UTXOTree:       0,
			UTXOIndex:      4,
			Ciphertext: &railevents.CommitmentCiphertextV2Event{
				Ciphertext:                fixture.V2.NoteCiphertext,
				BlindedSenderViewingKey:   fixture.BlindedSenderViewingKey,
				BlindedReceiverViewingKey: fixture.BlindedReceiverViewingKey,
				AnnotationData:            fixture.V2.AnnotationData,
				Memo:                      fixture.V2.NoteMemo,
			},
		}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := utxoTree.UpsertNullifiers(ctx, []railevents.Nullifier{
		{
			Txid:        "spend-txid",
			Nullifier:   nullifierHex,
			TreeNumber:  0,
			BlockNumber: 110,
		},
		{
			Txid:        "other-spend-txid",
			Nullifier:   mustImporterHex(t, big.NewInt(999)),
			TreeNumber:  0,
			BlockNumber: 111,
		},
	}); err != nil {
		t.Fatal(err)
	}
	eventLogIndex := uint(2)
	unshieldTxid := mustImporterHex(t, big.NewInt(1001))
	if _, err := utxoTree.UpsertUnshieldEvents(ctx, []railevents.UnshieldStoredEvent{{
		Txid:          unshieldTxid,
		ToAddress:     "0x0000000000000000000000000000000000000001",
		TokenType:     0,
		TokenAddress:  "0x0000000000000000000000000000000000000000",
		TokenSubID:    "0",
		Amount:        "7",
		Fee:           "1",
		BlockNumber:   112,
		EventLogIndex: &eventLogIndex,
	}}, false); err != nil {
		t.Fatal(err)
	}
	wallet, err := NewWalletWithAllStoresAndDetails(
		state,
		railevents.NewMemoryCheckpointStore(),
		keys,
		railpoi.NewManager(nil, nil),
		nil,
		nil,
		utxoTree,
		spentPOIEvents,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := wallet.RescanLocalUTXOTree(ctx, LocalRescanOptions{
		TXIDVersions: []string{railcrypto.TXIDVersionV2PoseidonMerkle},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{TXOsImported: 1, SpendsMarked: 1, UnshieldPOIEventsIndexed: 1})
	txo, ok, err := state.GetTXO(ctx, nullifierHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected local rescan to import txo")
	}
	assertImportedTXO(t, txo, importedTXOExpected{
		TXIDVersion:      railcrypto.TXIDVersionV2PoseidonMerkle,
		TXID:             "railgun-txid-v2",
		Nullifier:        nullifierHex,
		TokenHash:        fixture.TokenHash,
		Value:            fixture.Value,
		BlockNumber:      100,
		Tree:             0,
		Position:         4,
		CommitmentType:   railevents.CommitmentTypeTransactV2,
		MemoText:         loadWalletImportFixtures(t).TransactNoteFixtures.Inputs.MemoText,
		RecipientAddress: mustAddressFromScanKeys(t, fixture.Keys),
		SpendTXID:        "spend-txid",
		SpendBlockNumber: 110,
	})
	unshieldEvents, err := spentPOIEvents.ListUnshieldPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unshieldEvents) != 1 || unshieldEvents[0].TXID != unshieldTxid {
		t.Fatalf("expected one restored unshield POI event, got %+v", unshieldEvents)
	}
}

func TestImportV3AccumulatedEventsDecryptsAndStores(t *testing.T) {
	fixture := buildWalletImportFixture(t)
	keys := fixture.Keys
	nullifierHex := expectedNullifierHex(t, keys.NullifyingKey, 2, 7)
	store := NewMemoryStateStore()
	batchIndex := 0

	summary, err := ImportV3AccumulatedEvents(context.Background(), store, keys, railevents.V3AccumulatorEvents{
		CommitmentEvents: []railevents.V3CommitmentEvent{{
			Commitments: []railevents.V3Commitment{{
				CommitmentType:               railevents.CommitmentTypeTransactV3,
				Hash:                         fixture.CommitmentHash,
				Txid:                         "railgun-txid-v3",
				BlockNumber:                  200,
				UTXOTree:                     2,
				UTXOIndex:                    7,
				SenderCiphertext:             fixture.V3.AnnotationData,
				TransactCommitmentBatchIndex: &batchIndex,
				Ciphertext: &railevents.CommitmentCiphertextV3Event{
					Ciphertext:                fixture.V3.NoteCiphertext,
					BlindedSenderViewingKey:   fixture.BlindedSenderViewingKey,
					BlindedReceiverViewingKey: fixture.BlindedReceiverViewingKey,
				},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{TXOsImported: 1})

	txo, ok, err := store.GetTXO(context.Background(), nullifierHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected imported txo")
	}
	assertImportedTXO(t, txo, importedTXOExpected{
		TXIDVersion:      railcrypto.TXIDVersionV3PoseidonMerkle,
		TXID:             "railgun-txid-v3",
		Nullifier:        nullifierHex,
		TokenHash:        fixture.TokenHash,
		Value:            fixture.Value,
		BlockNumber:      200,
		Tree:             2,
		Position:         7,
		CommitmentType:   railevents.CommitmentTypeTransactV3,
		MemoText:         loadWalletImportFixtures(t).TransactNoteFixtures.Inputs.MemoText,
		RecipientAddress: mustAddressFromScanKeys(t, fixture.Keys),
	})
}

func TestImportV3AccumulatedEventsIndexesRailgunTransactions(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	txidStore := railtxid.NewMemoryTransactionStore()
	txidTree := railtxid.NewMemoryMerkleTreeStore()
	commitment := mustImporterHex(t, big.NewInt(11))
	nullifier := mustImporterHex(t, big.NewInt(22))
	boundParamsHash := mustImporterHex(t, big.NewInt(33))
	expectedRailgunTxid, err := railtxid.RailgunTransactionIDHex([]string{nullifier}, []string{commitment}, boundParamsHash)
	if err != nil {
		t.Fatal(err)
	}

	summary, err := ImportV3AccumulatedEventsWithTXIDStores(ctx, store, txidStore, txidTree, testSyncKeys(), railevents.V3AccumulatorEvents{
		RailgunTransactionEvents: []railevents.RailgunTransactionV3{{
			Version:                   railevents.RailgunTransactionVersionV3,
			Txid:                      "0xevm",
			BlockNumber:               250,
			Commitments:               []string{commitment},
			Nullifiers:                []string{nullifier},
			BoundParamsHash:           boundParamsHash,
			UTXOTreeIn:                3,
			UTXOTreeOut:               4,
			UTXOBatchStartPositionOut: 5,
			VerificationHash:          "0xverification",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{RailgunTransactionsIndexed: 1, TXIDMerkleLeavesIndexed: 1})
	got, ok, err := txidStore.GetByRailgunTxid(ctx, expectedRailgunTxid)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected indexed railgun transaction")
	}
	if got.Txid != "0xevm" || got.BlockNumber != 250 || got.UTXOTreeIn != 3 {
		t.Fatalf("unexpected indexed transaction %+v", got)
	}
	if len(got.Commitments) != 1 || got.Commitments[0] != commitment {
		t.Fatalf("unexpected commitments %+v", got.Commitments)
	}
	leaf, ok, err := txidTree.GetLeaf(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected indexed txid merkle leaf")
	}
	if leaf.RailgunTxid != expectedRailgunTxid || leaf.BlockNumber != 250 {
		t.Fatalf("unexpected txid merkle leaf %+v", leaf)
	}
	proof, err := txidTree.Proof(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := merkletree.VerifyProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("expected txid merkle proof to verify")
	}
}

func TestImportAccumulatedEventsIndexesUTXOMerkleTree(t *testing.T) {
	ctx := context.Background()
	keys := testSyncKeys()
	hashV2 := mustImporterHex(t, big.NewInt(44))
	hashV3 := mustImporterHex(t, big.NewInt(45))

	v2Tree := railutxotree.NewMemoryStore()
	summary, err := ImportV2AccumulatedEventsWithAllStores(ctx, NewMemoryStateStore(), nil, v2Tree, keys, railevents.V2AccumulatedEvents{
		CommitmentEvents: []railevents.CommitmentEvent{{
			Commitments: []railevents.Commitment{{
				CommitmentType: railevents.CommitmentTypeTransactV2,
				Hash:           hashV2,
				Txid:           "0xv2",
				BlockNumber:    270,
				UTXOTree:       1,
				UTXOIndex:      4,
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{UTXOMerkleLeavesIndexed: 1, CommitmentsSkipped: 1})
	leaf, ok, err := v2Tree.GetLeaf(ctx, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || leaf.Hash != hashV2 || leaf.TXID != "0xv2" {
		t.Fatalf("unexpected V2 utxo tree leaf %+v", leaf)
	}

	v3Tree := railutxotree.NewMemoryStore()
	summary, err = ImportV3AccumulatedEventsWithAllStores(ctx, NewMemoryStateStore(), nil, nil, v3Tree, nil, keys, railevents.V3AccumulatorEvents{
		CommitmentEvents: []railevents.V3CommitmentEvent{{
			Commitments: []railevents.V3Commitment{{
				CommitmentType: railevents.CommitmentTypeTransactV3,
				Hash:           hashV3,
				Txid:           "0xv3",
				BlockNumber:    280,
				UTXOTree:       2,
				UTXOIndex:      5,
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{UTXOMerkleLeavesIndexed: 1, CommitmentsSkipped: 1})
	proof, err := v3Tree.Proof(ctx, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := merkletree.VerifyProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("expected indexed UTXO proof to verify")
	}
}

func TestImportV3AccumulatedEventsIndexesUnshieldEventFeeIntoRailgunTransaction(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	txidStore := railtxid.NewMemoryTransactionStore()
	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	commitment := mustImporterHex(t, big.NewInt(11))
	nullifier := mustImporterHex(t, big.NewInt(22))
	boundParamsHash := mustImporterHex(t, big.NewInt(33))
	expectedRailgunTxid, err := railtxid.RailgunTransactionIDHex([]string{nullifier}, []string{commitment}, boundParamsHash)
	if err != nil {
		t.Fatal(err)
	}

	summary, err := ImportV3AccumulatedEventsWithTXIDStore(ctx, store, txidStore, testSyncKeys(), railevents.V3AccumulatorEvents{
		RailgunTransactionEvents: []railevents.RailgunTransactionV3{{
			Version:         railevents.RailgunTransactionVersionV3,
			Txid:            "0xevm",
			BlockNumber:     260,
			Commitments:     []string{commitment},
			Nullifiers:      []string{nullifier},
			BoundParamsHash: boundParamsHash,
			Unshield: &railevents.UnshieldRailgunTransactionData{
				TokenData: tokenData,
				ToAddress: "0x2222222222222222222222222222222222222222",
				Value:     "10",
			},
		}},
		UnshieldEvents: []railevents.UnshieldStoredEvent{{
			Txid:         "0xevm",
			RailgunTxid:  expectedRailgunTxid,
			ToAddress:    "0x2222222222222222222222222222222222222222",
			TokenType:    tokenData.TokenType,
			TokenAddress: tokenData.TokenAddress,
			TokenSubID:   tokenData.TokenSubID,
			Amount:       "8",
			Fee:          "2",
			BlockNumber:  260,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{RailgunTransactionsIndexed: 1})
	got, ok, err := txidStore.GetByRailgunTxid(ctx, expectedRailgunTxid)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Unshield == nil {
		t.Fatalf("expected indexed unshield transaction, got %+v", got)
	}
	if got.Unshield.Value != "8" || got.Unshield.Fee != "2" {
		t.Fatalf("expected unshield event amount/fee, got %+v", got.Unshield)
	}
}

func TestImportV3AccumulatedEventsIndexesUnshieldPOIEvents(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	spentPOIEvents := NewMemorySpentPOIEventStore()

	summary, err := ImportV3AccumulatedEventsWithStores(ctx, store, nil, nil, spentPOIEvents, testSyncKeys(), railevents.V3AccumulatorEvents{
		UnshieldEvents: []railevents.UnshieldStoredEvent{{
			Txid:        "0xevm",
			RailgunTxid: "railgun",
			BlockNumber: 300,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{UnshieldPOIEventsIndexed: 1})
	unshieldEvents, err := spentPOIEvents.ListUnshieldPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unshieldEvents) != 1 || unshieldEvents[0].TXID != "0xevm" || unshieldEvents[0].RailgunTxid != "railgun" || unshieldEvents[0].BlockNumber != 300 {
		t.Fatalf("unexpected indexed unshield poi events %+v", unshieldEvents)
	}
}

func TestImportV3AccumulatedEventsIndexesSentCommitmentPOIEvents(t *testing.T) {
	ctx := context.Background()
	fixture := buildWalletImportFixture(t)
	store := NewMemoryStateStore()
	spentPOIEvents := NewMemorySpentPOIEventStore()
	nullifier := mustImporterHex(t, big.NewInt(22))
	boundParamsHash := mustImporterHex(t, big.NewInt(33))
	expectedRailgunTxid, err := railtxid.RailgunTransactionIDHex([]string{nullifier}, []string{fixture.CommitmentHash}, boundParamsHash)
	if err != nil {
		t.Fatal(err)
	}
	batchIndex := 0

	summary, err := ImportV3AccumulatedEventsWithStores(ctx, store, nil, nil, spentPOIEvents, fixture.SenderKeys, railevents.V3AccumulatorEvents{
		RailgunTransactionEvents: []railevents.RailgunTransactionV3{{
			Version:         railevents.RailgunTransactionVersionV3,
			Txid:            "0xevm",
			BlockNumber:     350,
			Commitments:     []string{fixture.CommitmentHash},
			Nullifiers:      []string{nullifier},
			BoundParamsHash: boundParamsHash,
		}},
		CommitmentEvents: []railevents.V3CommitmentEvent{{
			Commitments: []railevents.V3Commitment{{
				CommitmentType:               railevents.CommitmentTypeTransactV3,
				Hash:                         fixture.CommitmentHash,
				Txid:                         "0xevm",
				BlockNumber:                  350,
				UTXOTree:                     2,
				UTXOIndex:                    7,
				SenderCiphertext:             fixture.V3.AnnotationData,
				TransactCommitmentBatchIndex: &batchIndex,
				Ciphertext: &railevents.CommitmentCiphertextV3Event{
					Ciphertext:                fixture.V3.NoteCiphertext,
					BlindedSenderViewingKey:   fixture.BlindedSenderViewingKey,
					BlindedReceiverViewingKey: fixture.BlindedReceiverViewingKey,
				},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{SentCommitmentPOIEventsIndexed: 1})
	txos, err := store.ListTXOs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(txos) != 0 {
		t.Fatalf("expected sent commitment to stay out of TXO state, got %+v", txos)
	}
	sentEvents, err := spentPOIEvents.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sentEvents) != 1 {
		t.Fatalf("expected one sent commitment POI event, got %+v", sentEvents)
	}
	event := sentEvents[0]
	if event.TXID != "0xevm" || event.RailgunTxid != expectedRailgunTxid || event.BlockNumber != 350 {
		t.Fatalf("unexpected sent commitment event identity %+v", event)
	}
	if event.CommitmentHash != fixture.CommitmentHash || event.BlindedCommitment == "" {
		t.Fatalf("unexpected sent commitment event commitment fields %+v", event)
	}
	if event.Value == nil || event.Value.String() != fixture.Value {
		t.Fatalf("expected sent value %s, got %v", fixture.Value, event.Value)
	}
	if event.WalletSource != loadWalletImportFixtures(t).TransactNoteFixtures.Inputs.WalletSource || event.MemoText != loadWalletImportFixtures(t).TransactNoteFixtures.Inputs.MemoText {
		t.Fatalf("unexpected sent annotations %+v", event)
	}
	if event.RecipientAddress != mustAddressFromScanKeys(t, fixture.Keys) || event.SenderAddress != mustAddressFromScanKeys(t, fixture.SenderKeys) {
		t.Fatalf("unexpected sent addresses %+v", event)
	}
}

func TestImportV2AccumulatedEventsIndexesSpentPOIEvents(t *testing.T) {
	ctx := context.Background()
	fixture := buildWalletImportFixture(t)
	store := NewMemoryStateStore()
	spentPOIEvents := NewMemorySpentPOIEventStore()

	summary, err := ImportV2AccumulatedEventsWithStores(ctx, store, spentPOIEvents, fixture.SenderKeys, railevents.V2AccumulatedEvents{
		CommitmentEvents: []railevents.CommitmentEvent{{
			Commitments: []railevents.Commitment{{
				CommitmentType: railevents.CommitmentTypeTransactV2,
				Hash:           fixture.CommitmentHash,
				Txid:           "0xevm",
				BlockNumber:    360,
				UTXOTree:       1,
				UTXOIndex:      6,
				Ciphertext: &railevents.CommitmentCiphertextV2Event{
					Ciphertext:                fixture.V2.NoteCiphertext,
					BlindedSenderViewingKey:   fixture.BlindedSenderViewingKey,
					BlindedReceiverViewingKey: fixture.BlindedReceiverViewingKey,
					AnnotationData:            fixture.V2.AnnotationData,
					Memo:                      fixture.V2.NoteMemo,
				},
			}},
		}},
		UnshieldEvents: []railevents.UnshieldStoredEvent{{
			Txid:        "0xunshield",
			BlockNumber: 361,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{SentCommitmentPOIEventsIndexed: 1, UnshieldPOIEventsIndexed: 1})
	txos, err := store.ListTXOs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(txos) != 0 {
		t.Fatalf("expected sent commitment to stay out of TXO state, got %+v", txos)
	}
	sentEvents, err := spentPOIEvents.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sentEvents) != 1 {
		t.Fatalf("expected one sent commitment event, got %+v", sentEvents)
	}
	if sentEvents[0].TXID != "0xevm" || sentEvents[0].RailgunTxid != "0xevm" || sentEvents[0].Value.String() != fixture.Value {
		t.Fatalf("unexpected V2 sent event %+v", sentEvents[0])
	}
	if sentEvents[0].WalletSource != loadWalletImportFixtures(t).TransactNoteFixtures.Inputs.WalletSource || sentEvents[0].MemoText != loadWalletImportFixtures(t).TransactNoteFixtures.Inputs.MemoText {
		t.Fatalf("unexpected V2 sent annotations %+v", sentEvents[0])
	}
	if sentEvents[0].RecipientAddress != mustAddressFromScanKeys(t, fixture.Keys) || sentEvents[0].SenderAddress != mustAddressFromScanKeys(t, fixture.SenderKeys) {
		t.Fatalf("unexpected V2 sent addresses %+v", sentEvents[0])
	}
	unshieldEvents, err := spentPOIEvents.ListUnshieldPOIEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unshieldEvents) != 1 || unshieldEvents[0].TXID != "0xunshield" || unshieldEvents[0].RailgunTxid != "0xunshield" {
		t.Fatalf("unexpected V2 unshield event %+v", unshieldEvents)
	}
}

func TestImportV2AccumulatedEventsImportsShieldCommitment(t *testing.T) {
	fixture := loadWalletImportFixtures(t).ShieldFixtures.ShieldNote
	keys := shieldScanKeys(t, fixture)
	nullifierHex := expectedNullifierHex(t, keys.NullifyingKey, 1, 9)
	commitmentHash := shieldCommitmentHashHex(t, fixture.Request.Preimage)
	chainPreimage := fixture.Request.Preimage
	chainValue, err := railcrypto.BigIntToHex(mustImporterDec(t, fixture.Request.Preimage.Value), 16, false)
	if err != nil {
		t.Fatal(err)
	}
	chainPreimage.Value = chainValue
	store := NewMemoryStateStore()

	summary, err := ImportV2AccumulatedEvents(context.Background(), store, keys, railevents.V2AccumulatedEvents{
		CommitmentEvents: []railevents.CommitmentEvent{{
			Commitments: []railevents.Commitment{{
				CommitmentType:  railevents.CommitmentTypeShield,
				Hash:            commitmentHash,
				Txid:            "shield-txid-v2",
				BlockNumber:     300,
				UTXOTree:        1,
				UTXOIndex:       9,
				PreImage:        shieldPreImage(chainPreimage),
				EncryptedBundle: fixture.Request.Ciphertext.EncryptedBundle[:],
				ShieldKey:       fixture.Request.Ciphertext.ShieldKey,
				Fee:             "4",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{TXOsImported: 1})

	txo, ok, err := store.GetTXO(context.Background(), nullifierHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected imported shield txo")
	}
	tokenHash, err := railcrypto.TokenDataHash(fixture.Request.Preimage.Token)
	if err != nil {
		t.Fatal(err)
	}
	assertImportedTXO(t, txo, importedTXOExpected{
		TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
		TXID:           "shield-txid-v2",
		Nullifier:      nullifierHex,
		TokenHash:      tokenHash,
		Value:          fixture.Request.Preimage.Value,
		BlockNumber:    300,
		Tree:           1,
		Position:       9,
		CommitmentType: railevents.CommitmentTypeShield,
		ShieldFee:      "4",
	})
}

func TestImportV3AccumulatedEventsImportsShieldCommitment(t *testing.T) {
	fixture := loadWalletImportFixtures(t).ShieldFixtures.ShieldNote
	keys := shieldScanKeys(t, fixture)
	nullifierHex := expectedNullifierHex(t, keys.NullifyingKey, 2, 10)
	commitmentHash := shieldCommitmentHashHex(t, fixture.Request.Preimage)
	store := NewMemoryStateStore()

	summary, err := ImportV3AccumulatedEvents(context.Background(), store, keys, railevents.V3AccumulatorEvents{
		CommitmentEvents: []railevents.V3CommitmentEvent{{
			Commitments: []railevents.V3Commitment{{
				CommitmentType:  railevents.CommitmentTypeShield,
				Hash:            commitmentHash,
				Txid:            "shield-txid-v3",
				BlockNumber:     400,
				UTXOTree:        2,
				UTXOIndex:       10,
				PreImage:        shieldPreImage(fixture.Request.Preimage),
				EncryptedBundle: fixture.Request.Ciphertext.EncryptedBundle[:],
				ShieldKey:       fixture.Request.Ciphertext.ShieldKey,
				Fee:             "5",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{TXOsImported: 1})

	txo, ok, err := store.GetTXO(context.Background(), nullifierHex)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected imported shield txo")
	}
	tokenHash, err := railcrypto.TokenDataHash(fixture.Request.Preimage.Token)
	if err != nil {
		t.Fatal(err)
	}
	assertImportedTXO(t, txo, importedTXOExpected{
		TXIDVersion:    railcrypto.TXIDVersionV3PoseidonMerkle,
		TXID:           "shield-txid-v3",
		Nullifier:      nullifierHex,
		TokenHash:      tokenHash,
		Value:          fixture.Request.Preimage.Value,
		BlockNumber:    400,
		Tree:           2,
		Position:       10,
		CommitmentType: railevents.CommitmentTypeShield,
		ShieldFee:      "5",
	})
}

func TestImportV2AccumulatedEventsSkipsUndecryptableCommitments(t *testing.T) {
	fixture := buildWalletImportFixture(t)
	keys := fixture.Keys
	store := NewMemoryStateStore()
	summary, err := ImportV2AccumulatedEvents(context.Background(), store, keys, railevents.V2AccumulatedEvents{
		CommitmentEvents: []railevents.CommitmentEvent{{
			Commitments: []railevents.Commitment{{
				CommitmentType: railevents.CommitmentTypeTransactV2,
				Hash:           fixture.CommitmentHash,
				BlockNumber:    100,
				UTXOTree:       0,
				UTXOIndex:      4,
				Ciphertext: &railevents.CommitmentCiphertextV2Event{
					Ciphertext:                fixture.V2.NoteCiphertext,
					BlindedSenderViewingKey:   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
					BlindedReceiverViewingKey: fixture.BlindedReceiverViewingKey,
					AnnotationData:            fixture.V2.AnnotationData,
					Memo:                      fixture.V2.NoteMemo,
				},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, summary, ImportSummary{CommitmentsSkipped: 1})
	txos, err := store.ListTXOs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(txos) != 0 {
		t.Fatalf("expected no imported txos, got %+v", txos)
	}
}

type walletImportFixtures struct {
	TransactNoteFixtures transactNoteImportFixtureSet `json:"transactNoteFixtures"`
	ShieldFixtures       shieldImportFixtureSet       `json:"shieldFixtures"`
}

type transactNoteImportFixtureSet struct {
	Inputs       transactNoteImportInputs    `json:"inputs"`
	V2           transactNoteImportV2        `json:"v2"`
	V3           transactNoteImportV3        `json:"v3"`
	NoteBlinding transactNoteImportBlinding  `json:"noteBlinding"`
	Decrypted    transactNoteImportDecrypted `json:"decrypted"`
}

type transactNoteImportInputs struct {
	ReceiverMasterPublicKey string               `json:"receiverMasterPublicKey"`
	SenderMasterPublicKey   string               `json:"senderMasterPublicKey"`
	Random                  string               `json:"random"`
	Value                   string               `json:"value"`
	SenderRandom            string               `json:"senderRandom"`
	ViewingPrivateKey       string               `json:"viewingPrivateKey"`
	OutputType              int                  `json:"outputType"`
	WalletSource            string               `json:"walletSource"`
	MemoText                string               `json:"memoText"`
	NoteCiphertextV2IV      string               `json:"noteCiphertextV2IV"`
	AnnotationV2IV          string               `json:"annotationV2IV"`
	NoteCiphertextV3Nonce   string               `json:"noteCiphertextV3Nonce"`
	AnnotationV3Nonce       string               `json:"annotationV3Nonce"`
	OrderedOutputTypes      []int                `json:"orderedOutputTypes"`
	TokenData               railcrypto.TokenData `json:"tokenData"`
}

type transactNoteImportV2 struct {
	NoteCiphertext railcrypto.CiphertextGCM `json:"noteCiphertext"`
	NoteMemo       string                   `json:"noteMemo"`
	AnnotationData string                   `json:"annotationData"`
}

type transactNoteImportV3 struct {
	NoteCiphertext railcrypto.CiphertextXChaCha `json:"noteCiphertext"`
	AnnotationData string                       `json:"annotationData"`
}

type transactNoteImportBlinding struct {
	BlindedSenderViewingKey   string `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string `json:"blindedReceiverViewingKey"`
}

type transactNoteImportDecrypted struct {
	V2Received decryptedImportNote `json:"v2Received"`
	V3Received decryptedImportNote `json:"v3Received"`
}

type decryptedImportNote struct {
	TokenHash string `json:"tokenHash"`
	Value     string `json:"value"`
	Hash      string `json:"hash"`
}

type shieldImportFixtureSet struct {
	ShieldNote shieldImportNote `json:"shieldNote"`
}

type shieldImportNote struct {
	MasterPublicKey          string              `json:"masterPublicKey"`
	ReceiverPrivateKey       string              `json:"receiverPrivateKey"`
	ReceiverViewingPublicKey string              `json:"receiverViewingPublicKey"`
	Request                  shieldImportRequest `json:"request"`
}

type shieldImportRequest struct {
	Preimage   shieldImportPreimage   `json:"preimage"`
	Ciphertext shieldImportCiphertext `json:"ciphertext"`
}

type shieldImportPreimage struct {
	NPK   string               `json:"npk"`
	Token railcrypto.TokenData `json:"token"`
	Value string               `json:"value"`
}

type shieldImportCiphertext struct {
	EncryptedBundle [3]string `json:"encryptedBundle"`
	ShieldKey       string    `json:"shieldKey"`
}

func loadWalletImportFixtures(t *testing.T) walletImportFixtures {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures walletImportFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

type generatedWalletImportFixture struct {
	Keys                      ScanKeys
	SenderKeys                ScanKeys
	V2                        railcrypto.TransactNoteV2Encryption
	V3                        railcrypto.TransactNoteV3Encryption
	BlindedSenderViewingKey   string
	BlindedReceiverViewingKey string
	CommitmentHash            string
	TokenHash                 string
	Value                     string
}

func buildWalletImportFixture(t *testing.T) generatedWalletImportFixture {
	t.Helper()
	fixture := loadWalletImportFixtures(t).TransactNoteFixtures
	receiverPrivateKey, err := railcrypto.HexToBytes(fixture.Inputs.ViewingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	senderPrivateKey, err := railcrypto.HexToBytes("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	if err != nil {
		t.Fatal(err)
	}
	receiverViewingPublicKey, err := railcrypto.PublicViewingKey(receiverPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	senderViewingPublicKey, err := railcrypto.PublicViewingKey(senderPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	blindedSender, blindedReceiver, err := railcrypto.NoteBlindingKeys(
		senderViewingPublicKey,
		receiverViewingPublicKey,
		fixture.Inputs.Random,
		fixture.Inputs.SenderRandom,
	)
	if err != nil {
		t.Fatal(err)
	}
	sharedKey, err := railcrypto.SharedSymmetricKey(receiverPrivateKey, blindedSender)
	if err != nil {
		t.Fatal(err)
	}
	value := mustImporterDec(t, fixture.Inputs.Value)
	inputs := railcrypto.TransactNoteEncryptionInputs{
		ReceiverMasterPublicKey: mustImporterDec(t, fixture.Inputs.ReceiverMasterPublicKey),
		SenderMasterPublicKey:   mustImporterDec(t, fixture.Inputs.SenderMasterPublicKey),
		Random:                  fixture.Inputs.Random,
		Value:                   value,
		TokenData:               fixture.Inputs.TokenData,
		SenderRandom:            fixture.Inputs.SenderRandom,
		SharedKey:               sharedKey,
		ViewingPrivateKey:       senderPrivateKey,
		OutputType:              fixture.Inputs.OutputType,
		WalletSource:            fixture.Inputs.WalletSource,
		MemoText:                fixture.Inputs.MemoText,
	}
	v2, err := railcrypto.EncryptTransactNoteV2(inputs, fixture.Inputs.NoteCiphertextV2IV, fixture.Inputs.AnnotationV2IV)
	if err != nil {
		t.Fatal(err)
	}
	v3, err := railcrypto.EncryptTransactNoteV3(
		inputs,
		fixture.Inputs.NoteCiphertextV3Nonce,
		fixture.Inputs.AnnotationV3Nonce,
		fixture.Inputs.OrderedOutputTypes,
	)
	if err != nil {
		t.Fatal(err)
	}
	notePublicKey, err := railcrypto.NotePublicKey(inputs.ReceiverMasterPublicKey, inputs.Random)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(inputs.TokenData)
	if err != nil {
		t.Fatal(err)
	}
	commitmentHash, err := railcrypto.NoteHash(notePublicKey, tokenHash, value)
	if err != nil {
		t.Fatal(err)
	}
	return generatedWalletImportFixture{
		Keys: ScanKeys{
			MasterPublicKey:   inputs.ReceiverMasterPublicKey,
			ViewingPrivateKey: receiverPrivateKey,
			ViewingPublicKey:  receiverViewingPublicKey,
			NullifyingKey:     big.NewInt(1234567890),
			TokenDataByHash: map[string]railcrypto.TokenData{
				tokenHash: fixture.Inputs.TokenData,
			},
		},
		SenderKeys: ScanKeys{
			MasterPublicKey:   inputs.SenderMasterPublicKey,
			ViewingPrivateKey: senderPrivateKey,
			ViewingPublicKey:  senderViewingPublicKey,
			NullifyingKey:     big.NewInt(9876543210),
			TokenDataByHash: map[string]railcrypto.TokenData{
				tokenHash: fixture.Inputs.TokenData,
			},
		},
		V2:                        v2,
		V3:                        v3,
		BlindedSenderViewingKey:   railcrypto.BytesToHex(blindedSender, false),
		BlindedReceiverViewingKey: railcrypto.BytesToHex(blindedReceiver, false),
		CommitmentHash:            mustImporterHex(t, commitmentHash),
		TokenHash:                 tokenHash,
		Value:                     fixture.Inputs.Value,
	}
}

func shieldScanKeys(t *testing.T, fixture shieldImportNote) ScanKeys {
	t.Helper()
	viewingPrivateKey, err := railcrypto.HexToBytes(fixture.ReceiverPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	viewingPublicKey, err := railcrypto.HexToBytes(fixture.ReceiverViewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return ScanKeys{
		MasterPublicKey:   mustImporterDec(t, fixture.MasterPublicKey),
		ViewingPrivateKey: viewingPrivateKey,
		ViewingPublicKey:  viewingPublicKey,
		NullifyingKey:     big.NewInt(1234567890),
	}
}

func shieldPreImage(preimage shieldImportPreimage) *railevents.PreImage {
	return &railevents.PreImage{
		NPK:   preimage.NPK,
		Token: preimage.Token,
		Value: preimage.Value,
	}
}

func shieldCommitmentHashHex(t *testing.T, preimage shieldImportPreimage) string {
	t.Helper()
	npk, err := railcrypto.HexToBigInt(preimage.NPK)
	if err != nil {
		t.Fatal(err)
	}
	value := mustImporterDec(t, preimage.Value)
	hash, err := railcrypto.NoteHashFromTokenData(npk, preimage.Token, value)
	if err != nil {
		t.Fatal(err)
	}
	return mustImporterHex(t, hash)
}

func receiverScanKeys(t *testing.T, fixture transactNoteImportFixtureSet) ScanKeys {
	t.Helper()
	viewingPrivateKey, err := railcrypto.HexToBytes(fixture.Inputs.ViewingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	viewingPublicKey, err := railcrypto.PublicViewingKey(viewingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return ScanKeys{
		MasterPublicKey:   mustImporterDec(t, fixture.Inputs.ReceiverMasterPublicKey),
		ViewingPrivateKey: viewingPrivateKey,
		ViewingPublicKey:  viewingPublicKey,
		NullifyingKey:     big.NewInt(1234567890),
		TokenDataByHash: map[string]railcrypto.TokenData{
			fixture.Decrypted.V2Received.TokenHash: fixture.Inputs.TokenData,
		},
	}
}

func expectedNullifierHex(t *testing.T, nullifyingKey *big.Int, tree uint64, position uint64) string {
	t.Helper()
	global := railtxid.GetGlobalTreePosition(tree, position)
	if !global.IsUint64() {
		t.Fatal("global tree position exceeds uint64")
	}
	nullifier, err := railcrypto.Nullifier(nullifyingKey, global.Uint64())
	if err != nil {
		t.Fatal(err)
	}
	return mustImporterHex(t, nullifier)
}

func mustImporterHex(t *testing.T, value *big.Int) string {
	t.Helper()
	out, err := railcrypto.BigIntToHex(value, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mustImporterDec(t *testing.T, value string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid decimal %s", value)
	}
	return n
}

func mustAddressFromScanKeys(t *testing.T, keys ScanKeys) string {
	t.Helper()
	encoded, err := encodeTransactNoteAddressData(currentWalletAddressData(keys))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type importedTXOExpected struct {
	TXIDVersion      string
	TXID             string
	Nullifier        string
	TokenHash        string
	Value            string
	BlockNumber      uint64
	Tree             uint64
	Position         uint64
	CommitmentType   string
	WalletSource     string
	MemoText         string
	SenderAddress    string
	RecipientAddress string
	ShieldFee        string
	SpendTXID        string
	SpendBlockNumber uint64
}

func assertImportedTXO(t *testing.T, txo StoredTXO, expected importedTXOExpected) {
	t.Helper()
	if txo.TXIDVersion != expected.TXIDVersion {
		t.Fatalf("expected txid version %s, got %s", expected.TXIDVersion, txo.TXIDVersion)
	}
	if txo.TXID != expected.TXID {
		t.Fatalf("expected txid %s, got %s", expected.TXID, txo.TXID)
	}
	if txo.Nullifier != expected.Nullifier {
		t.Fatalf("expected nullifier %s, got %s", expected.Nullifier, txo.Nullifier)
	}
	if txo.CommitmentHash == "" {
		t.Fatal("expected commitment hash")
	}
	if txo.NotePublicKey == "" {
		t.Fatal("expected note public key")
	}
	if txo.NoteRandom == "" {
		t.Fatal("expected note random")
	}
	if txo.TokenHash != expected.TokenHash {
		t.Fatalf("expected token hash %s, got %s", expected.TokenHash, txo.TokenHash)
	}
	if txo.Value == nil || txo.Value.String() != expected.Value {
		t.Fatalf("expected value %s, got %v", expected.Value, txo.Value)
	}
	if txo.BlockNumber != expected.BlockNumber || txo.Tree != expected.Tree || txo.Position != expected.Position {
		t.Fatalf("unexpected position fields %+v", txo)
	}
	if txo.CommitmentType != expected.CommitmentType {
		t.Fatalf("expected commitment type %s, got %s", expected.CommitmentType, txo.CommitmentType)
	}
	if txo.WalletSource != expected.WalletSource {
		t.Fatalf("expected wallet source %s, got %s", expected.WalletSource, txo.WalletSource)
	}
	if txo.MemoText != expected.MemoText {
		t.Fatalf("expected memo text %s, got %s", expected.MemoText, txo.MemoText)
	}
	if txo.SenderAddress != expected.SenderAddress {
		t.Fatalf("expected sender address %s, got %s", expected.SenderAddress, txo.SenderAddress)
	}
	if txo.RecipientAddress != expected.RecipientAddress {
		t.Fatalf("expected recipient address %s, got %s", expected.RecipientAddress, txo.RecipientAddress)
	}
	if txo.ShieldFee != expected.ShieldFee {
		t.Fatalf("expected shield fee %s, got %s", expected.ShieldFee, txo.ShieldFee)
	}
	if txo.SpendTXID != expected.SpendTXID {
		t.Fatalf("expected spend txid %s, got %s", expected.SpendTXID, txo.SpendTXID)
	}
	if expected.SpendBlockNumber == 0 {
		if txo.SpendBlockNumber != nil {
			t.Fatalf("expected no spend block, got %d", *txo.SpendBlockNumber)
		}
	} else if txo.SpendBlockNumber == nil || *txo.SpendBlockNumber != expected.SpendBlockNumber {
		t.Fatalf("expected spend block %d, got %v", expected.SpendBlockNumber, txo.SpendBlockNumber)
	}
	if txo.BlindedCommitment == "" {
		t.Fatal("expected blinded commitment")
	}
}
