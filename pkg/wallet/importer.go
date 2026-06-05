package wallet

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/bf30075/railgun-go/pkg/address"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railtransaction "github.com/bf30075/railgun-go/pkg/transaction"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
)

type ScanKeys struct {
	MasterPublicKey   *big.Int
	ViewingPrivateKey []byte
	ViewingPublicKey  []byte
	NullifyingKey     *big.Int
	TokenDataByHash   map[string]railcrypto.TokenData
}

type ImportSummary struct {
	TXOsImported                   int
	CommitmentsSkipped             int
	SpendsMarked                   int
	SpendsSkipped                  int
	RailgunTransactionsIndexed     int
	TXIDMerkleLeavesIndexed        int
	UTXOMerkleLeavesIndexed        int
	NullifierEventsIndexed         int
	UnshieldEventsIndexed          int
	SentCommitmentPOIEventsIndexed int
	UnshieldPOIEventsIndexed       int
}

func ImportV2AccumulatedEvents(ctx context.Context, store StateStore, keys ScanKeys, accumulated railevents.V2AccumulatedEvents) (ImportSummary, error) {
	return ImportV2AccumulatedEventsWithStores(ctx, store, nil, keys, accumulated)
}

func ImportV2AccumulatedEventsWithStores(ctx context.Context, store StateStore, spentPOIEvents SpentPOIEventStore, keys ScanKeys, accumulated railevents.V2AccumulatedEvents) (ImportSummary, error) {
	return ImportV2AccumulatedEventsWithAllStores(ctx, store, spentPOIEvents, nil, keys, accumulated)
}

func ImportV2AccumulatedEventsWithAllStores(ctx context.Context, store StateStore, spentPOIEvents SpentPOIEventStore, utxoTree railutxotree.Store, keys ScanKeys, accumulated railevents.V2AccumulatedEvents) (ImportSummary, error) {
	if err := validateImportInputs(store, keys); err != nil {
		return ImportSummary{}, err
	}
	summary := ImportSummary{}
	if utxoTree != nil {
		indexed, err := railutxotree.IndexV2CommitmentEvents(ctx, utxoTree, accumulated.CommitmentEvents)
		if err != nil {
			return ImportSummary{}, err
		}
		summary.UTXOMerkleLeavesIndexed = indexed
		if nullifierStore, ok := utxoTree.(railutxotree.NullifierEventStore); ok {
			indexed, err := nullifierStore.UpsertNullifiers(ctx, accumulated.NullifierEvents)
			if err != nil {
				return ImportSummary{}, err
			}
			summary.NullifierEventsIndexed = indexed
		}
		if unshieldStore, ok := utxoTree.(railutxotree.UnshieldEventStore); ok {
			indexed, err := unshieldStore.UpsertUnshieldEvents(ctx, accumulated.UnshieldEvents, false)
			if err != nil {
				return ImportSummary{}, err
			}
			summary.UnshieldEventsIndexed = indexed
		}
	}
	if spentPOIEvents != nil {
		for _, event := range accumulated.UnshieldEvents {
			if err := ctx.Err(); err != nil {
				return ImportSummary{}, err
			}
			if err := spentPOIEvents.UpsertUnshieldPOIEvent(ctx, unshieldPOIStatusFromV2Event(event)); err != nil {
				return ImportSummary{}, err
			}
			summary.UnshieldPOIEventsIndexed++
		}
	}
	for _, event := range accumulated.CommitmentEvents {
		for _, commitment := range event.Commitments {
			if err := ctx.Err(); err != nil {
				return ImportSummary{}, err
			}
			txo, isSent, ok, err := txoFromV2CommitmentWithDirection(keys, commitment)
			if err != nil {
				return ImportSummary{}, err
			}
			if !ok {
				summary.CommitmentsSkipped++
				continue
			}
			if isSent {
				if spentPOIEvents != nil {
					railgunTxid := firstNonEmpty(commitment.RailgunTxid, txo.TXID)
					if err := spentPOIEvents.UpsertSentCommitmentPOIEvent(ctx, sentCommitmentPOIStatusFromTXO(txo, commitment.Txid, railgunTxid)); err != nil {
						return ImportSummary{}, err
					}
					summary.SentCommitmentPOIEventsIndexed++
				}
				continue
			}
			if err := store.UpsertTXO(ctx, txo); err != nil {
				return ImportSummary{}, err
			}
			summary.TXOsImported++
		}
	}
	if err := markNullifiersSpent(ctx, store, accumulated.NullifierEvents, &summary); err != nil {
		return ImportSummary{}, err
	}
	return summary, nil
}

func ImportV3AccumulatedEvents(ctx context.Context, store StateStore, keys ScanKeys, accumulated railevents.V3AccumulatorEvents) (ImportSummary, error) {
	return ImportV3AccumulatedEventsWithTXIDStore(ctx, store, nil, keys, accumulated)
}

func ImportV3AccumulatedEventsWithTXIDStore(ctx context.Context, store StateStore, txidStore railtxid.TransactionStore, keys ScanKeys, accumulated railevents.V3AccumulatorEvents) (ImportSummary, error) {
	return ImportV3AccumulatedEventsWithTXIDStores(ctx, store, txidStore, nil, keys, accumulated)
}

func ImportV3AccumulatedEventsWithTXIDStores(ctx context.Context, store StateStore, txidStore railtxid.TransactionStore, txidMerkleTree railtxid.MerkleTreeStore, keys ScanKeys, accumulated railevents.V3AccumulatorEvents) (ImportSummary, error) {
	return ImportV3AccumulatedEventsWithStores(ctx, store, txidStore, txidMerkleTree, nil, keys, accumulated)
}

func ImportV3AccumulatedEventsWithStores(ctx context.Context, store StateStore, txidStore railtxid.TransactionStore, txidMerkleTree railtxid.MerkleTreeStore, spentPOIEvents SpentPOIEventStore, keys ScanKeys, accumulated railevents.V3AccumulatorEvents) (ImportSummary, error) {
	return ImportV3AccumulatedEventsWithAllStores(ctx, store, txidStore, txidMerkleTree, nil, spentPOIEvents, keys, accumulated)
}

func ImportV3AccumulatedEventsWithAllStores(ctx context.Context, store StateStore, txidStore railtxid.TransactionStore, txidMerkleTree railtxid.MerkleTreeStore, utxoTree railutxotree.Store, spentPOIEvents SpentPOIEventStore, keys ScanKeys, accumulated railevents.V3AccumulatorEvents) (ImportSummary, error) {
	if err := validateImportInputs(store, keys); err != nil {
		return ImportSummary{}, err
	}
	summary := ImportSummary{}
	if utxoTree != nil {
		indexed, err := railutxotree.IndexV3CommitmentEvents(ctx, utxoTree, accumulated.CommitmentEvents)
		if err != nil {
			return ImportSummary{}, err
		}
		summary.UTXOMerkleLeavesIndexed = indexed
		if nullifierStore, ok := utxoTree.(railutxotree.NullifierEventStore); ok {
			indexed, err := nullifierStore.UpsertNullifiers(ctx, accumulated.NullifierEvents)
			if err != nil {
				return ImportSummary{}, err
			}
			summary.NullifierEventsIndexed = indexed
		}
		if unshieldStore, ok := utxoTree.(railutxotree.UnshieldEventStore); ok {
			indexed, err := unshieldStore.UpsertUnshieldEvents(ctx, accumulated.UnshieldEvents, false)
			if err != nil {
				return ImportSummary{}, err
			}
			summary.UnshieldEventsIndexed = indexed
		}
	}
	railgunTxidsByCommitment := map[string]string{}
	unshieldEventsByRailgunTxid, unshieldEventsByTxid := unshieldEventMaps(accumulated.UnshieldEvents)
	if txidStore != nil || txidMerkleTree != nil || spentPOIEvents != nil {
		for _, transaction := range accumulated.RailgunTransactionEvents {
			if err := ctx.Err(); err != nil {
				return ImportSummary{}, err
			}
			stored, err := storedRailgunTransactionV3(transaction, unshieldEventsByRailgunTxid, unshieldEventsByTxid)
			if err != nil {
				return ImportSummary{}, err
			}
			for _, commitment := range stored.Commitments {
				railgunTxidsByCommitment[normalizedHex(commitment)] = stored.RailgunTxid
			}
			if txidStore != nil {
				if err := txidStore.UpsertTransaction(ctx, stored); err != nil {
					return ImportSummary{}, err
				}
				summary.RailgunTransactionsIndexed++
			}
			if txidMerkleTree != nil {
				if _, err := railtxid.AppendTransactionLeaf(ctx, txidMerkleTree, stored); err != nil {
					return ImportSummary{}, err
				}
				summary.TXIDMerkleLeavesIndexed++
			}
		}
	}
	if spentPOIEvents != nil {
		for _, event := range accumulated.UnshieldEvents {
			if err := ctx.Err(); err != nil {
				return ImportSummary{}, err
			}
			if err := spentPOIEvents.UpsertUnshieldPOIEvent(ctx, unshieldPOIStatusFromEvent(event)); err != nil {
				return ImportSummary{}, err
			}
			summary.UnshieldPOIEventsIndexed++
		}
	}
	for _, event := range accumulated.CommitmentEvents {
		for _, commitment := range event.Commitments {
			if err := ctx.Err(); err != nil {
				return ImportSummary{}, err
			}
			txo, isSent, ok, err := txoFromV3CommitmentWithDirection(keys, commitment)
			if err != nil {
				return ImportSummary{}, err
			}
			if !ok {
				summary.CommitmentsSkipped++
				continue
			}
			if isSent {
				if spentPOIEvents != nil {
					railgunTxid := firstNonEmpty(commitment.RailgunTxid, railgunTxidsByCommitment[normalizedHex(txo.CommitmentHash)])
					if err := spentPOIEvents.UpsertSentCommitmentPOIEvent(ctx, sentCommitmentPOIStatusFromTXO(txo, commitment.Txid, railgunTxid)); err != nil {
						return ImportSummary{}, err
					}
					summary.SentCommitmentPOIEventsIndexed++
				}
				continue
			}
			if err := store.UpsertTXO(ctx, txo); err != nil {
				return ImportSummary{}, err
			}
			summary.TXOsImported++
		}
	}
	if err := markNullifiersSpent(ctx, store, accumulated.NullifierEvents, &summary); err != nil {
		return ImportSummary{}, err
	}
	return summary, nil
}

func unshieldPOIStatusFromEvent(event railevents.UnshieldStoredEvent) UnshieldPOIStatusInput {
	return UnshieldPOIStatusInput{
		TXID:        event.Txid,
		RailgunTxid: event.RailgunTxid,
		BlockNumber: event.BlockNumber,
	}
}

func unshieldPOIStatusFromV2Event(event railevents.UnshieldStoredEvent) UnshieldPOIStatusInput {
	return UnshieldPOIStatusInput{
		TXID:        event.Txid,
		RailgunTxid: firstNonEmpty(event.RailgunTxid, event.Txid),
		BlockNumber: event.BlockNumber,
	}
}

func sentCommitmentPOIStatusFromTXO(txo StoredTXO, txid string, railgunTxid string) SentCommitmentPOIStatusInput {
	return SentCommitmentPOIStatusInput{
		TXID:              txid,
		RailgunTxid:       railgunTxid,
		Timestamp:         cloneUint64Ptr(txo.Timestamp),
		BlockNumber:       txo.BlockNumber,
		CommitmentHash:    txo.CommitmentHash,
		BlindedCommitment: txo.BlindedCommitment,
		TokenHash:         txo.TokenHash,
		TokenData:         txo.TokenData,
		Value:             cloneBigInt(txo.Value),
		OutputType:        cloneIntPtr(txo.OutputType),
		WalletSource:      txo.WalletSource,
		MemoText:          txo.MemoText,
		SenderAddress:     txo.SenderAddress,
		RecipientAddress:  txo.RecipientAddress,
		POIsPerList:       clonePOIsPerList(txo.POIsPerList),
	}
}

func storedRailgunTransactionV3(transaction railevents.RailgunTransactionV3, unshieldEventsByRailgunTxid map[string]railevents.UnshieldStoredEvent, unshieldEventsByTxid map[string]railevents.UnshieldStoredEvent) (railtxid.Transaction, error) {
	railgunTxid, err := railtxid.RailgunTransactionIDHex(
		transaction.Nullifiers,
		transaction.Commitments,
		transaction.BoundParamsHash,
	)
	if err != nil {
		return railtxid.Transaction{}, err
	}
	var unshield *railtxid.UnshieldData
	if transaction.Unshield != nil {
		unshield = &railtxid.UnshieldData{
			TokenData: transaction.Unshield.TokenData,
			ToAddress: transaction.Unshield.ToAddress,
			Value:     transaction.Unshield.Value,
		}
		if event, ok := unshieldEventsByRailgunTxid[railgunTxid]; ok {
			applyUnshieldEventData(unshield, event)
		} else if event, ok := unshieldEventsByTxid[transaction.Txid]; ok {
			applyUnshieldEventData(unshield, event)
		}
	}
	return railtxid.Transaction{
		Version:                   transaction.Version,
		RailgunTxid:               railgunTxid,
		Txid:                      transaction.Txid,
		BlockNumber:               transaction.BlockNumber,
		Commitments:               append([]string(nil), transaction.Commitments...),
		Nullifiers:                append([]string(nil), transaction.Nullifiers...),
		BoundParamsHash:           transaction.BoundParamsHash,
		Unshield:                  unshield,
		UTXOTreeIn:                transaction.UTXOTreeIn,
		UTXOTreeOut:               transaction.UTXOTreeOut,
		UTXOBatchStartPositionOut: transaction.UTXOBatchStartPositionOut,
		VerificationHash:          transaction.VerificationHash,
	}, nil
}

func unshieldEventMaps(events []railevents.UnshieldStoredEvent) (map[string]railevents.UnshieldStoredEvent, map[string]railevents.UnshieldStoredEvent) {
	byRailgunTxid := map[string]railevents.UnshieldStoredEvent{}
	byTxid := map[string]railevents.UnshieldStoredEvent{}
	for _, event := range events {
		if event.RailgunTxid != "" {
			byRailgunTxid[event.RailgunTxid] = event
		}
		if event.Txid != "" {
			byTxid[event.Txid] = event
		}
	}
	return byRailgunTxid, byTxid
}

func applyUnshieldEventData(unshield *railtxid.UnshieldData, event railevents.UnshieldStoredEvent) {
	if event.Amount != "" {
		unshield.Value = event.Amount
	}
	unshield.Fee = event.Fee
	if event.ToAddress != "" {
		unshield.ToAddress = event.ToAddress
	}
}

func validateImportInputs(store StateStore, keys ScanKeys) error {
	if store == nil {
		return fmt.Errorf("state store is required")
	}
	if keys.MasterPublicKey == nil {
		return fmt.Errorf("master public key is required")
	}
	if len(keys.ViewingPrivateKey) == 0 {
		return fmt.Errorf("viewing private key is required")
	}
	if len(keys.ViewingPublicKey) == 0 {
		return fmt.Errorf("viewing public key is required")
	}
	if keys.NullifyingKey == nil {
		return fmt.Errorf("nullifying key is required")
	}
	return nil
}

func txoFromV2Commitment(keys ScanKeys, commitment railevents.Commitment) (StoredTXO, bool, error) {
	txo, _, ok, err := txoFromV2CommitmentWithDirection(keys, commitment)
	return txo, ok, err
}

func txoFromV2CommitmentWithDirection(keys ScanKeys, commitment railevents.Commitment) (StoredTXO, bool, bool, error) {
	if commitment.PreImage != nil {
		txo, ok, err := txoFromShieldCommitment(keys, shieldCommitmentData{
			Hash:            commitment.Hash,
			TXIDVersion:     railcrypto.TXIDVersionV2PoseidonMerkle,
			TXID:            commitment.Txid,
			Timestamp:       commitment.Timestamp,
			BlockNumber:     commitment.BlockNumber,
			Tree:            commitment.UTXOTree,
			Position:        commitment.UTXOIndex,
			CommitmentType:  commitment.CommitmentType,
			PreImage:        commitment.PreImage,
			EncryptedBundle: commitment.EncryptedBundle,
			ShieldKey:       commitment.ShieldKey,
			Fee:             commitment.Fee,
		})
		return txo, false, ok, err
	}
	if commitment.Ciphertext == nil {
		return StoredTXO{}, false, false, nil
	}
	blindedSender, err := railcrypto.HexToBytes(commitment.Ciphertext.BlindedSenderViewingKey)
	if err != nil {
		return StoredTXO{}, false, false, fmt.Errorf("blinded sender viewing key: %w", err)
	}
	blindedReceiver, err := railcrypto.HexToBytes(commitment.Ciphertext.BlindedReceiverViewingKey)
	if err != nil {
		return StoredTXO{}, false, false, fmt.Errorf("blinded receiver viewing key: %w", err)
	}
	blockNumber := commitment.BlockNumber
	isSent := false
	decrypted, ok := tryDecryptV2(keys, commitment, blindedSender, blindedReceiver, false, blockNumber)
	if !ok {
		decrypted, ok = tryDecryptV2(keys, commitment, blindedSender, blindedReceiver, true, blockNumber)
		isSent = ok
	}
	if !ok {
		return StoredTXO{}, false, false, nil
	}
	txo, ok, err := txoFromDecryptedCommitment(keys, decrypted, commitmentHashData{
		Hash:           commitment.Hash,
		TXIDVersion:    railcrypto.TXIDVersionV2PoseidonMerkle,
		TXID:           firstNonEmpty(commitment.RailgunTxid, commitment.Txid),
		Timestamp:      commitment.Timestamp,
		BlockNumber:    commitment.BlockNumber,
		Tree:           commitment.UTXOTree,
		Position:       commitment.UTXOIndex,
		CommitmentType: commitment.CommitmentType,
	})
	return txo, isSent, ok, err
}

func txoFromV3Commitment(keys ScanKeys, commitment railevents.V3Commitment) (StoredTXO, bool, error) {
	txo, _, ok, err := txoFromV3CommitmentWithDirection(keys, commitment)
	return txo, ok, err
}

func txoFromV3CommitmentWithDirection(keys ScanKeys, commitment railevents.V3Commitment) (StoredTXO, bool, bool, error) {
	if commitment.PreImage != nil {
		txo, ok, err := txoFromShieldCommitment(keys, shieldCommitmentData{
			Hash:            commitment.Hash,
			TXIDVersion:     railcrypto.TXIDVersionV3PoseidonMerkle,
			TXID:            commitment.Txid,
			Timestamp:       commitment.Timestamp,
			BlockNumber:     commitment.BlockNumber,
			Tree:            commitment.UTXOTree,
			Position:        commitment.UTXOIndex,
			CommitmentType:  commitment.CommitmentType,
			PreImage:        commitment.PreImage,
			EncryptedBundle: commitment.EncryptedBundle,
			ShieldKey:       commitment.ShieldKey,
			Fee:             commitment.Fee,
		})
		return txo, false, ok, err
	}
	if commitment.Ciphertext == nil {
		return StoredTXO{}, false, false, nil
	}
	blindedSender, err := railcrypto.HexToBytes(commitment.Ciphertext.BlindedSenderViewingKey)
	if err != nil {
		return StoredTXO{}, false, false, fmt.Errorf("blinded sender viewing key: %w", err)
	}
	blindedReceiver, err := railcrypto.HexToBytes(commitment.Ciphertext.BlindedReceiverViewingKey)
	if err != nil {
		return StoredTXO{}, false, false, fmt.Errorf("blinded receiver viewing key: %w", err)
	}
	blockNumber := commitment.BlockNumber
	batchIndex := 0
	if commitment.TransactCommitmentBatchIndex != nil {
		batchIndex = *commitment.TransactCommitmentBatchIndex
	}
	isSent := false
	decrypted, ok := tryDecryptV3(keys, commitment, blindedSender, blindedReceiver, false, blockNumber, batchIndex)
	if !ok {
		decrypted, ok = tryDecryptV3(keys, commitment, blindedSender, blindedReceiver, true, blockNumber, batchIndex)
		isSent = ok
	}
	if !ok {
		return StoredTXO{}, false, false, nil
	}
	txo, ok, err := txoFromDecryptedCommitment(keys, decrypted, commitmentHashData{
		Hash:           commitment.Hash,
		TXIDVersion:    railcrypto.TXIDVersionV3PoseidonMerkle,
		TXID:           firstNonEmpty(commitment.RailgunTxid, commitment.Txid),
		Timestamp:      commitment.Timestamp,
		BlockNumber:    commitment.BlockNumber,
		Tree:           commitment.UTXOTree,
		Position:       commitment.UTXOIndex,
		CommitmentType: commitment.CommitmentType,
	})
	return txo, isSent, ok, err
}

func tryDecryptV2(keys ScanKeys, commitment railevents.Commitment, blindedSender []byte, blindedReceiver []byte, isSent bool, blockNumber uint64) (railcrypto.DecryptedTransactNote, bool) {
	publicKey := blindedSender
	if isSent {
		publicKey = blindedReceiver
	}
	sharedKey, err := railcrypto.SharedSymmetricKey(keys.ViewingPrivateKey, publicKey)
	if err != nil {
		return railcrypto.DecryptedTransactNote{}, false
	}
	decrypted, err := railcrypto.DecryptTransactNoteV2(
		currentWalletAddressData(keys),
		commitment.Ciphertext.Ciphertext,
		sharedKey,
		commitment.Ciphertext.Memo,
		commitment.Ciphertext.AnnotationData,
		keys.ViewingPrivateKey,
		blindedReceiver,
		blindedSender,
		isSent,
		false,
		keys.TokenDataByHash,
		&blockNumber,
	)
	return decrypted, err == nil
}

func tryDecryptV3(keys ScanKeys, commitment railevents.V3Commitment, blindedSender []byte, blindedReceiver []byte, isSent bool, blockNumber uint64, batchIndex int) (railcrypto.DecryptedTransactNote, bool) {
	publicKey := blindedSender
	if isSent {
		publicKey = blindedReceiver
	}
	sharedKey, err := railcrypto.SharedSymmetricKey(keys.ViewingPrivateKey, publicKey)
	if err != nil {
		return railcrypto.DecryptedTransactNote{}, false
	}
	decrypted, err := railcrypto.DecryptTransactNoteV3(
		currentWalletAddressData(keys),
		commitment.Ciphertext.Ciphertext,
		sharedKey,
		commitment.SenderCiphertext,
		keys.ViewingPrivateKey,
		blindedReceiver,
		blindedSender,
		isSent,
		false,
		keys.TokenDataByHash,
		&blockNumber,
		batchIndex,
	)
	return decrypted, err == nil
}

type commitmentHashData struct {
	Hash           string
	TXIDVersion    string
	TXID           string
	Timestamp      *uint64
	BlockNumber    uint64
	Tree           int
	Position       int
	CommitmentType string
}

type shieldCommitmentData struct {
	Hash            string
	TXIDVersion     string
	TXID            string
	Timestamp       *uint64
	BlockNumber     uint64
	Tree            int
	Position        int
	CommitmentType  string
	PreImage        *railevents.PreImage
	EncryptedBundle []string
	ShieldKey       string
	Fee             string
}

func txoFromShieldCommitment(keys ScanKeys, data shieldCommitmentData) (StoredTXO, bool, error) {
	if data.PreImage == nil || len(data.EncryptedBundle) != 3 || data.ShieldKey == "" {
		return StoredTXO{}, false, nil
	}
	shieldKey, err := railcrypto.HexToBytes(data.ShieldKey)
	if err != nil {
		return StoredTXO{}, false, fmt.Errorf("shield key: %w", err)
	}
	sharedKey, err := railcrypto.SharedSymmetricKey(keys.ViewingPrivateKey, shieldKey)
	if err != nil {
		return StoredTXO{}, false, nil
	}
	random, err := railtransaction.DecryptShieldRandom(
		[3]string{data.EncryptedBundle[0], data.EncryptedBundle[1], data.EncryptedBundle[2]},
		sharedKey,
	)
	if err != nil {
		return StoredTXO{}, false, nil
	}
	notePublicKey, err := railcrypto.NotePublicKey(keys.MasterPublicKey, random)
	if err != nil {
		return StoredTXO{}, false, err
	}
	notePublicKeyHex, err := railcrypto.BigIntToHex(notePublicKey, 32, false)
	if err != nil {
		return StoredTXO{}, false, err
	}
	preimageNPK, err := railcrypto.FormatHexToByteLength(data.PreImage.NPK, 32, false)
	if err != nil {
		return StoredTXO{}, false, fmt.Errorf("shield npk: %w", err)
	}
	if preimageNPK != notePublicKeyHex {
		return StoredTXO{}, false, nil
	}
	value, err := shieldPreimageValue(data.PreImage.Value)
	if err != nil {
		return StoredTXO{}, false, fmt.Errorf("shield value: %w", err)
	}
	tokenHash, err := railcrypto.TokenDataHash(data.PreImage.Token)
	if err != nil {
		return StoredTXO{}, false, err
	}
	hash, err := railcrypto.NoteHash(notePublicKey, tokenHash, value)
	if err != nil {
		return StoredTXO{}, false, err
	}
	hashHex, err := railcrypto.BigIntToHex(hash, 32, false)
	if err != nil {
		return StoredTXO{}, false, err
	}
	if data.Hash != "" {
		expected, err := railcrypto.FormatHexToByteLength(data.Hash, 32, false)
		if err != nil {
			return StoredTXO{}, false, fmt.Errorf("commitment hash: %w", err)
		}
		if expected != hashHex {
			return StoredTXO{}, false, nil
		}
	}
	globalPosition, err := globalPosition(data.Tree, data.Position)
	if err != nil {
		return StoredTXO{}, false, err
	}
	nullifier, err := railcrypto.Nullifier(keys.NullifyingKey, globalPosition)
	if err != nil {
		return StoredTXO{}, false, err
	}
	nullifierHex, err := railcrypto.BigIntToHex(nullifier, 32, false)
	if err != nil {
		return StoredTXO{}, false, err
	}
	blindedCommitment, err := railcrypto.BlindedCommitment(hashHex, notePublicKey, railtxid.GetGlobalTreePosition(uint64(data.Tree), uint64(data.Position)))
	if err != nil {
		return StoredTXO{}, false, err
	}
	return StoredTXO{
		TXIDVersion:       data.TXIDVersion,
		Tree:              uint64(data.Tree),
		Position:          uint64(data.Position),
		TXID:              data.TXID,
		Timestamp:         cloneUint64Ptr(data.Timestamp),
		BlockNumber:       data.BlockNumber,
		Nullifier:         nullifierHex,
		CommitmentHash:    hashHex,
		NotePublicKey:     notePublicKeyHex,
		NoteRandom:        random,
		TokenHash:         tokenHash,
		TokenData:         data.PreImage.Token,
		Value:             value,
		ShieldFee:         data.Fee,
		CommitmentType:    data.CommitmentType,
		BlindedCommitment: blindedCommitment,
	}, true, nil
}

func shieldPreimageValue(value string) (*big.Int, error) {
	trimmed := strings.TrimSpace(value)
	stripped := railcrypto.Strip0x(trimmed)
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") || len(stripped) == 32 || hasHexLetters(stripped) {
		return railcrypto.HexToBigInt(trimmed)
	}
	return railcrypto.NumberishToBigInt(trimmed)
}

func hasHexLetters(value string) bool {
	for _, char := range value {
		if (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') {
			return true
		}
	}
	return false
}

func txoFromDecryptedCommitment(keys ScanKeys, decrypted railcrypto.DecryptedTransactNote, data commitmentHashData) (StoredTXO, bool, error) {
	hash, err := railcrypto.BigIntToHex(decrypted.Hash, 32, false)
	if err != nil {
		return StoredTXO{}, false, err
	}
	if data.Hash != "" {
		expected, err := railcrypto.FormatHexToByteLength(data.Hash, 32, false)
		if err != nil {
			return StoredTXO{}, false, fmt.Errorf("commitment hash: %w", err)
		}
		if expected != hash {
			return StoredTXO{}, false, nil
		}
	}
	globalPosition, err := globalPosition(data.Tree, data.Position)
	if err != nil {
		return StoredTXO{}, false, err
	}
	nullifier, err := railcrypto.Nullifier(keys.NullifyingKey, globalPosition)
	if err != nil {
		return StoredTXO{}, false, err
	}
	nullifierHex, err := railcrypto.BigIntToHex(nullifier, 32, false)
	if err != nil {
		return StoredTXO{}, false, err
	}
	blindedCommitment, err := railcrypto.BlindedCommitment(hash, decrypted.NotePublicKey, railtxid.GetGlobalTreePosition(uint64(data.Tree), uint64(data.Position)))
	if err != nil {
		return StoredTXO{}, false, err
	}
	notePublicKeyHex, err := railcrypto.BigIntToHex(decrypted.NotePublicKey, 32, false)
	if err != nil {
		return StoredTXO{}, false, err
	}
	recipientAddress, err := encodeTransactNoteAddressData(decrypted.ReceiverAddressData)
	if err != nil {
		return StoredTXO{}, false, fmt.Errorf("recipient address: %w", err)
	}
	senderAddress, err := encodeTransactNoteAddressDataPtr(decrypted.SenderAddressData)
	if err != nil {
		return StoredTXO{}, false, fmt.Errorf("sender address: %w", err)
	}
	return StoredTXO{
		TXIDVersion:                 data.TXIDVersion,
		Tree:                        uint64(data.Tree),
		Position:                    uint64(data.Position),
		TXID:                        data.TXID,
		Timestamp:                   cloneUint64Ptr(data.Timestamp),
		BlockNumber:                 data.BlockNumber,
		Nullifier:                   nullifierHex,
		CommitmentHash:              hash,
		NotePublicKey:               notePublicKeyHex,
		NoteRandom:                  decrypted.Random,
		TokenHash:                   decrypted.TokenHash,
		TokenData:                   decrypted.TokenData,
		Value:                       cloneBigInt(decrypted.Value),
		OutputType:                  cloneIntPtr(decrypted.OutputType),
		WalletSource:                decrypted.WalletSource,
		MemoText:                    decrypted.MemoText,
		SenderAddress:               senderAddress,
		RecipientAddress:            recipientAddress,
		CommitmentType:              data.CommitmentType,
		BlindedCommitment:           blindedCommitment,
		TransactCreationRailgunTxid: data.TXID,
	}, true, nil
}

func markNullifiersSpent(ctx context.Context, store StateStore, nullifiers []railevents.Nullifier, summary *ImportSummary) error {
	for _, event := range nullifiers {
		if err := ctx.Err(); err != nil {
			return err
		}
		nullifier, err := railcrypto.FormatHexToByteLength(event.Nullifier, 32, false)
		if err != nil {
			return fmt.Errorf("nullifier: %w", err)
		}
		if reorgStore, ok := store.(ReorgStateStore); ok {
			err = reorgStore.MarkTXOSpentAtBlock(ctx, nullifier, event.Txid, event.BlockNumber)
		} else {
			err = store.MarkTXOSpent(ctx, nullifier, event.Txid)
		}
		if err != nil {
			summary.SpendsSkipped++
			continue
		}
		summary.SpendsMarked++
	}
	return nil
}

func currentWalletAddressData(keys ScanKeys) railcrypto.TransactNoteAddressData {
	return railcrypto.TransactNoteAddressData{
		MasterPublicKey:  new(big.Int).Set(keys.MasterPublicKey),
		ViewingPublicKey: append([]byte(nil), keys.ViewingPublicKey...),
	}
}

func encodeTransactNoteAddressData(data railcrypto.TransactNoteAddressData) (string, error) {
	if data.MasterPublicKey == nil || len(data.ViewingPublicKey) == 0 {
		return "", nil
	}
	return address.Encode(address.AddressData{
		MasterPublicKey:  data.MasterPublicKey.String(),
		ViewingPublicKey: railcrypto.BytesToHex(data.ViewingPublicKey, false),
		Version:          address.AddressVersion,
	})
}

func encodeTransactNoteAddressDataPtr(data *railcrypto.TransactNoteAddressData) (string, error) {
	if data == nil {
		return "", nil
	}
	return encodeTransactNoteAddressData(*data)
}

func globalPosition(tree int, position int) (uint64, error) {
	if tree < 0 || position < 0 {
		return 0, fmt.Errorf("tree and position must be non-negative")
	}
	global := railtxid.GetGlobalTreePosition(uint64(tree), uint64(position))
	if !global.IsUint64() {
		return 0, fmt.Errorf("global tree position exceeds uint64")
	}
	return global.Uint64(), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
