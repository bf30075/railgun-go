package wallet

import (
	"context"
	"fmt"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

func (wallet *Wallet) ReceiveCommitmentHasValidPOI(ctx context.Context, txidVersion string, commitment string) (bool, error) {
	if err := wallet.validate(); err != nil {
		return false, err
	}
	if txidVersion == "" {
		return false, fmt.Errorf("txid version is required")
	}
	formattedCommitment, err := railcrypto.FormatHexToByteLength(commitment, 32, true)
	if err != nil {
		return false, err
	}
	txos, err := wallet.State.ListTXOs(ctx)
	if err != nil {
		return false, err
	}
	for _, txo := range txosForTXIDVersion(txos, txidVersion) {
		if !isTransactCommitmentTypeForStatus(txo.CommitmentType) || txo.CommitmentHash == "" {
			continue
		}
		formattedTXOCommitment, err := railcrypto.FormatHexToByteLength(txo.CommitmentHash, 32, true)
		if err != nil {
			return false, err
		}
		if formattedTXOCommitment == formattedCommitment {
			return wallet.POIManager.HasValidPOIsActiveLists(txo.POIsPerList), nil
		}
	}
	return false, nil
}

func (wallet *Wallet) SpendableReceivedChainTXIDs(ctx context.Context, txidVersion string) ([]string, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	if txidVersion == "" {
		return nil, fmt.Errorf("txid version is required")
	}
	txos, err := wallet.State.ListTXOs(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	txids := []string{}
	for _, txo := range txosForTXIDVersion(txos, txidVersion) {
		if txo.TXID == "" || seen[txo.TXID] {
			continue
		}
		bucket := wallet.POIManager.GetBalanceBucket(storedTXOToPOITXO(txo))
		if bucket != railpoi.WalletBalanceBucketSpendable {
			continue
		}
		seen[txo.TXID] = true
		txids = append(txids, txo.TXID)
	}
	return txids, nil
}

func (wallet *Wallet) ChainTXIDsStillPendingSpentPOIs(ctx context.Context) ([]string, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	if wallet.SpentPOIEvents == nil {
		return nil, fmt.Errorf("spent poi event store is required")
	}
	sentCommitments, err := wallet.SpentPOIEvents.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		return nil, err
	}
	unshieldEvents, err := wallet.SpentPOIEvents.ListUnshieldPOIEvents(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	txids := []string{}
	for _, event := range sentCommitments {
		if event.TXID == "" || seen[event.TXID] {
			continue
		}
		if wallet.POIManager.ShouldGenerateSpentPOIsSentCommitment(railpoi.SentCommitment{
			POIsPerList:       clonePOIsPerList(event.POIsPerList),
			Value:             cloneBigInt(event.Value),
			BlindedCommitment: event.BlindedCommitment,
			RailgunTxid:       event.RailgunTxid,
		}) {
			seen[event.TXID] = true
			txids = append(txids, event.TXID)
		}
	}
	for _, event := range unshieldEvents {
		if event.TXID == "" || seen[event.TXID] {
			continue
		}
		if wallet.POIManager.ShouldGenerateSpentPOIsUnshieldEvent(railpoi.UnshieldPOIEvent{
			POIsPerList: clonePOIsPerList(event.POIsPerList),
			RailgunTxid: event.RailgunTxid,
		}) {
			seen[event.TXID] = true
			txids = append(txids, event.TXID)
		}
	}
	return txids, nil
}

func (wallet *Wallet) NumSpendPOIProofsPossible(ctx context.Context, chain railchain.Chain) (int, error) {
	statuses, err := wallet.SpentPOIStatusFromStore(ctx, chain)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, status := range statuses {
		total += len(status.ListKeysCanGenerateSpentPOIs)
	}
	return total, nil
}

func isTransactCommitmentTypeForStatus(commitmentType string) bool {
	return commitmentType == railpoi.CommitmentTypeTransactV2 ||
		commitmentType == railpoi.CommitmentTypeTransactV3 ||
		commitmentType == railpoi.CommitmentTypeLegacyEncrypted
}
