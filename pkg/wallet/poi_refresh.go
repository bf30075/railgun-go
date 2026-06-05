package wallet

import (
	"context"
	"fmt"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

const poiRefreshBatchSize = 1000

type RefreshPOIsSummary struct {
	TXOsChecked int
	TXOsMatched int
	Requests    int
	TXOsUpdated int
	TXOsMissing int
}

type RefreshSpentPOIEventsSummary struct {
	SentCommitmentsChecked int
	UnshieldEventsChecked  int
	EventsMatched          int
	Requests               int
	EventsUpdated          int
	EventsMissing          int
}

func RefreshPOIs(ctx context.Context, store StateStore, poiManager *railpoi.Manager, txidVersion string, chain railchain.Chain) (RefreshPOIsSummary, error) {
	if store == nil {
		return RefreshPOIsSummary{}, fmt.Errorf("state store is required")
	}
	if poiManager == nil {
		return RefreshPOIsSummary{}, fmt.Errorf("poi manager is required")
	}
	if txidVersion == "" {
		return RefreshPOIsSummary{}, fmt.Errorf("txid version is required")
	}
	txos, err := store.ListTXOs(ctx)
	if err != nil {
		return RefreshPOIsSummary{}, err
	}

	summary := RefreshPOIsSummary{TXOsChecked: len(txos)}
	candidates := []poiRefreshCandidate{}
	for _, txo := range txos {
		if txo.TXIDVersion != "" && txo.TXIDVersion != txidVersion {
			continue
		}
		if !poiManager.ShouldRetrieveTXOPOIs(storedTXOToPOITXO(txo)) {
			continue
		}
		commitmentType, err := blindedCommitmentTypeForTXO(txo)
		if err != nil {
			return RefreshPOIsSummary{}, err
		}
		candidates = append(candidates, poiRefreshCandidate{
			Nullifier: txo.Nullifier,
			Data: railpoi.BlindedCommitmentData{
				BlindedCommitment: txo.BlindedCommitment,
				Type:              commitmentType,
			},
		})
	}
	summary.TXOsMatched = len(candidates)

	for start := 0; start < len(candidates); start += poiRefreshBatchSize {
		end := start + poiRefreshBatchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		batch := candidates[start:end]
		datas := make([]railpoi.BlindedCommitmentData, len(batch))
		for i, candidate := range batch {
			datas[i] = candidate.Data
		}
		poisByCommitment, err := poiManager.RetrievePOIsForBlindedCommitments(ctx, txidVersion, chain, datas)
		if err != nil {
			return RefreshPOIsSummary{}, err
		}
		summary.Requests++
		for _, candidate := range batch {
			pois, ok := poisByCommitment[candidate.Data.BlindedCommitment]
			if !ok {
				summary.TXOsMissing++
				continue
			}
			if err := store.UpdateTXOPOIs(ctx, candidate.Nullifier, pois); err != nil {
				return RefreshPOIsSummary{}, err
			}
			summary.TXOsUpdated++
		}
	}
	return summary, nil
}

func RefreshSpentPOIEvents(ctx context.Context, store SpentPOIEventStore, poiManager *railpoi.Manager, txidVersion string, chain railchain.Chain) (RefreshSpentPOIEventsSummary, error) {
	if store == nil {
		return RefreshSpentPOIEventsSummary{}, fmt.Errorf("spent poi event store is required")
	}
	if poiManager == nil {
		return RefreshSpentPOIEventsSummary{}, fmt.Errorf("poi manager is required")
	}
	if txidVersion == "" {
		return RefreshSpentPOIEventsSummary{}, fmt.Errorf("txid version is required")
	}
	sentCommitments, err := store.ListSentCommitmentPOIEvents(ctx)
	if err != nil {
		return RefreshSpentPOIEventsSummary{}, err
	}
	unshieldEvents, err := store.ListUnshieldPOIEvents(ctx)
	if err != nil {
		return RefreshSpentPOIEventsSummary{}, err
	}

	summary := RefreshSpentPOIEventsSummary{
		SentCommitmentsChecked: len(sentCommitments),
		UnshieldEventsChecked:  len(unshieldEvents),
	}
	candidates := []spentPOIEventRefreshCandidate{}
	for _, event := range sentCommitments {
		if !poiManager.ShouldRetrieveSentCommitmentPOIs(railpoi.SentCommitment{
			POIsPerList:       clonePOIsPerList(event.POIsPerList),
			Value:             cloneBigInt(event.Value),
			BlindedCommitment: event.BlindedCommitment,
			RailgunTxid:       event.RailgunTxid,
		}) {
			continue
		}
		candidates = append(candidates, spentPOIEventRefreshCandidate{
			SentCommitment: event,
			Data: railpoi.BlindedCommitmentData{
				BlindedCommitment: event.BlindedCommitment,
				Type:              railpoi.BlindedCommitmentTypeTransact,
			},
		})
	}
	for _, event := range unshieldEvents {
		if !poiManager.ShouldRetrieveUnshieldEventPOIs(railpoi.UnshieldPOIEvent{
			POIsPerList: clonePOIsPerList(event.POIsPerList),
			RailgunTxid: event.RailgunTxid,
		}) {
			continue
		}
		candidates = append(candidates, spentPOIEventRefreshCandidate{
			UnshieldEvent: event,
			Data: railpoi.BlindedCommitmentData{
				BlindedCommitment: event.RailgunTxid,
				Type:              railpoi.BlindedCommitmentTypeUnshield,
			},
		})
	}
	summary.EventsMatched = len(candidates)

	for start := 0; start < len(candidates); start += poiRefreshBatchSize {
		end := start + poiRefreshBatchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		batch := candidates[start:end]
		datas := make([]railpoi.BlindedCommitmentData, len(batch))
		for i, candidate := range batch {
			datas[i] = candidate.Data
		}
		poisByCommitment, err := poiManager.RetrievePOIsForBlindedCommitments(ctx, txidVersion, chain, datas)
		if err != nil {
			return RefreshSpentPOIEventsSummary{}, err
		}
		summary.Requests++
		for _, candidate := range batch {
			pois, ok := poisByCommitment[candidate.Data.BlindedCommitment]
			if !ok {
				summary.EventsMissing++
				continue
			}
			if candidate.SentCommitment.BlindedCommitment != "" {
				event := cloneSentCommitmentPOIStatusInput(candidate.SentCommitment)
				event.POIsPerList = clonePOIsPerList(pois)
				if err := store.UpsertSentCommitmentPOIEvent(ctx, event); err != nil {
					return RefreshSpentPOIEventsSummary{}, err
				}
			} else {
				event := cloneUnshieldPOIStatusInput(candidate.UnshieldEvent)
				event.POIsPerList = clonePOIsPerList(pois)
				if err := store.UpsertUnshieldPOIEvent(ctx, event); err != nil {
					return RefreshSpentPOIEventsSummary{}, err
				}
			}
			summary.EventsUpdated++
		}
	}
	return summary, nil
}

type poiRefreshCandidate struct {
	Nullifier string
	Data      railpoi.BlindedCommitmentData
}

type spentPOIEventRefreshCandidate struct {
	SentCommitment SentCommitmentPOIStatusInput
	UnshieldEvent  UnshieldPOIStatusInput
	Data           railpoi.BlindedCommitmentData
}

func storedTXOToPOITXO(txo StoredTXO) railpoi.TXO {
	return railpoi.TXO{
		SpendTXID:                   txo.SpendTXID,
		POIsPerList:                 clonePOIsPerList(txo.POIsPerList),
		CommitmentType:              txo.CommitmentType,
		OutputType:                  cloneIntPtr(txo.OutputType),
		Value:                       cloneBigInt(txo.Value),
		BlindedCommitment:           txo.BlindedCommitment,
		BlockNumber:                 txo.BlockNumber,
		TransactCreationRailgunTxid: txo.TransactCreationRailgunTxid,
	}
}

func blindedCommitmentTypeForTXO(txo StoredTXO) (string, error) {
	switch txo.CommitmentType {
	case railpoi.CommitmentTypeShield, railpoi.CommitmentTypeLegacyGenerated:
		return railpoi.BlindedCommitmentTypeShield, nil
	case railpoi.CommitmentTypeTransactV2, railpoi.CommitmentTypeTransactV3, railpoi.CommitmentTypeLegacyEncrypted:
		return railpoi.BlindedCommitmentTypeTransact, nil
	default:
		return "", fmt.Errorf("unsupported commitment type for POI refresh: %s", txo.CommitmentType)
	}
}
