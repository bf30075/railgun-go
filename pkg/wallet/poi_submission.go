package wallet

import railpoi "github.com/bf30075/railgun-go/pkg/poi"

func ApplySubmittedPreTransactionPOIStatuses(
	sentCommitments []SentCommitmentPOIStatusInput,
	unshieldEvents []UnshieldPOIStatusInput,
	submissions []railpoi.SubmittedPreTransactionPOI,
) ([]SentCommitmentPOIStatusInput, []UnshieldPOIStatusInput) {
	return MarkSpentPOIProofSubmitted(sentCommitments, unshieldEvents, submittedPOIListKeys(submissions))
}

func MarkSpentPOIProofSubmitted(
	sentCommitments []SentCommitmentPOIStatusInput,
	unshieldEvents []UnshieldPOIStatusInput,
	listKeys []string,
) ([]SentCommitmentPOIStatusInput, []UnshieldPOIStatusInput) {
	updatedSent := make([]SentCommitmentPOIStatusInput, len(sentCommitments))
	for i, sentCommitment := range sentCommitments {
		updatedSent[i] = sentCommitment
		updatedSent[i].Value = cloneBigInt(sentCommitment.Value)
		updatedSent[i].POIsPerList = markPOIsProofSubmitted(sentCommitment.POIsPerList, listKeys)
	}

	updatedUnshield := make([]UnshieldPOIStatusInput, len(unshieldEvents))
	for i, unshieldEvent := range unshieldEvents {
		updatedUnshield[i] = unshieldEvent
		updatedUnshield[i].POIsPerList = markPOIsProofSubmitted(unshieldEvent.POIsPerList, listKeys)
	}
	return updatedSent, updatedUnshield
}

func markPOIsProofSubmitted(pois railpoi.POIsPerList, listKeys []string) railpoi.POIsPerList {
	out := clonePOIsPerList(pois)
	if out == nil {
		out = railpoi.POIsPerList{}
	}
	for _, listKey := range listKeys {
		if listKey == "" {
			continue
		}
		if out[listKey] == railpoi.TXOPOIListStatusValid {
			continue
		}
		out[listKey] = railpoi.TXOPOIListStatusProofSubmitted
	}
	return out
}
