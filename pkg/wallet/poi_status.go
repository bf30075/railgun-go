package wallet

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

const unavailablePOIStatusField = "Unavailable"

type ReceivedPOIStatusInfo struct {
	Tree              uint64              `json:"tree"`
	Position          uint64              `json:"position"`
	TXID              string              `json:"txid"`
	Commitment        string              `json:"commitment"`
	BlindedCommitment string              `json:"blindedCommitment"`
	POIsPerList       railpoi.POIsPerList `json:"poisPerList,omitempty"`
}

type SentCommitmentPOIStatusInput struct {
	TXID              string
	RailgunTxid       string
	Timestamp         *uint64
	BlockNumber       uint64
	CommitmentHash    string
	BlindedCommitment string
	TokenHash         string
	TokenData         railcrypto.TokenData
	Value             *big.Int
	OutputType        *int
	WalletSource      string
	MemoText          string
	SenderAddress     string
	RecipientAddress  string
	POIsPerList       railpoi.POIsPerList
}

type UnshieldPOIStatusInput struct {
	TXID           string
	RailgunTxid    string
	BlockNumber    uint64
	CommitmentHash string
	POIsPerList    railpoi.POIsPerList
}

type SpentPOIStatusInfo struct {
	BlockNumber                  uint64                `json:"blockNumber"`
	TXID                         string                `json:"txid"`
	RailgunTxid                  string                `json:"railgunTxid"`
	RailgunTransactionInfo       string                `json:"railgunTransactionInfo"`
	POIStatusesSpentTXOs         []railpoi.POIsPerList `json:"poiStatusesSpentTXOs"`
	SentCommitmentsBlinded       string                `json:"sentCommitmentsBlinded"`
	POIStatusesSentCommitments   []railpoi.POIsPerList `json:"poiStatusesSentCommitments"`
	UnshieldEventsBlinded        string                `json:"unshieldEventsBlinded"`
	POIStatusesUnshieldEvents    []railpoi.POIsPerList `json:"poiStatusesUnshieldEvents"`
	ListKeysCanGenerateSpentPOIs []string              `json:"listKeysCanGenerateSpentPOIs"`
}

func FormatReceivedPOIStatusInfo(txos []StoredTXO) []ReceivedPOIStatusInfo {
	statuses := make([]ReceivedPOIStatusInfo, len(txos))
	for i, txo := range txos {
		statuses[i] = ReceivedPOIStatusInfo{
			Tree:              txo.Tree,
			Position:          txo.Position,
			TXID:              txo.TXID,
			Commitment:        commitmentStatusField(txo),
			BlindedCommitment: nonEmptyOrUnavailable(txo.BlindedCommitment),
			POIsPerList:       clonePOIsPerList(txo.POIsPerList),
		}
	}
	sort.Slice(statuses, func(i int, j int) bool {
		left := railtxid.GetGlobalTreePosition(statuses[i].Tree, statuses[i].Position)
		right := railtxid.GetGlobalTreePosition(statuses[j].Tree, statuses[j].Position)
		cmp := right.Cmp(left)
		if cmp != 0 {
			return cmp < 0
		}
		return statuses[i].TXID > statuses[j].TXID
	})
	return statuses
}

func FormatSpentPOIStatusInfo(
	ctx context.Context,
	poiManager *railpoi.Manager,
	txidStore railtxid.TransactionStore,
	chain railchain.Chain,
	txos []StoredTXO,
	sentCommitments []SentCommitmentPOIStatusInput,
	unshieldEvents []UnshieldPOIStatusInput,
) ([]SpentPOIStatusInfo, error) {
	if poiManager == nil {
		return nil, fmt.Errorf("poi manager is required")
	}
	if txidStore == nil {
		return nil, fmt.Errorf("txid store is required")
	}
	groups := spentStatusGroups(sentCommitments, unshieldEvents)
	statuses := make([]SpentPOIStatusInfo, 0, len(groups))
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		status, err := formatSpentStatusGroup(ctx, poiManager, txidStore, chain, txos, group)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i int, j int) bool {
		if statuses[i].BlockNumber != statuses[j].BlockNumber {
			return statuses[i].BlockNumber > statuses[j].BlockNumber
		}
		if statuses[i].TXID != statuses[j].TXID {
			return statuses[i].TXID > statuses[j].TXID
		}
		return statuses[i].RailgunTxid > statuses[j].RailgunTxid
	})
	return statuses, nil
}

func (wallet *Wallet) ReceivedPOIStatus(ctx context.Context) ([]ReceivedPOIStatusInfo, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	txos, err := wallet.State.ListTXOs(ctx)
	if err != nil {
		return nil, err
	}
	return FormatReceivedPOIStatusInfo(txos), nil
}

func (wallet *Wallet) SpentPOIStatus(ctx context.Context, chain railchain.Chain, sentCommitments []SentCommitmentPOIStatusInput, unshieldEvents []UnshieldPOIStatusInput) ([]SpentPOIStatusInfo, error) {
	if err := wallet.validate(); err != nil {
		return nil, err
	}
	if wallet.TXIDStore == nil {
		return nil, fmt.Errorf("txid store is required")
	}
	txos, err := wallet.State.ListTXOs(ctx)
	if err != nil {
		return nil, err
	}
	return FormatSpentPOIStatusInfo(ctx, wallet.POIManager, wallet.TXIDStore, chain, txos, sentCommitments, unshieldEvents)
}

func (wallet *Wallet) SpentPOIStatusFromStore(ctx context.Context, chain railchain.Chain) ([]SpentPOIStatusInfo, error) {
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
	return wallet.SpentPOIStatus(ctx, chain, sentCommitments, unshieldEvents)
}

func (wallet *Wallet) MarkSpentPOIProofsSubmitted(ctx context.Context, submissions []railpoi.SubmittedPreTransactionPOI) error {
	if err := wallet.validate(); err != nil {
		return err
	}
	if wallet.SpentPOIEvents == nil {
		return fmt.Errorf("spent poi event store is required")
	}
	return wallet.SpentPOIEvents.MarkProofSubmitted(ctx, submissions)
}

func commitmentStatusField(txo StoredTXO) string {
	if txo.CommitmentHash == "" && txo.CommitmentType == "" {
		return unavailablePOIStatusField
	}
	if txo.CommitmentHash == "" {
		return fmt.Sprintf("%s (%s)", unavailablePOIStatusField, txo.CommitmentType)
	}
	if txo.CommitmentType == "" {
		return txo.CommitmentHash
	}
	return fmt.Sprintf("%s (%s)", txo.CommitmentHash, txo.CommitmentType)
}

func nonEmptyOrUnavailable(value string) string {
	if value == "" {
		return unavailablePOIStatusField
	}
	return value
}

type spentStatusGroup struct {
	TXID            string
	RailgunTxid     string
	SentCommitments []SentCommitmentPOIStatusInput
	UnshieldEvents  []UnshieldPOIStatusInput
}

func spentStatusGroups(sentCommitments []SentCommitmentPOIStatusInput, unshieldEvents []UnshieldPOIStatusInput) []spentStatusGroup {
	byKey := map[string]*spentStatusGroup{}
	for _, sentCommitment := range sentCommitments {
		txid := nonEmptyOrMissing(sentCommitment.TXID)
		railgunTxid := nonEmptyOrMissing(sentCommitment.RailgunTxid)
		key := txid + "\x00" + railgunTxid
		group := byKey[key]
		if group == nil {
			group = &spentStatusGroup{TXID: txid, RailgunTxid: railgunTxid}
			byKey[key] = group
		}
		group.SentCommitments = append(group.SentCommitments, sentCommitment)
	}
	for _, unshieldEvent := range unshieldEvents {
		txid := nonEmptyOrMissing(unshieldEvent.TXID)
		railgunTxid := nonEmptyOrMissing(unshieldEvent.RailgunTxid)
		key := txid + "\x00" + railgunTxid
		group := byKey[key]
		if group == nil {
			group = &spentStatusGroup{TXID: txid, RailgunTxid: railgunTxid}
			byKey[key] = group
		}
		group.UnshieldEvents = append(group.UnshieldEvents, unshieldEvent)
	}
	groups := make([]spentStatusGroup, 0, len(byKey))
	for _, group := range byKey {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i int, j int) bool {
		if groups[i].TXID != groups[j].TXID {
			return groups[i].TXID < groups[j].TXID
		}
		return groups[i].RailgunTxid < groups[j].RailgunTxid
	})
	return groups
}

func formatSpentStatusGroup(
	ctx context.Context,
	poiManager *railpoi.Manager,
	txidStore railtxid.TransactionStore,
	chain railchain.Chain,
	txos []StoredTXO,
	group spentStatusGroup,
) (SpentPOIStatusInfo, error) {
	blockNumber := spentGroupBlockNumber(group)
	transactionInfo := "Missing"
	spentTXOs := []StoredTXO{}
	listKeysCanGenerateSpentPOIs := []string{}
	if group.RailgunTxid != "" && group.RailgunTxid != "Missing" {
		transaction, ok, err := txidStore.GetByRailgunTxid(ctx, group.RailgunTxid)
		if err != nil {
			return SpentPOIStatusInfo{}, err
		}
		if ok {
			hasAllNullifiers := transactionHasAllNullifiers(transaction, txos)
			hasAllCommitments := transactionHasAllCommitments(transaction, group)
			transactionInfo = fmt.Sprintf(
				"%d nul: %s (%s), %d com/unsh: %s (%s)",
				len(transaction.Nullifiers),
				strings.Join(transaction.Nullifiers, ", "),
				checkMark(hasAllNullifiers),
				len(transaction.Commitments),
				strings.Join(transaction.Commitments, ", "),
				checkMark(hasAllCommitments),
			)
			launchBlock, ok := poiManager.LaunchBlock(chain)
			if !ok {
				return SpentPOIStatusInfo{}, fmt.Errorf("No POI launch block for railgun txids")
			}
			isLegacyPOIProof := transaction.BlockNumber < launchBlock
			spentTXOs = filterSpentTXOs(txos, transaction.Nullifiers, transaction.UTXOTreeIn)
			listKeysCanGenerateSpentPOIs = poiManager.GetListKeysCanGenerateSpentPOIs(
				poiTXOsFromStored(spentTXOs),
				poiSentCommitmentsFromStatusInputs(group.SentCommitments),
				poiUnshieldEventsFromStatusInputs(group.UnshieldEvents),
				isLegacyPOIProof,
			)
		} else {
			transactionInfo = "Not found"
		}
	}
	return SpentPOIStatusInfo{
		BlockNumber:                  blockNumber,
		TXID:                         group.TXID,
		RailgunTxid:                  group.RailgunTxid,
		RailgunTransactionInfo:       transactionInfo,
		POIStatusesSpentTXOs:         poisRowsFromTXOs(spentTXOs),
		SentCommitmentsBlinded:       sentCommitmentsBlinded(group.SentCommitments),
		POIStatusesSentCommitments:   poisRowsFromSentCommitments(group.SentCommitments),
		UnshieldEventsBlinded:        unshieldEventsBlinded(group.UnshieldEvents),
		POIStatusesUnshieldEvents:    poisRowsFromUnshieldEvents(group.UnshieldEvents),
		ListKeysCanGenerateSpentPOIs: append([]string(nil), listKeysCanGenerateSpentPOIs...),
	}, nil
}

func spentGroupBlockNumber(group spentStatusGroup) uint64 {
	if len(group.SentCommitments) > 0 {
		return group.SentCommitments[0].BlockNumber
	}
	if len(group.UnshieldEvents) > 0 {
		return group.UnshieldEvents[0].BlockNumber
	}
	return 0
}

func transactionHasAllNullifiers(transaction railtxid.Transaction, txos []StoredTXO) bool {
	for _, nullifier := range transaction.Nullifiers {
		found := false
		for _, txo := range txos {
			if normalizedHex(txo.Nullifier) == normalizedHex(nullifier) && int(txo.Tree) == transaction.UTXOTreeIn {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func transactionHasAllCommitments(transaction railtxid.Transaction, group spentStatusGroup) bool {
	commitments := map[string]bool{}
	for _, sentCommitment := range group.SentCommitments {
		if sentCommitment.CommitmentHash != "" {
			commitments[normalizedHex(sentCommitment.CommitmentHash)] = true
		}
	}
	for _, unshieldEvent := range group.UnshieldEvents {
		if unshieldEvent.CommitmentHash != "" {
			commitments[normalizedHex(unshieldEvent.CommitmentHash)] = true
		}
	}
	for _, commitment := range transaction.Commitments {
		if !commitments[normalizedHex(commitment)] {
			return false
		}
	}
	return true
}

func filterSpentTXOs(txos []StoredTXO, nullifiers []string, utxoTreeIn int) []StoredTXO {
	nullifierSet := map[string]bool{}
	for _, nullifier := range nullifiers {
		nullifierSet[normalizedHex(nullifier)] = true
	}
	out := []StoredTXO{}
	for _, txo := range txos {
		if int(txo.Tree) == utxoTreeIn && nullifierSet[normalizedHex(txo.Nullifier)] {
			out = append(out, cloneStoredTXO(txo))
		}
	}
	return out
}

func poiTXOsFromStored(txos []StoredTXO) []railpoi.TXO {
	out := make([]railpoi.TXO, len(txos))
	for i, txo := range txos {
		out[i] = storedTXOToPOITXO(txo)
	}
	return out
}

func poiSentCommitmentsFromStatusInputs(values []SentCommitmentPOIStatusInput) []railpoi.SentCommitment {
	out := make([]railpoi.SentCommitment, len(values))
	for i, value := range values {
		out[i] = railpoi.SentCommitment{
			POIsPerList:       clonePOIsPerList(value.POIsPerList),
			Value:             cloneBigInt(value.Value),
			BlindedCommitment: value.BlindedCommitment,
			RailgunTxid:       value.RailgunTxid,
		}
	}
	return out
}

func poiUnshieldEventsFromStatusInputs(values []UnshieldPOIStatusInput) []railpoi.UnshieldPOIEvent {
	out := make([]railpoi.UnshieldPOIEvent, len(values))
	for i, value := range values {
		out[i] = railpoi.UnshieldPOIEvent{
			POIsPerList: clonePOIsPerList(value.POIsPerList),
			RailgunTxid: value.RailgunTxid,
		}
	}
	return out
}

func poisRowsFromTXOs(txos []StoredTXO) []railpoi.POIsPerList {
	out := make([]railpoi.POIsPerList, len(txos))
	for i, txo := range txos {
		out[i] = clonePOIsPerList(txo.POIsPerList)
	}
	return out
}

func poisRowsFromSentCommitments(values []SentCommitmentPOIStatusInput) []railpoi.POIsPerList {
	out := make([]railpoi.POIsPerList, len(values))
	for i, value := range values {
		out[i] = clonePOIsPerList(value.POIsPerList)
	}
	return out
}

func poisRowsFromUnshieldEvents(values []UnshieldPOIStatusInput) []railpoi.POIsPerList {
	out := make([]railpoi.POIsPerList, len(values))
	for i, value := range values {
		out[i] = clonePOIsPerList(value.POIsPerList)
	}
	return out
}

func sentCommitmentsBlinded(values []SentCommitmentPOIStatusInput) string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = nonEmptyOrUnavailable(value.BlindedCommitment)
	}
	return strings.Join(out, ", ")
}

func unshieldEventsBlinded(values []UnshieldPOIStatusInput) string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = nonEmptyOrUnavailable(value.RailgunTxid)
	}
	return strings.Join(out, ", ")
}

func checkMark(ok bool) string {
	if ok {
		return "✓"
	}
	return "x"
}

func nonEmptyOrMissing(value string) string {
	if value == "" {
		return "Missing"
	}
	return value
}

func normalizedHex(value string) string {
	value = strings.TrimPrefix(strings.ToLower(value), "0x")
	value = strings.TrimLeft(value, "0")
	if value == "" {
		return "0"
	}
	return value
}
