package wallet

import (
	"context"
	"fmt"
	"math/big"
	"sort"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
)

type TransactionHistoryItemVersion int

const (
	TransactionHistoryItemVersionUnknown TransactionHistoryItemVersion = iota
	TransactionHistoryItemVersionLegacy
	TransactionHistoryItemVersionUpdatedAug2022
	TransactionHistoryItemVersionUpdatedNov2022
)

type TransactionHistoryTokenAmount struct {
	TokenHash                 string               `json:"tokenHash"`
	TokenData                 railcrypto.TokenData `json:"tokenData"`
	Amount                    *big.Int             `json:"amount"`
	OutputType                *int                 `json:"outputType,omitempty"`
	WalletSource              string               `json:"walletSource,omitempty"`
	MemoText                  string               `json:"memoText,omitempty"`
	HasValidPOIForActiveLists bool                 `json:"hasValidPOIForActiveLists"`
}

type TransactionHistoryTransferTokenAmount struct {
	TransactionHistoryTokenAmount
	RecipientAddress string `json:"recipientAddress,omitempty"`
}

type TransactionHistoryUnshieldTokenAmount struct {
	TransactionHistoryTransferTokenAmount
	UnshieldFee string `json:"unshieldFee"`
}

type TransactionHistoryReceiveTokenAmount struct {
	TransactionHistoryTokenAmount
	SenderAddress string `json:"senderAddress,omitempty"`
	ShieldFee     string `json:"shieldFee,omitempty"`
	BalanceBucket string `json:"balanceBucket"`
}

type TransactionHistoryEntry struct {
	TXIDVersion               string                                  `json:"txidVersion"`
	TXID                      string                                  `json:"txid"`
	Timestamp                 *uint64                                 `json:"timestamp,omitempty"`
	BlockNumber               uint64                                  `json:"blockNumber,omitempty"`
	ReceiveTokenAmounts       []TransactionHistoryReceiveTokenAmount  `json:"receiveTokenAmounts"`
	TransferTokenAmounts      []TransactionHistoryTransferTokenAmount `json:"transferTokenAmounts"`
	ChangeTokenAmounts        []TransactionHistoryTokenAmount         `json:"changeTokenAmounts"`
	BroadcasterFeeTokenAmount *TransactionHistoryTokenAmount          `json:"broadcasterFeeTokenAmount,omitempty"`
	UnshieldTokenAmounts      []TransactionHistoryUnshieldTokenAmount `json:"unshieldTokenAmounts"`
	Version                   TransactionHistoryItemVersion           `json:"version"`
}

func (wallet *Wallet) TransactionHistory(ctx context.Context, txidVersion string, startingBlock *uint64) ([]TransactionHistoryEntry, error) {
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
	txos = filterHistoryTXOs(txosForTXIDVersion(txos, txidVersion), startingBlock)
	receiveHistory, err := wallet.transactionReceiveHistory(txidVersion, txos)
	if err != nil {
		return nil, err
	}
	spendHistory, err := wallet.transactionSpendHistory(ctx, txidVersion, startingBlock)
	if err != nil {
		return nil, err
	}

	history := make([]TransactionHistoryEntry, len(spendHistory))
	copy(history, spendHistory)
	for _, receive := range receiveHistory {
		existing := findHistoryEntry(history, receive.TXID)
		if existing == nil {
			history = append(history, receive)
			continue
		}
		for _, amount := range receive.ReceiveTokenAmounts {
			change, transferIndex := matchingChangeOrLegacyTransfer(*existing, amount.TransactionHistoryTokenAmount)
			if transferIndex >= 0 {
				existing.TransferTokenAmounts = append(existing.TransferTokenAmounts[:transferIndex], existing.TransferTokenAmounts[transferIndex+1:]...)
				existing.ChangeTokenAmounts = append(existing.ChangeTokenAmounts, change)
				continue
			}
			if change.TokenHash != "" {
				continue
			}
			existing.ReceiveTokenAmounts = append(existing.ReceiveTokenAmounts, amount)
		}
	}
	sortTransactionHistory(history)
	return history, nil
}

func (wallet *Wallet) transactionReceiveHistory(txidVersion string, txos []StoredTXO) ([]TransactionHistoryEntry, error) {
	byTXID := map[string]*TransactionHistoryEntry{}
	order := []string{}
	for _, txo := range txos {
		if txo.Value == nil || txo.Value.Sign() == 0 {
			continue
		}
		txid := txo.TXID
		if txid == "" {
			txid = txo.TransactCreationRailgunTxid
		}
		if txid == "" {
			continue
		}
		entry := byTXID[txid]
		if entry == nil {
			entry = &TransactionHistoryEntry{
				TXIDVersion:          txidVersion,
				TXID:                 txid,
				Timestamp:            cloneUint64Ptr(txo.Timestamp),
				BlockNumber:          txo.BlockNumber,
				ReceiveTokenAmounts:  []TransactionHistoryReceiveTokenAmount{},
				TransferTokenAmounts: []TransactionHistoryTransferTokenAmount{},
				ChangeTokenAmounts:   []TransactionHistoryTokenAmount{},
				UnshieldTokenAmounts: []TransactionHistoryUnshieldTokenAmount{},
				Version:              TransactionHistoryItemVersionUnknown,
			}
			byTXID[txid] = entry
			order = append(order, txid)
		}
		tokenHash, err := tokenHashForTXO(txo)
		if err != nil {
			return nil, err
		}
		entry.ReceiveTokenAmounts = append(entry.ReceiveTokenAmounts, TransactionHistoryReceiveTokenAmount{
			TransactionHistoryTokenAmount: TransactionHistoryTokenAmount{
				TokenHash:                 tokenHash,
				TokenData:                 txo.TokenData,
				Amount:                    cloneBigInt(txo.Value),
				OutputType:                cloneIntPtr(txo.OutputType),
				WalletSource:              txo.WalletSource,
				MemoText:                  txo.MemoText,
				HasValidPOIForActiveLists: wallet.POIManager.HasValidPOIsActiveLists(txo.POIsPerList),
			},
			SenderAddress: txo.SenderAddress,
			BalanceBucket: wallet.POIManager.GetBalanceBucket(storedTXOToPOITXO(txo)),
			ShieldFee:     txo.ShieldFee,
		})
	}
	out := make([]TransactionHistoryEntry, 0, len(order))
	for _, txid := range order {
		out = append(out, cloneTransactionHistoryEntry(*byTXID[txid]))
	}
	return out, nil
}

func (wallet *Wallet) transactionSpendHistory(ctx context.Context, txidVersion string, startingBlock *uint64) ([]TransactionHistoryEntry, error) {
	byTXID := map[string]*TransactionHistoryEntry{}
	order := []string{}
	if wallet.SpentPOIEvents != nil {
		sentCommitments, err := wallet.SpentPOIEvents.ListSentCommitmentPOIEvents(ctx)
		if err != nil {
			return nil, err
		}
		for _, event := range sentCommitments {
			if event.Value == nil || event.Value.Sign() == 0 || !historyBlockIncluded(event.BlockNumber, startingBlock) || event.TXID == "" {
				continue
			}
			entry := ensureSpendHistoryEntry(byTXID, &order, txidVersion, event.TXID, event.Timestamp, event.BlockNumber, historyVersionForOutputType(event.OutputType))
			amount, err := tokenAmountFromSentCommitment(wallet.POIManager, event)
			if err != nil {
				return nil, err
			}
			switch outputTypeValue(event.OutputType) {
			case railcrypto.OutputTypeBroadcasterFee:
				entry.BroadcasterFeeTokenAmount = &amount
			case railcrypto.OutputTypeChange:
				entry.ChangeTokenAmounts = append(entry.ChangeTokenAmounts, amount)
			default:
				entry.TransferTokenAmounts = append(entry.TransferTokenAmounts, TransactionHistoryTransferTokenAmount{
					TransactionHistoryTokenAmount: amount,
					RecipientAddress:              event.RecipientAddress,
				})
			}
		}
	}
	if wallet.TXIDStore != nil {
		transactions, err := wallet.TXIDStore.ListTransactions(ctx)
		if err != nil {
			return nil, err
		}
		for _, transaction := range transactions {
			if transaction.Unshield == nil || transaction.Txid == "" || !historyBlockIncluded(transaction.BlockNumber, startingBlock) {
				continue
			}
			entry := ensureSpendHistoryEntry(byTXID, &order, txidVersion, transaction.Txid, nil, transaction.BlockNumber, TransactionHistoryItemVersionUpdatedNov2022)
			amount, err := unshieldTokenAmountFromTransaction(transaction)
			if err != nil {
				return nil, err
			}
			entry.UnshieldTokenAmounts = append(entry.UnshieldTokenAmounts, amount)
		}
	}
	out := make([]TransactionHistoryEntry, 0, len(order))
	for _, txid := range order {
		out = append(out, cloneTransactionHistoryEntry(*byTXID[txid]))
	}
	return out, nil
}

func ensureSpendHistoryEntry(byTXID map[string]*TransactionHistoryEntry, order *[]string, txidVersion string, txid string, timestamp *uint64, blockNumber uint64, version TransactionHistoryItemVersion) *TransactionHistoryEntry {
	entry := byTXID[txid]
	if entry != nil {
		if entry.Timestamp == nil {
			entry.Timestamp = cloneUint64Ptr(timestamp)
		}
		if entry.BlockNumber == 0 {
			entry.BlockNumber = blockNumber
		}
		if version > entry.Version {
			entry.Version = version
		}
		return entry
	}
	entry = &TransactionHistoryEntry{
		TXIDVersion:          txidVersion,
		TXID:                 txid,
		Timestamp:            cloneUint64Ptr(timestamp),
		BlockNumber:          blockNumber,
		ReceiveTokenAmounts:  []TransactionHistoryReceiveTokenAmount{},
		TransferTokenAmounts: []TransactionHistoryTransferTokenAmount{},
		ChangeTokenAmounts:   []TransactionHistoryTokenAmount{},
		UnshieldTokenAmounts: []TransactionHistoryUnshieldTokenAmount{},
		Version:              version,
	}
	byTXID[txid] = entry
	*order = append(*order, txid)
	return entry
}

func filterHistoryTXOs(txos []StoredTXO, startingBlock *uint64) []StoredTXO {
	if startingBlock == nil {
		return txos
	}
	out := []StoredTXO{}
	for _, txo := range txos {
		if historyBlockIncluded(txo.BlockNumber, startingBlock) {
			out = append(out, txo)
		}
	}
	return out
}

func historyBlockIncluded(blockNumber uint64, startingBlock *uint64) bool {
	return startingBlock == nil || blockNumber == 0 || blockNumber >= *startingBlock
}

func findHistoryEntry(history []TransactionHistoryEntry, txid string) *TransactionHistoryEntry {
	for i := range history {
		if history[i].TXID == txid {
			return &history[i]
		}
	}
	return nil
}

func matchingChangeOrLegacyTransfer(entry TransactionHistoryEntry, received TransactionHistoryTokenAmount) (TransactionHistoryTokenAmount, int) {
	for _, change := range entry.ChangeTokenAmounts {
		if tokenAmountsMatch(change, received) {
			return change, -1
		}
	}
	if entry.Version != TransactionHistoryItemVersionLegacy && entry.Version != TransactionHistoryItemVersionUnknown {
		return TransactionHistoryTokenAmount{}, -1
	}
	for i, transfer := range entry.TransferTokenAmounts {
		if tokenAmountsMatch(transfer.TransactionHistoryTokenAmount, received) {
			return transfer.TransactionHistoryTokenAmount, i
		}
	}
	return TransactionHistoryTokenAmount{}, -1
}

func tokenAmountsMatch(left TransactionHistoryTokenAmount, right TransactionHistoryTokenAmount) bool {
	if left.TokenHash != right.TokenHash || left.Amount == nil || right.Amount == nil {
		return false
	}
	return left.Amount.Cmp(right.Amount) == 0
}

func tokenAmountFromSentCommitment(poiManager *railpoi.Manager, event SentCommitmentPOIStatusInput) (TransactionHistoryTokenAmount, error) {
	tokenHash, err := tokenHashForSentCommitment(event)
	if err != nil {
		return TransactionHistoryTokenAmount{}, err
	}
	return TransactionHistoryTokenAmount{
		TokenHash:                 tokenHash,
		TokenData:                 event.TokenData,
		Amount:                    cloneBigInt(event.Value),
		OutputType:                cloneIntPtr(event.OutputType),
		WalletSource:              event.WalletSource,
		MemoText:                  event.MemoText,
		HasValidPOIForActiveLists: poiManager.HasValidPOIsActiveLists(event.POIsPerList),
	}, nil
}

func unshieldTokenAmountFromTransaction(transaction railtxid.Transaction) (TransactionHistoryUnshieldTokenAmount, error) {
	value, err := railcrypto.NumberishToBigInt(transaction.Unshield.Value)
	if err != nil {
		return TransactionHistoryUnshieldTokenAmount{}, fmt.Errorf("unshield value: %w", err)
	}
	tokenHash, err := railcrypto.TokenDataHash(transaction.Unshield.TokenData)
	if err != nil {
		return TransactionHistoryUnshieldTokenAmount{}, err
	}
	return TransactionHistoryUnshieldTokenAmount{
		TransactionHistoryTransferTokenAmount: TransactionHistoryTransferTokenAmount{
			TransactionHistoryTokenAmount: TransactionHistoryTokenAmount{
				TokenHash: tokenHash,
				TokenData: transaction.Unshield.TokenData,
				Amount:    value,
			},
			RecipientAddress: transaction.Unshield.ToAddress,
		},
		UnshieldFee: transaction.Unshield.Fee,
	}, nil
}

func tokenHashForTXO(txo StoredTXO) (string, error) {
	if txo.TokenHash != "" {
		return railcrypto.FormatHexToByteLength(txo.TokenHash, 32, false)
	}
	return railcrypto.TokenDataHash(txo.TokenData)
}

func tokenHashForSentCommitment(event SentCommitmentPOIStatusInput) (string, error) {
	if event.TokenHash != "" {
		return railcrypto.FormatHexToByteLength(event.TokenHash, 32, false)
	}
	return railcrypto.TokenDataHash(event.TokenData)
}

func historyVersionForOutputType(outputType *int) TransactionHistoryItemVersion {
	if outputType == nil {
		return TransactionHistoryItemVersionLegacy
	}
	return TransactionHistoryItemVersionUpdatedNov2022
}

func outputTypeValue(outputType *int) int {
	if outputType == nil {
		return railcrypto.OutputTypeTransfer
	}
	return *outputType
}

func sortTransactionHistory(history []TransactionHistoryEntry) {
	sort.Slice(history, func(i int, j int) bool {
		if history[i].BlockNumber != history[j].BlockNumber {
			return history[i].BlockNumber > history[j].BlockNumber
		}
		if history[i].Timestamp != nil && history[j].Timestamp != nil && *history[i].Timestamp != *history[j].Timestamp {
			return *history[i].Timestamp > *history[j].Timestamp
		}
		return history[i].TXID > history[j].TXID
	})
}

func cloneTransactionHistoryEntry(entry TransactionHistoryEntry) TransactionHistoryEntry {
	entry.Timestamp = cloneUint64Ptr(entry.Timestamp)
	entry.ReceiveTokenAmounts = cloneReceiveHistoryAmounts(entry.ReceiveTokenAmounts)
	entry.TransferTokenAmounts = cloneTransferHistoryAmounts(entry.TransferTokenAmounts)
	entry.ChangeTokenAmounts = cloneHistoryAmounts(entry.ChangeTokenAmounts)
	if entry.BroadcasterFeeTokenAmount != nil {
		amount := cloneHistoryAmount(*entry.BroadcasterFeeTokenAmount)
		entry.BroadcasterFeeTokenAmount = &amount
	}
	entry.UnshieldTokenAmounts = cloneUnshieldHistoryAmounts(entry.UnshieldTokenAmounts)
	return entry
}

func cloneReceiveHistoryAmounts(values []TransactionHistoryReceiveTokenAmount) []TransactionHistoryReceiveTokenAmount {
	out := make([]TransactionHistoryReceiveTokenAmount, len(values))
	for i, value := range values {
		out[i] = value
		out[i].TransactionHistoryTokenAmount = cloneHistoryAmount(value.TransactionHistoryTokenAmount)
	}
	return out
}

func cloneTransferHistoryAmounts(values []TransactionHistoryTransferTokenAmount) []TransactionHistoryTransferTokenAmount {
	out := make([]TransactionHistoryTransferTokenAmount, len(values))
	for i, value := range values {
		out[i] = value
		out[i].TransactionHistoryTokenAmount = cloneHistoryAmount(value.TransactionHistoryTokenAmount)
	}
	return out
}

func cloneUnshieldHistoryAmounts(values []TransactionHistoryUnshieldTokenAmount) []TransactionHistoryUnshieldTokenAmount {
	out := make([]TransactionHistoryUnshieldTokenAmount, len(values))
	for i, value := range values {
		out[i] = value
		out[i].TransactionHistoryTokenAmount = cloneHistoryAmount(value.TransactionHistoryTokenAmount)
	}
	return out
}

func cloneHistoryAmounts(values []TransactionHistoryTokenAmount) []TransactionHistoryTokenAmount {
	out := make([]TransactionHistoryTokenAmount, len(values))
	for i, value := range values {
		out[i] = cloneHistoryAmount(value)
	}
	return out
}

func cloneHistoryAmount(value TransactionHistoryTokenAmount) TransactionHistoryTokenAmount {
	value.Amount = cloneBigInt(value.Amount)
	value.OutputType = cloneIntPtr(value.OutputType)
	return value
}
