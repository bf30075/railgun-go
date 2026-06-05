package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

type SpentPOIEventStore interface {
	UpsertSentCommitmentPOIEvent(ctx context.Context, event SentCommitmentPOIStatusInput) error
	UpsertUnshieldPOIEvent(ctx context.Context, event UnshieldPOIStatusInput) error
	ListSentCommitmentPOIEvents(ctx context.Context) ([]SentCommitmentPOIStatusInput, error)
	ListUnshieldPOIEvents(ctx context.Context) ([]UnshieldPOIStatusInput, error)
	MarkProofSubmitted(ctx context.Context, submissions []railpoi.SubmittedPreTransactionPOI) error
}

type ReorgSpentPOIEventStore interface {
	SpentPOIEventStore
	RollbackToBlock(ctx context.Context, fromBlock uint64) error
}

type MemorySpentPOIEventStore struct {
	mu              sync.RWMutex
	sentCommitments map[string]SentCommitmentPOIStatusInput
	unshieldEvents  map[string]UnshieldPOIStatusInput
}

func NewMemorySpentPOIEventStore() *MemorySpentPOIEventStore {
	return &MemorySpentPOIEventStore{
		sentCommitments: map[string]SentCommitmentPOIStatusInput{},
		unshieldEvents:  map[string]UnshieldPOIStatusInput{},
	}
}

func (store *MemorySpentPOIEventStore) UpsertSentCommitmentPOIEvent(ctx context.Context, event SentCommitmentPOIStatusInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("spent poi event store is required")
	}
	key, err := sentCommitmentPOIEventKey(event)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.sentCommitments == nil {
		store.sentCommitments = map[string]SentCommitmentPOIStatusInput{}
	}
	store.sentCommitments[key] = cloneSentCommitmentPOIStatusInput(event)
	return nil
}

func (store *MemorySpentPOIEventStore) UpsertUnshieldPOIEvent(ctx context.Context, event UnshieldPOIStatusInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("spent poi event store is required")
	}
	key, err := unshieldPOIEventKey(event)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.unshieldEvents == nil {
		store.unshieldEvents = map[string]UnshieldPOIStatusInput{}
	}
	store.unshieldEvents[key] = cloneUnshieldPOIStatusInput(event)
	return nil
}

func (store *MemorySpentPOIEventStore) ListSentCommitmentPOIEvents(ctx context.Context) ([]SentCommitmentPOIStatusInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("spent poi event store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return sortedSentCommitmentPOIEvents(store.sentCommitments), nil
}

func (store *MemorySpentPOIEventStore) ListUnshieldPOIEvents(ctx context.Context) ([]UnshieldPOIStatusInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("spent poi event store is required")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return sortedUnshieldPOIEvents(store.unshieldEvents), nil
}

func (store *MemorySpentPOIEventStore) MarkProofSubmitted(ctx context.Context, submissions []railpoi.SubmittedPreTransactionPOI) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("spent poi event store is required")
	}
	listKeys := submittedPOIListKeys(submissions)
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, event := range store.sentCommitments {
		event.POIsPerList = markPOIsProofSubmitted(event.POIsPerList, listKeys)
		store.sentCommitments[key] = event
	}
	for key, event := range store.unshieldEvents {
		event.POIsPerList = markPOIsProofSubmitted(event.POIsPerList, listKeys)
		store.unshieldEvents[key] = event
	}
	return nil
}

func (store *MemorySpentPOIEventStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("spent poi event store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for key, event := range store.sentCommitments {
		if event.BlockNumber >= fromBlock {
			delete(store.sentCommitments, key)
		}
	}
	for key, event := range store.unshieldEvents {
		if event.BlockNumber >= fromBlock {
			delete(store.unshieldEvents, key)
		}
	}
	return nil
}

type FileSpentPOIEventStore struct {
	Path string
	mu   sync.Mutex
}

func NewFileSpentPOIEventStore(path string) *FileSpentPOIEventStore {
	return &FileSpentPOIEventStore{Path: path}
}

func (store *FileSpentPOIEventStore) UpsertSentCommitmentPOIEvent(ctx context.Context, event SentCommitmentPOIStatusInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := sentCommitmentPOIEventKey(event)
	if err != nil {
		return err
	}
	return store.update(func(state spentPOIEventFileState) (spentPOIEventFileState, error) {
		state.sentCommitments()[key] = cloneSentCommitmentPOIStatusInput(event)
		return state, nil
	})
}

func (store *FileSpentPOIEventStore) UpsertUnshieldPOIEvent(ctx context.Context, event UnshieldPOIStatusInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := unshieldPOIEventKey(event)
	if err != nil {
		return err
	}
	return store.update(func(state spentPOIEventFileState) (spentPOIEventFileState, error) {
		state.unshieldEvents()[key] = cloneUnshieldPOIStatusInput(event)
		return state, nil
	})
}

func (store *FileSpentPOIEventStore) ListSentCommitmentPOIEvents(ctx context.Context) ([]SentCommitmentPOIStatusInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := store.load()
	if err != nil {
		return nil, err
	}
	return sortedSentCommitmentPOIEvents(state.sentCommitments()), nil
}

func (store *FileSpentPOIEventStore) ListUnshieldPOIEvents(ctx context.Context) ([]UnshieldPOIStatusInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := store.load()
	if err != nil {
		return nil, err
	}
	return sortedUnshieldPOIEvents(state.unshieldEvents()), nil
}

func (store *FileSpentPOIEventStore) MarkProofSubmitted(ctx context.Context, submissions []railpoi.SubmittedPreTransactionPOI) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	listKeys := submittedPOIListKeys(submissions)
	return store.update(func(state spentPOIEventFileState) (spentPOIEventFileState, error) {
		for key, event := range state.sentCommitments() {
			event.POIsPerList = markPOIsProofSubmitted(event.POIsPerList, listKeys)
			state.sentCommitments()[key] = event
		}
		for key, event := range state.unshieldEvents() {
			event.POIsPerList = markPOIsProofSubmitted(event.POIsPerList, listKeys)
			state.unshieldEvents()[key] = event
		}
		return state, nil
	})
}

func (store *FileSpentPOIEventStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.update(func(state spentPOIEventFileState) (spentPOIEventFileState, error) {
		for key, event := range state.sentCommitments() {
			if event.BlockNumber >= fromBlock {
				delete(state.sentCommitments(), key)
			}
		}
		for key, event := range state.unshieldEvents() {
			if event.BlockNumber >= fromBlock {
				delete(state.unshieldEvents(), key)
			}
		}
		return state, nil
	})
}

func (store *FileSpentPOIEventStore) update(update func(spentPOIEventFileState) (spentPOIEventFileState, error)) error {
	if store == nil {
		return fmt.Errorf("spent poi event store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.loadLocked()
	if err != nil {
		return err
	}
	state, err = update(state)
	if err != nil {
		return err
	}
	return store.saveLocked(state)
}

func (store *FileSpentPOIEventStore) load() (spentPOIEventFileState, error) {
	if store == nil {
		return spentPOIEventFileState{}, fmt.Errorf("spent poi event store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked()
}

func (store *FileSpentPOIEventStore) loadLocked() (spentPOIEventFileState, error) {
	if store.Path == "" {
		return spentPOIEventFileState{}, fmt.Errorf("spent poi event store file path is required")
	}
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return newSpentPOIEventFileState(), nil
	}
	if err != nil {
		return spentPOIEventFileState{}, err
	}
	if len(data) == 0 {
		return newSpentPOIEventFileState(), nil
	}
	var records spentPOIEventFileRecords
	if err := json.Unmarshal(data, &records); err != nil {
		return spentPOIEventFileState{}, err
	}
	return spentPOIEventFileStateFromRecords(records)
}

func (store *FileSpentPOIEventStore) saveLocked(state spentPOIEventFileState) error {
	if store.Path == "" {
		return fmt.Errorf("spent poi event store file path is required")
	}
	records, err := recordsFromSpentPOIEventFileState(state)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o755); err != nil {
		return err
	}
	tmpPath := store.Path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, store.Path)
}

type spentPOIEventFileState struct {
	sentCommitmentsByKey map[string]SentCommitmentPOIStatusInput
	unshieldEventsByKey  map[string]UnshieldPOIStatusInput
}

func newSpentPOIEventFileState() spentPOIEventFileState {
	return spentPOIEventFileState{
		sentCommitmentsByKey: map[string]SentCommitmentPOIStatusInput{},
		unshieldEventsByKey:  map[string]UnshieldPOIStatusInput{},
	}
}

func (state spentPOIEventFileState) sentCommitments() map[string]SentCommitmentPOIStatusInput {
	if state.sentCommitmentsByKey == nil {
		state.sentCommitmentsByKey = map[string]SentCommitmentPOIStatusInput{}
	}
	return state.sentCommitmentsByKey
}

func (state spentPOIEventFileState) unshieldEvents() map[string]UnshieldPOIStatusInput {
	if state.unshieldEventsByKey == nil {
		state.unshieldEventsByKey = map[string]UnshieldPOIStatusInput{}
	}
	return state.unshieldEventsByKey
}

type spentPOIEventFileRecords struct {
	SentCommitments []sentCommitmentPOIEventRecord `json:"sentCommitments"`
	UnshieldEvents  []unshieldPOIEventRecord       `json:"unshieldEvents"`
}

type sentCommitmentPOIEventRecord struct {
	TXID              string               `json:"txid"`
	RailgunTxid       string               `json:"railgunTxid"`
	Timestamp         *uint64              `json:"timestamp,omitempty"`
	BlockNumber       uint64               `json:"blockNumber"`
	CommitmentHash    string               `json:"commitmentHash,omitempty"`
	BlindedCommitment string               `json:"blindedCommitment,omitempty"`
	TokenHash         string               `json:"tokenHash,omitempty"`
	TokenData         railcrypto.TokenData `json:"tokenData,omitempty"`
	Value             string               `json:"value,omitempty"`
	OutputType        *int                 `json:"outputType,omitempty"`
	WalletSource      string               `json:"walletSource,omitempty"`
	MemoText          string               `json:"memoText,omitempty"`
	SenderAddress     string               `json:"senderAddress,omitempty"`
	RecipientAddress  string               `json:"recipientAddress,omitempty"`
	POIsPerList       railpoi.POIsPerList  `json:"poisPerList,omitempty"`
}

type unshieldPOIEventRecord struct {
	TXID           string              `json:"txid"`
	RailgunTxid    string              `json:"railgunTxid"`
	BlockNumber    uint64              `json:"blockNumber"`
	CommitmentHash string              `json:"commitmentHash,omitempty"`
	POIsPerList    railpoi.POIsPerList `json:"poisPerList,omitempty"`
}

func spentPOIEventFileStateFromRecords(records spentPOIEventFileRecords) (spentPOIEventFileState, error) {
	state := newSpentPOIEventFileState()
	for i, record := range records.SentCommitments {
		event, err := sentCommitmentPOIEventFromRecord(record)
		if err != nil {
			return spentPOIEventFileState{}, fmt.Errorf("sentCommitments[%d]: %w", i, err)
		}
		key, err := sentCommitmentPOIEventKey(event)
		if err != nil {
			return spentPOIEventFileState{}, fmt.Errorf("sentCommitments[%d]: %w", i, err)
		}
		state.sentCommitmentsByKey[key] = event
	}
	for i, record := range records.UnshieldEvents {
		event := UnshieldPOIStatusInput{
			TXID:           record.TXID,
			RailgunTxid:    record.RailgunTxid,
			BlockNumber:    record.BlockNumber,
			CommitmentHash: record.CommitmentHash,
			POIsPerList:    clonePOIsPerList(record.POIsPerList),
		}
		key, err := unshieldPOIEventKey(event)
		if err != nil {
			return spentPOIEventFileState{}, fmt.Errorf("unshieldEvents[%d]: %w", i, err)
		}
		state.unshieldEventsByKey[key] = event
	}
	return state, nil
}

func recordsFromSpentPOIEventFileState(state spentPOIEventFileState) (spentPOIEventFileRecords, error) {
	sentEvents := sortedSentCommitmentPOIEvents(state.sentCommitments())
	sentRecords := make([]sentCommitmentPOIEventRecord, len(sentEvents))
	for i, event := range sentEvents {
		sentRecords[i] = recordFromSentCommitmentPOIEvent(event)
	}
	unshieldEvents := sortedUnshieldPOIEvents(state.unshieldEvents())
	unshieldRecords := make([]unshieldPOIEventRecord, len(unshieldEvents))
	for i, event := range unshieldEvents {
		unshieldRecords[i] = recordFromUnshieldPOIEvent(event)
	}
	return spentPOIEventFileRecords{
		SentCommitments: sentRecords,
		UnshieldEvents:  unshieldRecords,
	}, nil
}

func sentCommitmentPOIEventFromRecord(record sentCommitmentPOIEventRecord) (SentCommitmentPOIStatusInput, error) {
	var value *big.Int
	if record.Value != "" {
		parsed, ok := new(big.Int).SetString(record.Value, 10)
		if !ok {
			return SentCommitmentPOIStatusInput{}, fmt.Errorf("invalid value %q", record.Value)
		}
		value = parsed
	}
	return SentCommitmentPOIStatusInput{
		TXID:              record.TXID,
		RailgunTxid:       record.RailgunTxid,
		Timestamp:         cloneUint64Ptr(record.Timestamp),
		BlockNumber:       record.BlockNumber,
		CommitmentHash:    record.CommitmentHash,
		BlindedCommitment: record.BlindedCommitment,
		TokenHash:         record.TokenHash,
		TokenData:         record.TokenData,
		Value:             value,
		OutputType:        cloneIntPtr(record.OutputType),
		WalletSource:      record.WalletSource,
		MemoText:          record.MemoText,
		SenderAddress:     record.SenderAddress,
		RecipientAddress:  record.RecipientAddress,
		POIsPerList:       clonePOIsPerList(record.POIsPerList),
	}, nil
}

func recordFromSentCommitmentPOIEvent(event SentCommitmentPOIStatusInput) sentCommitmentPOIEventRecord {
	value := ""
	if event.Value != nil {
		value = event.Value.String()
	}
	return sentCommitmentPOIEventRecord{
		TXID:              event.TXID,
		RailgunTxid:       event.RailgunTxid,
		Timestamp:         cloneUint64Ptr(event.Timestamp),
		BlockNumber:       event.BlockNumber,
		CommitmentHash:    event.CommitmentHash,
		BlindedCommitment: event.BlindedCommitment,
		TokenHash:         event.TokenHash,
		TokenData:         event.TokenData,
		Value:             value,
		OutputType:        cloneIntPtr(event.OutputType),
		WalletSource:      event.WalletSource,
		MemoText:          event.MemoText,
		SenderAddress:     event.SenderAddress,
		RecipientAddress:  event.RecipientAddress,
		POIsPerList:       clonePOIsPerList(event.POIsPerList),
	}
}

func recordFromUnshieldPOIEvent(event UnshieldPOIStatusInput) unshieldPOIEventRecord {
	return unshieldPOIEventRecord{
		TXID:           event.TXID,
		RailgunTxid:    event.RailgunTxid,
		BlockNumber:    event.BlockNumber,
		CommitmentHash: event.CommitmentHash,
		POIsPerList:    clonePOIsPerList(event.POIsPerList),
	}
}

func sortedSentCommitmentPOIEvents(events map[string]SentCommitmentPOIStatusInput) []SentCommitmentPOIStatusInput {
	out := make([]SentCommitmentPOIStatusInput, 0, len(events))
	for _, event := range events {
		out = append(out, cloneSentCommitmentPOIStatusInput(event))
	}
	sort.Slice(out, func(i int, j int) bool {
		if out[i].BlockNumber != out[j].BlockNumber {
			return out[i].BlockNumber < out[j].BlockNumber
		}
		if out[i].TXID != out[j].TXID {
			return out[i].TXID < out[j].TXID
		}
		if out[i].RailgunTxid != out[j].RailgunTxid {
			return out[i].RailgunTxid < out[j].RailgunTxid
		}
		if out[i].CommitmentHash != out[j].CommitmentHash {
			return out[i].CommitmentHash < out[j].CommitmentHash
		}
		return out[i].BlindedCommitment < out[j].BlindedCommitment
	})
	return out
}

func sortedUnshieldPOIEvents(events map[string]UnshieldPOIStatusInput) []UnshieldPOIStatusInput {
	out := make([]UnshieldPOIStatusInput, 0, len(events))
	for _, event := range events {
		out = append(out, cloneUnshieldPOIStatusInput(event))
	}
	sort.Slice(out, func(i int, j int) bool {
		if out[i].BlockNumber != out[j].BlockNumber {
			return out[i].BlockNumber < out[j].BlockNumber
		}
		if out[i].TXID != out[j].TXID {
			return out[i].TXID < out[j].TXID
		}
		if out[i].RailgunTxid != out[j].RailgunTxid {
			return out[i].RailgunTxid < out[j].RailgunTxid
		}
		return out[i].CommitmentHash < out[j].CommitmentHash
	})
	return out
}

func cloneSentCommitmentPOIStatusInput(event SentCommitmentPOIStatusInput) SentCommitmentPOIStatusInput {
	event.Timestamp = cloneUint64Ptr(event.Timestamp)
	event.Value = cloneBigInt(event.Value)
	event.OutputType = cloneIntPtr(event.OutputType)
	event.POIsPerList = clonePOIsPerList(event.POIsPerList)
	return event
}

func cloneUnshieldPOIStatusInput(event UnshieldPOIStatusInput) UnshieldPOIStatusInput {
	event.POIsPerList = clonePOIsPerList(event.POIsPerList)
	return event
}

func sentCommitmentPOIEventKey(event SentCommitmentPOIStatusInput) (string, error) {
	if event.TXID == "" && event.RailgunTxid == "" && event.CommitmentHash == "" && event.BlindedCommitment == "" && event.BlockNumber == 0 {
		return "", fmt.Errorf("sent commitment poi event identifier is required")
	}
	return fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", event.BlockNumber, event.TXID, event.RailgunTxid, event.CommitmentHash, event.BlindedCommitment), nil
}

func unshieldPOIEventKey(event UnshieldPOIStatusInput) (string, error) {
	if event.TXID == "" && event.RailgunTxid == "" && event.CommitmentHash == "" && event.BlockNumber == 0 {
		return "", fmt.Errorf("unshield poi event identifier is required")
	}
	return fmt.Sprintf("%d\x00%s\x00%s\x00%s", event.BlockNumber, event.TXID, event.RailgunTxid, event.CommitmentHash), nil
}

func submittedPOIListKeys(submissions []railpoi.SubmittedPreTransactionPOI) []string {
	listKeys := make([]string, 0, len(submissions))
	for _, submission := range submissions {
		if submission.SubmitRequest.ListKey != "" {
			listKeys = append(listKeys, submission.SubmitRequest.ListKey)
		}
	}
	return listKeys
}
