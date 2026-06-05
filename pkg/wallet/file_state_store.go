package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

type FileStateStore struct {
	Path string
	mu   sync.Mutex
}

func NewFileStateStore(path string) *FileStateStore {
	return &FileStateStore{Path: path}
}

func (store *FileStateStore) UpsertTXO(ctx context.Context, txo StoredTXO) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if txo.Nullifier == "" {
		return fmt.Errorf("txo nullifier is required")
	}
	return store.update(func(txos map[string]StoredTXO) error {
		txos[txo.Nullifier] = cloneStoredTXO(txo)
		return nil
	})
}

func (store *FileStateStore) GetTXO(ctx context.Context, nullifier string) (StoredTXO, bool, error) {
	if err := ctx.Err(); err != nil {
		return StoredTXO{}, false, err
	}
	txos, err := store.load()
	if err != nil {
		return StoredTXO{}, false, err
	}
	txo, ok := txos[nullifier]
	if !ok {
		return StoredTXO{}, false, nil
	}
	return cloneStoredTXO(txo), true, nil
}

func (store *FileStateStore) ListTXOs(ctx context.Context) ([]StoredTXO, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	txos, err := store.load()
	if err != nil {
		return nil, err
	}
	return sortedTXOs(txos), nil
}

func (store *FileStateStore) MarkTXOSpent(ctx context.Context, nullifier string, spendTXID string) error {
	return store.markTXOSpent(ctx, nullifier, spendTXID, nil)
}

func (store *FileStateStore) MarkTXOSpentAtBlock(ctx context.Context, nullifier string, spendTXID string, blockNumber uint64) error {
	return store.markTXOSpent(ctx, nullifier, spendTXID, &blockNumber)
}

func (store *FileStateStore) markTXOSpent(ctx context.Context, nullifier string, spendTXID string, blockNumber *uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.update(func(txos map[string]StoredTXO) error {
		txo, ok := txos[nullifier]
		if !ok {
			return fmt.Errorf("missing txo for nullifier %s", nullifier)
		}
		txo.SpendTXID = spendTXID
		txo.SpendBlockNumber = cloneUint64Ptr(blockNumber)
		txos[nullifier] = txo
		return nil
	})
}

func (store *FileStateStore) RollbackToBlock(ctx context.Context, fromBlock uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.update(func(txos map[string]StoredTXO) error {
		for nullifier, txo := range txos {
			if txo.BlockNumber >= fromBlock {
				delete(txos, nullifier)
				continue
			}
			if txo.SpendBlockNumber != nil && *txo.SpendBlockNumber >= fromBlock {
				txo.SpendTXID = ""
				txo.SpendBlockNumber = nil
				txos[nullifier] = txo
			}
		}
		return nil
	})
}

func (store *FileStateStore) UpdateTXOPOIs(ctx context.Context, nullifier string, pois railpoi.POIsPerList) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return store.update(func(txos map[string]StoredTXO) error {
		txo, ok := txos[nullifier]
		if !ok {
			return fmt.Errorf("missing txo for nullifier %s", nullifier)
		}
		txo.POIsPerList = clonePOIsPerList(pois)
		txos[nullifier] = txo
		return nil
	})
}

func (store *FileStateStore) TokenBalances(ctx context.Context, poiManager *railpoi.Manager, includedBuckets []string) (TokenBalances, error) {
	if poiManager == nil {
		return nil, fmt.Errorf("poi manager is required")
	}
	txos, err := store.ListTXOs(ctx)
	if err != nil {
		return nil, err
	}
	return tokenBalancesFromTXOs(txos, poiManager, includedBuckets)
}

func (store *FileStateStore) update(update func(map[string]StoredTXO) error) error {
	if store == nil {
		return fmt.Errorf("state store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	txos, err := store.loadLocked()
	if err != nil {
		return err
	}
	if err := update(txos); err != nil {
		return err
	}
	return store.saveLocked(txos)
}

func (store *FileStateStore) load() (map[string]StoredTXO, error) {
	if store == nil {
		return nil, fmt.Errorf("state store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked()
}

func (store *FileStateStore) loadLocked() (map[string]StoredTXO, error) {
	if store.Path == "" {
		return nil, fmt.Errorf("state store file path is required")
	}
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]StoredTXO{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return map[string]StoredTXO{}, nil
	}
	var state fileState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	txos := make(map[string]StoredTXO, len(state.TXOs))
	for i, record := range state.TXOs {
		txo, err := storedTXOFromRecord(record)
		if err != nil {
			return nil, fmt.Errorf("txos[%d]: %w", i, err)
		}
		if txo.Nullifier == "" {
			return nil, fmt.Errorf("txos[%d]: nullifier is required", i)
		}
		txos[txo.Nullifier] = txo
	}
	return txos, nil
}

func (store *FileStateStore) saveLocked(txos map[string]StoredTXO) error {
	if store.Path == "" {
		return fmt.Errorf("state store file path is required")
	}
	records := make([]storedTXORecord, 0, len(txos))
	for _, txo := range sortedTXOs(txos) {
		record, err := recordFromStoredTXO(txo)
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	data, err := json.MarshalIndent(fileState{TXOs: records}, "", "  ")
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

type fileState struct {
	TXOs []storedTXORecord `json:"txos"`
}

type storedTXORecord struct {
	TXIDVersion                 string               `json:"txidVersion"`
	Tree                        uint64               `json:"tree"`
	Position                    uint64               `json:"position"`
	TXID                        string               `json:"txid"`
	Timestamp                   *uint64              `json:"timestamp,omitempty"`
	BlockNumber                 uint64               `json:"blockNumber"`
	SpendTXID                   string               `json:"spendTxid,omitempty"`
	SpendBlockNumber            *uint64              `json:"spendBlockNumber,omitempty"`
	Nullifier                   string               `json:"nullifier"`
	CommitmentHash              string               `json:"commitmentHash,omitempty"`
	NotePublicKey               string               `json:"notePublicKey,omitempty"`
	NoteRandom                  string               `json:"noteRandom,omitempty"`
	TokenHash                   string               `json:"tokenHash"`
	TokenData                   railcrypto.TokenData `json:"tokenData"`
	Value                       string               `json:"value"`
	OutputType                  *int                 `json:"outputType,omitempty"`
	WalletSource                string               `json:"walletSource,omitempty"`
	MemoText                    string               `json:"memoText,omitempty"`
	SenderAddress               string               `json:"senderAddress,omitempty"`
	RecipientAddress            string               `json:"recipientAddress,omitempty"`
	ShieldFee                   string               `json:"shieldFee,omitempty"`
	CommitmentType              string               `json:"commitmentType"`
	POIsPerList                 railpoi.POIsPerList  `json:"poisPerList,omitempty"`
	BlindedCommitment           string               `json:"blindedCommitment,omitempty"`
	TransactCreationRailgunTxid string               `json:"transactCreationRailgunTxid,omitempty"`
}

func recordFromStoredTXO(txo StoredTXO) (storedTXORecord, error) {
	if txo.Value == nil {
		return storedTXORecord{}, fmt.Errorf("txo %s value is required", txo.Nullifier)
	}
	return storedTXORecord{
		TXIDVersion:                 txo.TXIDVersion,
		Tree:                        txo.Tree,
		Position:                    txo.Position,
		TXID:                        txo.TXID,
		Timestamp:                   cloneUint64Ptr(txo.Timestamp),
		BlockNumber:                 txo.BlockNumber,
		SpendTXID:                   txo.SpendTXID,
		SpendBlockNumber:            cloneUint64Ptr(txo.SpendBlockNumber),
		Nullifier:                   txo.Nullifier,
		CommitmentHash:              txo.CommitmentHash,
		NotePublicKey:               txo.NotePublicKey,
		NoteRandom:                  txo.NoteRandom,
		TokenHash:                   txo.TokenHash,
		TokenData:                   txo.TokenData,
		Value:                       txo.Value.String(),
		OutputType:                  cloneIntPtr(txo.OutputType),
		WalletSource:                txo.WalletSource,
		MemoText:                    txo.MemoText,
		SenderAddress:               txo.SenderAddress,
		RecipientAddress:            txo.RecipientAddress,
		ShieldFee:                   txo.ShieldFee,
		CommitmentType:              txo.CommitmentType,
		POIsPerList:                 clonePOIsPerList(txo.POIsPerList),
		BlindedCommitment:           txo.BlindedCommitment,
		TransactCreationRailgunTxid: txo.TransactCreationRailgunTxid,
	}, nil
}

func storedTXOFromRecord(record storedTXORecord) (StoredTXO, error) {
	value, ok := new(big.Int).SetString(record.Value, 10)
	if !ok {
		return StoredTXO{}, fmt.Errorf("invalid value %q", record.Value)
	}
	return StoredTXO{
		TXIDVersion:                 record.TXIDVersion,
		Tree:                        record.Tree,
		Position:                    record.Position,
		TXID:                        record.TXID,
		Timestamp:                   cloneUint64Ptr(record.Timestamp),
		BlockNumber:                 record.BlockNumber,
		SpendTXID:                   record.SpendTXID,
		SpendBlockNumber:            cloneUint64Ptr(record.SpendBlockNumber),
		Nullifier:                   record.Nullifier,
		CommitmentHash:              record.CommitmentHash,
		NotePublicKey:               record.NotePublicKey,
		NoteRandom:                  record.NoteRandom,
		TokenHash:                   record.TokenHash,
		TokenData:                   record.TokenData,
		Value:                       value,
		OutputType:                  cloneIntPtr(record.OutputType),
		WalletSource:                record.WalletSource,
		MemoText:                    record.MemoText,
		SenderAddress:               record.SenderAddress,
		RecipientAddress:            record.RecipientAddress,
		ShieldFee:                   record.ShieldFee,
		CommitmentType:              record.CommitmentType,
		POIsPerList:                 clonePOIsPerList(record.POIsPerList),
		BlindedCommitment:           record.BlindedCommitment,
		TransactCreationRailgunTxid: record.TransactCreationRailgunTxid,
	}, nil
}
