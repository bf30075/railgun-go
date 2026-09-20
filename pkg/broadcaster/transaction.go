package broadcaster

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	railaddress "github.com/bf30075/railgun-go/pkg/address"
	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const (
	secondsPerRetry             = 2
	pollDelay                   = 100 * time.Millisecond
	retryTransactionSeconds     = 20
	postAlertTotalWaitingSeconds = 120
)

// Transaction is an encrypted broadcaster submission, mirroring BroadcasterTransaction.
type Transaction struct {
	messageData   map[string]any
	contentTopic  string
	txidVersion   string
	chain         railchain.Chain
	nullifiers    []string
	transport     Transport
	responses     *TransactResponseStore
	cfg           *Config
	dbg           Debugger
	nullifierLook NullifierTxidLookup
}

// CreateTransaction encrypts a COMMON transact payload for the selected broadcaster.
func CreateTransaction(
	txidVersion string,
	to string,
	data string,
	broadcasterRailgunAddress string,
	broadcasterFeesID string,
	chain railchain.Chain,
	nullifiers []string,
	overallBatchMinGasPrice string,
	useRelayAdapt bool,
	preTransactionPOIs map[string]map[string]any,
	transport Transport,
	responses *TransactResponseStore,
	cfg *Config,
	dbg Debugger,
	nullifierLookup NullifierTxidLookup,
) (*Transaction, error) {
	if !strings.HasPrefix(data, "0x") && !strings.HasPrefix(data, "0X") {
		return nil, fmt.Errorf("data field must be a hex string")
	}
	if dbg == nil {
		dbg = nopDebugger{}
	}
	addressData, err := railaddress.Decode(broadcasterRailgunAddress)
	if err != nil {
		return nil, err
	}
	viewingPub, err := railcrypto.HexToBytes(addressData.ViewingPublicKey)
	if err != nil {
		return nil, err
	}
	if preTransactionPOIs == nil {
		preTransactionPOIs = map[string]map[string]any{}
	}
	raw := RawParamsTransact{
		TransactType:                         TransactRequestCommon,
		TXIDVersion:                          txidVersion,
		To:                                   checksumAddress(to),
		Data:                                 data,
		BroadcasterViewingKey:                railcrypto.BytesToHex(viewingPub, false),
		ChainID:                              chain.ID,
		ChainType:                            chain.Type,
		MinGasPrice:                          overallBatchMinGasPrice,
		FeesID:                               broadcasterFeesID,
		UseRelayAdapt:                        useRelayAdapt,
		DevLog:                               cfg.IsDev,
		MinVersion:                           cfg.MinimumBroadcasterVersion,
		MaxVersion:                           cfg.MaximumBroadcasterVersion,
		PreTransactionPOIsPerTxidLeafPerList: preTransactionPOIs,
	}
	encrypted, err := EncryptDataWithSharedKey(raw, viewingPub)
	if err != nil {
		return nil, err
	}
	responses.SetSharedKey(encrypted.SharedKey)
	return &Transaction{
		messageData: map[string]any{
			"method": "transact",
			"params": EncryptedMethodParams{
				Pubkey:        encrypted.RandomPubKey,
				EncryptedData: encrypted.EncryptedData,
			},
		},
		contentTopic:  ContentTopicTransact(chain),
		txidVersion:   txidVersion,
		chain:         chain,
		nullifiers:    append([]string{}, nullifiers...),
		transport:     transport,
		responses:     responses,
		cfg:           cfg,
		dbg:           dbg,
		nullifierLook: nullifierLookup,
	}, nil
}

// Send broadcasts the encrypted payload and waits for a tx hash or error.
func (tx *Transaction) Send(ctx context.Context) (string, error) {
	return tx.broadcast(ctx, 0)
}

func (tx *Transaction) broadcast(ctx context.Context, retryNumber int) (string, error) {
	switch broadcastRetryState(retryNumber) {
	case retryTransact:
		tx.dbg.Log(fmt.Sprintf("Broadcast Waku message: transact via %s", tx.contentTopic))
		payload, err := json.Marshal(tx.messageData)
		if err != nil {
			return "", err
		}
		if err := tx.transport.Publish(ctx, tx.contentTopic, payload); err != nil {
			tx.dbg.Log("Broadcast error: " + err.Error())
		}
	case retryWait:
		// wait only
	case retryTimeout:
		tx.responses.Clear()
		return "", fmt.Errorf("request timed out")
	}

	_ = tx.transport.QueryStore(ctx, ContentTopicTransactResponse(tx.chain), int64(tx.cfg.HistoricalLookBackMS), func(msg Message) {
		tx.responses.HandleMessage(msg, tx.dbg)
	})

	deadline := time.Now().Add(secondsPerRetry * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			tx.responses.Clear()
			return "", err
		}
		if resp, ok := tx.responses.Get(); ok {
			if resp.TxHash != "" {
				tx.responses.Clear()
				return resp.TxHash, nil
			}
			if resp.Error != "" {
				tx.responses.Clear()
				return "", fmt.Errorf("received response error from broadcaster: %s", resp.Error)
			}
		}
		if tx.nullifierLook != nil {
			txid, ok, err := tx.nullifierLook(tx.txidVersion, tx.chain, tx.nullifiers)
			if err != nil {
				tx.dbg.Error(err)
			} else if ok && txid != "" {
				tx.responses.Clear()
				return txid, nil
			}
		}
		select {
		case <-ctx.Done():
			tx.responses.Clear()
			return "", ctx.Err()
		case <-time.After(pollDelay):
		}
	}
	return tx.broadcast(ctx, retryNumber+1)
}

type retryState int

const (
	retryTransact retryState = iota
	retryWait
	retryTimeout
)

func broadcastRetryState(retryNumber int) retryState {
	retrySeconds := retryNumber * secondsPerRetry
	if retrySeconds <= retryTransactionSeconds {
		return retryTransact
	}
	if retrySeconds >= postAlertTotalWaitingSeconds {
		return retryTimeout
	}
	return retryWait
}

func checksumAddress(address string) string {
	// Upstream uses ethers getAddress. We normalize to lowercase 0x-prefixed hex.
	address = strings.TrimSpace(address)
	if !strings.HasPrefix(address, "0x") && !strings.HasPrefix(address, "0X") {
		address = "0x" + address
	}
	return "0x" + strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(address, "0x"), "0X"))
}
