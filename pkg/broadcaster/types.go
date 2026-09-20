package broadcaster

import railchain "github.com/bf30075/railgun-go/pkg/chain"

// ConnectionStatus mirrors BroadcasterConnectionStatus from shared-models.
type ConnectionStatus string

const (
	StatusError          ConnectionStatus = "Error"
	StatusSearching      ConnectionStatus = "Searching"
	StatusConnected      ConnectionStatus = "Connected"
	StatusDisconnected   ConnectionStatus = "Disconnected"
	StatusAllUnavailable ConnectionStatus = "AllUnavailable"
)

// CachedTokenFee is one broadcaster fee quote for a token.
type CachedTokenFee struct {
	FeePerUnitGas    string `json:"feePerUnitGas"`
	Expiration       int64  `json:"expiration"`
	FeesID           string `json:"feesID"`
	AvailableWallets int    `json:"availableWallets"`
	RelayAdapt       string `json:"relayAdapt"`
	RelayAdapt7702   string `json:"relayAdapt7702,omitempty"`
	Reliability      float64 `json:"reliability"`
}

// SelectedBroadcaster is a fee quote bound to a broadcaster address.
type SelectedBroadcaster struct {
	RailgunAddress string         `json:"railgunAddress"`
	TokenAddress   string         `json:"tokenAddress"`
	TokenFee       CachedTokenFee `json:"tokenFee"`
}

// FeeMessageData is the signed fee announcement payload (after hex→UTF8 JSON).
type FeeMessageData struct {
	Fees                map[string]string `json:"fees"`
	FeeExpiration       int64             `json:"feeExpiration"`
	FeesID              string            `json:"feesID"`
	RailgunAddress      string            `json:"railgunAddress"`
	Identifier          string            `json:"identifier"`
	AvailableWallets    int               `json:"availableWallets"`
	Version             string            `json:"version"`
	RelayAdapt          string            `json:"relayAdapt"`
	RelayAdapt7702      string            `json:"relayAdapt7702,omitempty"`
	RequiredPOIListKeys []string          `json:"requiredPOIListKeys"`
	Reliability         float64           `json:"reliability"`
}

// FeeMessage is the Waku fees payload envelope.
type FeeMessage struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

// EncryptedData is [iv||tag, ciphertext] as used by the engine ECIES helpers.
type EncryptedData [2]string

// EncryptedMethodParams is the lightpush transact body.
type EncryptedMethodParams struct {
	Pubkey        string        `json:"pubkey"`
	EncryptedData EncryptedData `json:"encryptedData"`
}

// TransactRequestType discriminates COMMON vs TX7702 payloads.
type TransactRequestType string

const (
	TransactRequestCommon TransactRequestType = "COMMON"
	TransactRequestTX7702 TransactRequestType = "TX7702"
)

// RawParamsTransact is the plaintext object encrypted for a broadcaster.
type RawParamsTransact struct {
	TransactType                          TransactRequestType         `json:"transactType"`
	TXIDVersion                           string                      `json:"txidVersion"`
	To                                    string                      `json:"to"`
	Data                                  string                      `json:"data"`
	BroadcasterViewingKey                 string                      `json:"broadcasterViewingKey"`
	ChainID                               uint64                      `json:"chainID"`
	ChainType                             int                         `json:"chainType"`
	MinGasPrice                           string                      `json:"minGasPrice"`
	FeesID                                string                      `json:"feesID"`
	UseRelayAdapt                         bool                        `json:"useRelayAdapt"`
	DevLog                                bool                        `json:"devLog"`
	MinVersion                            string                      `json:"minVersion"`
	MaxVersion                            string                      `json:"maxVersion"`
	PreTransactionPOIsPerTxidLeafPerList  map[string]map[string]any   `json:"preTransactionPOIsPerTxidLeafPerList"`
}

// TransactResponse is the decrypted broadcaster reply.
type TransactResponse struct {
	ID     string `json:"id"`
	TxHash string `json:"txHash,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Message is a decoded Waku payload delivered to observers.
type Message struct {
	Payload      []byte
	ContentTopic string
	TimestampMS  int64
}

// StatusCallback receives connection status updates.
type StatusCallback func(chain railchain.Chain, status ConnectionStatus)

// Debugger mirrors BroadcasterDebugger.
type Debugger interface {
	Log(msg string)
	Error(err error)
}

type nopDebugger struct{}

func (nopDebugger) Log(string)  {}
func (nopDebugger) Error(error) {}

// NullifierTxidLookup optionally resolves an already-mined tx from nullifiers
// while waiting for a broadcaster response (getCompletedTxidFromNullifiers).
type NullifierTxidLookup func(txidVersion string, chain railchain.Chain, nullifiers []string) (txid string, ok bool, err error)
