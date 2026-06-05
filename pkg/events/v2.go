package events

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const (
	CommitmentTypeShield     = "ShieldCommitment"
	CommitmentTypeTransactV2 = "TransactCommitmentV2"
)

const railgunSmartWalletV2EventsABI = `[
  {
    "anonymous": false,
    "type": "event",
    "name": "Nullified",
    "inputs": [
      {"indexed": false, "name": "treeNumber", "type": "uint16"},
      {"indexed": false, "name": "nullifier", "type": "bytes32[]"}
    ]
  },
  {
    "anonymous": false,
    "type": "event",
    "name": "Shield",
    "inputs": [
      {"indexed": false, "name": "treeNumber", "type": "uint256"},
      {"indexed": false, "name": "startPosition", "type": "uint256"},
      {
        "indexed": false,
        "name": "commitments",
        "type": "tuple[]",
        "components": [
          {"name": "npk", "type": "bytes32"},
          {
            "name": "token",
            "type": "tuple",
            "components": [
              {"name": "tokenType", "type": "uint8"},
              {"name": "tokenAddress", "type": "address"},
              {"name": "tokenSubID", "type": "uint256"}
            ]
          },
          {"name": "value", "type": "uint120"}
        ]
      },
      {
        "indexed": false,
        "name": "shieldCiphertext",
        "type": "tuple[]",
        "components": [
          {"name": "encryptedBundle", "type": "bytes32[3]"},
          {"name": "shieldKey", "type": "bytes32"}
        ]
      },
      {"indexed": false, "name": "fees", "type": "uint256[]"}
    ]
  },
  {
    "anonymous": false,
    "type": "event",
    "name": "Transact",
    "inputs": [
      {"indexed": false, "name": "treeNumber", "type": "uint256"},
      {"indexed": false, "name": "startPosition", "type": "uint256"},
      {"indexed": false, "name": "hash", "type": "bytes32[]"},
      {
        "indexed": false,
        "name": "ciphertext",
        "type": "tuple[]",
        "components": [
          {"name": "ciphertext", "type": "bytes32[4]"},
          {"name": "blindedSenderViewingKey", "type": "bytes32"},
          {"name": "blindedReceiverViewingKey", "type": "bytes32"},
          {"name": "annotationData", "type": "bytes"},
          {"name": "memo", "type": "bytes"}
        ]
      }
    ]
  },
  {
    "anonymous": false,
    "type": "event",
    "name": "Unshield",
    "inputs": [
      {"indexed": false, "name": "to", "type": "address"},
      {
        "indexed": false,
        "name": "token",
        "type": "tuple",
        "components": [
          {"name": "tokenType", "type": "uint8"},
          {"name": "tokenAddress", "type": "address"},
          {"name": "tokenSubID", "type": "uint256"}
        ]
      },
      {"indexed": false, "name": "amount", "type": "uint256"},
      {"indexed": false, "name": "fee", "type": "uint256"}
    ]
  }
]`

type ContractLog struct {
	Topics          []string `json:"topics"`
	Data            string   `json:"data"`
	TransactionHash string   `json:"transactionHash"`
	BlockNumber     uint64   `json:"blockNumber"`
	Index           uint     `json:"index"`
}

type CommitmentEvent struct {
	Txid          string       `json:"txid"`
	TreeNumber    int          `json:"treeNumber"`
	StartPosition int          `json:"startPosition"`
	Commitments   []Commitment `json:"commitments"`
	BlockNumber   uint64       `json:"blockNumber"`
}

type Commitment struct {
	CommitmentType               string                       `json:"commitmentType"`
	Hash                         string                       `json:"hash"`
	Txid                         string                       `json:"txid"`
	Timestamp                    *uint64                      `json:"timestamp,omitempty"`
	BlockNumber                  uint64                       `json:"blockNumber"`
	UTXOTree                     int                          `json:"utxoTree"`
	UTXOIndex                    int                          `json:"utxoIndex"`
	PreImage                     *PreImage                    `json:"preImage,omitempty"`
	EncryptedBundle              []string                     `json:"encryptedBundle,omitempty"`
	ShieldKey                    string                       `json:"shieldKey,omitempty"`
	Fee                          string                       `json:"fee,omitempty"`
	From                         string                       `json:"from,omitempty"`
	Ciphertext                   *CommitmentCiphertextV2Event `json:"ciphertext,omitempty"`
	RailgunTxid                  string                       `json:"railgunTxid,omitempty"`
	SenderCiphertext             string                       `json:"senderCiphertext,omitempty"`
	TransactCommitmentBatchIndex *int                         `json:"transactCommitmentBatchIndex,omitempty"`
}

type PreImage struct {
	NPK   string               `json:"npk"`
	Token railcrypto.TokenData `json:"token"`
	Value string               `json:"value"`
}

type CommitmentCiphertextV2Event struct {
	Ciphertext                railcrypto.CiphertextGCM `json:"ciphertext"`
	BlindedSenderViewingKey   string                   `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string                   `json:"blindedReceiverViewingKey"`
	AnnotationData            string                   `json:"annotationData"`
	Memo                      string                   `json:"memo"`
}

type UnshieldStoredEvent struct {
	Txid          string  `json:"txid"`
	Timestamp     *uint64 `json:"timestamp,omitempty"`
	ToAddress     string  `json:"toAddress"`
	TokenType     int     `json:"tokenType"`
	TokenAddress  string  `json:"tokenAddress"`
	TokenSubID    string  `json:"tokenSubID"`
	Amount        string  `json:"amount"`
	Fee           string  `json:"fee"`
	BlockNumber   uint64  `json:"blockNumber"`
	EventLogIndex *uint   `json:"eventLogIndex,omitempty"`
	RailgunTxid   string  `json:"railgunTxid,omitempty"`
}

type Nullifier struct {
	Txid        string `json:"txid"`
	Nullifier   string `json:"nullifier"`
	TreeNumber  int    `json:"treeNumber"`
	BlockNumber uint64 `json:"blockNumber"`
}

type abiTokenData struct {
	TokenType    uint8          `abi:"tokenType"`
	TokenAddress common.Address `abi:"tokenAddress"`
	TokenSubID   *big.Int       `abi:"tokenSubID"`
}

type abiCommitmentPreimage struct {
	NPK   [32]byte     `abi:"npk"`
	Token abiTokenData `abi:"token"`
	Value *big.Int     `abi:"value"`
}

type abiShieldCiphertext struct {
	EncryptedBundle [3][32]byte `abi:"encryptedBundle"`
	ShieldKey       [32]byte    `abi:"shieldKey"`
}

type abiCommitmentCiphertextV2 struct {
	Ciphertext                [4][32]byte `abi:"ciphertext"`
	BlindedSenderViewingKey   [32]byte    `abi:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey [32]byte    `abi:"blindedReceiverViewingKey"`
	AnnotationData            []byte      `abi:"annotationData"`
	Memo                      []byte      `abi:"memo"`
}

type abiShieldEvent struct {
	TreeNumber       *big.Int                `abi:"treeNumber"`
	StartPosition    *big.Int                `abi:"startPosition"`
	Commitments      []abiCommitmentPreimage `abi:"commitments"`
	ShieldCiphertext []abiShieldCiphertext   `abi:"shieldCiphertext"`
	Fees             []*big.Int              `abi:"fees"`
}

type abiTransactEvent struct {
	TreeNumber    *big.Int                    `abi:"treeNumber"`
	StartPosition *big.Int                    `abi:"startPosition"`
	Hash          [][32]byte                  `abi:"hash"`
	Ciphertext    []abiCommitmentCiphertextV2 `abi:"ciphertext"`
}

type abiUnshieldEvent struct {
	To     common.Address `abi:"to"`
	Token  abiTokenData   `abi:"token"`
	Amount *big.Int       `abi:"amount"`
	Fee    *big.Int       `abi:"fee"`
}

type abiNullifiedEvent struct {
	TreeNumber uint16     `abi:"treeNumber"`
	Nullifier  [][32]byte `abi:"nullifier"`
}

func V2EventTopic(eventName string) (string, error) {
	event, err := v2Event(eventName)
	if err != nil {
		return "", err
	}
	return event.ID.Hex(), nil
}

func ParseV2ShieldLog(log ContractLog) (CommitmentEvent, error) {
	var decoded abiShieldEvent
	if err := unpackV2EventLog(log, "Shield", &decoded); err != nil {
		return CommitmentEvent{}, err
	}
	return FormatV2ShieldEvent(decoded, log.TransactionHash, log.BlockNumber)
}

func ParseV2TransactLog(log ContractLog) (CommitmentEvent, error) {
	var decoded abiTransactEvent
	if err := unpackV2EventLog(log, "Transact", &decoded); err != nil {
		return CommitmentEvent{}, err
	}
	return FormatV2TransactEvent(decoded, log.TransactionHash, log.BlockNumber)
}

func ParseV2UnshieldLog(log ContractLog) (UnshieldStoredEvent, error) {
	var decoded abiUnshieldEvent
	if err := unpackV2EventLog(log, "Unshield", &decoded); err != nil {
		return UnshieldStoredEvent{}, err
	}
	return FormatV2UnshieldEvent(decoded, log.TransactionHash, log.BlockNumber, log.Index)
}

func ParseV2NullifiedLog(log ContractLog) ([]Nullifier, error) {
	var decoded abiNullifiedEvent
	if err := unpackV2EventLog(log, "Nullified", &decoded); err != nil {
		return nil, err
	}
	return FormatV2NullifiedEvents(decoded, log.TransactionHash, log.BlockNumber)
}

func FormatV2ShieldEvent(event abiShieldEvent, transactionHash string, blockNumber uint64) (CommitmentEvent, error) {
	treeNumber, err := intFromBigInt(event.TreeNumber, "treeNumber")
	if err != nil {
		return CommitmentEvent{}, err
	}
	startPosition, err := intFromBigInt(event.StartPosition, "startPosition")
	if err != nil {
		return CommitmentEvent{}, err
	}
	commitments, err := formatV2ShieldCommitments(
		transactionHash,
		event.Commitments,
		event.ShieldCiphertext,
		blockNumber,
		treeNumber,
		startPosition,
		event.Fees,
	)
	if err != nil {
		return CommitmentEvent{}, err
	}
	txid, err := formatBytes32(transactionHash)
	if err != nil {
		return CommitmentEvent{}, err
	}
	return CommitmentEvent{
		Txid:          txid,
		TreeNumber:    treeNumber,
		StartPosition: startPosition,
		Commitments:   commitments,
		BlockNumber:   blockNumber,
	}, nil
}

func FormatV2TransactEvent(event abiTransactEvent, transactionHash string, blockNumber uint64) (CommitmentEvent, error) {
	treeNumber, err := intFromBigInt(event.TreeNumber, "treeNumber")
	if err != nil {
		return CommitmentEvent{}, err
	}
	startPosition, err := intFromBigInt(event.StartPosition, "startPosition")
	if err != nil {
		return CommitmentEvent{}, err
	}
	commitments, err := formatV2TransactCommitments(
		transactionHash,
		event.Hash,
		event.Ciphertext,
		blockNumber,
		treeNumber,
		startPosition,
	)
	if err != nil {
		return CommitmentEvent{}, err
	}
	txid, err := formatBytes32(transactionHash)
	if err != nil {
		return CommitmentEvent{}, err
	}
	return CommitmentEvent{
		Txid:          txid,
		TreeNumber:    treeNumber,
		StartPosition: startPosition,
		Commitments:   commitments,
		BlockNumber:   blockNumber,
	}, nil
}

func FormatV2UnshieldEvent(event abiUnshieldEvent, transactionHash string, blockNumber uint64, eventLogIndex uint) (UnshieldStoredEvent, error) {
	token, err := tokenDataFromABI(event.Token)
	if err != nil {
		return UnshieldStoredEvent{}, err
	}
	txid, err := formatBytes32(transactionHash)
	if err != nil {
		return UnshieldStoredEvent{}, err
	}
	index := eventLogIndex
	return UnshieldStoredEvent{
		Txid:          txid,
		ToAddress:     event.To.Hex(),
		TokenType:     token.TokenType,
		TokenAddress:  token.TokenAddress,
		TokenSubID:    token.TokenSubID,
		Amount:        defaultBigInt(event.Amount).String(),
		Fee:           defaultBigInt(event.Fee).String(),
		BlockNumber:   blockNumber,
		EventLogIndex: &index,
	}, nil
}

func FormatV2NullifiedEvents(event abiNullifiedEvent, transactionHash string, blockNumber uint64) ([]Nullifier, error) {
	txid, err := formatBytes32(transactionHash)
	if err != nil {
		return nil, err
	}
	nullifiers := make([]Nullifier, len(event.Nullifier))
	for i, nullifier := range event.Nullifier {
		nullifiers[i] = Nullifier{
			Txid:        txid,
			Nullifier:   bytes32Hex(nullifier),
			TreeNumber:  int(event.TreeNumber),
			BlockNumber: blockNumber,
		}
	}
	return nullifiers, nil
}

func formatV2ShieldCommitments(transactionHash string, preimages []abiCommitmentPreimage, ciphertexts []abiShieldCiphertext, blockNumber uint64, utxoTree int, startIndex int, fees []*big.Int) ([]Commitment, error) {
	if len(preimages) != len(ciphertexts) {
		return nil, fmt.Errorf("shield commitments and ciphertext lengths differ")
	}
	txid, err := formatBytes32(transactionHash)
	if err != nil {
		return nil, err
	}
	commitments := make([]Commitment, len(preimages))
	for i, preimage := range preimages {
		nativePreimage, err := preImageFromABI(preimage)
		if err != nil {
			return nil, fmt.Errorf("commitment[%d] preimage: %w", i, err)
		}
		notePublicKey, err := railcrypto.HexToBigInt(nativePreimage.NPK)
		if err != nil {
			return nil, fmt.Errorf("commitment[%d] npk: %w", i, err)
		}
		value := defaultBigInt(preimage.Value)
		noteHash, err := railcrypto.NoteHashFromTokenData(notePublicKey, nativePreimage.Token, value)
		if err != nil {
			return nil, fmt.Errorf("commitment[%d] hash: %w", i, err)
		}
		hash, err := railcrypto.BigIntToHex(noteHash, 32, false)
		if err != nil {
			return nil, err
		}
		commitments[i] = Commitment{
			CommitmentType:  CommitmentTypeShield,
			Hash:            hash,
			Txid:            txid,
			BlockNumber:     blockNumber,
			PreImage:        &nativePreimage,
			EncryptedBundle: shieldBundleHex(ciphertexts[i].EncryptedBundle),
			ShieldKey:       "0x" + bytes32Hex(ciphertexts[i].ShieldKey),
			Fee:             feeString(fees, i),
			UTXOTree:        utxoTree,
			UTXOIndex:       startIndex + i,
		}
	}
	return commitments, nil
}

func formatV2TransactCommitments(transactionHash string, hashes [][32]byte, ciphertexts []abiCommitmentCiphertextV2, blockNumber uint64, utxoTree int, startIndex int) ([]Commitment, error) {
	if len(hashes) != len(ciphertexts) {
		return nil, fmt.Errorf("transact hash and ciphertext lengths differ")
	}
	txid, err := formatBytes32(transactionHash)
	if err != nil {
		return nil, err
	}
	commitments := make([]Commitment, len(ciphertexts))
	for i, ciphertext := range ciphertexts {
		formatted, err := formatV2CommitmentCiphertext(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("commitment[%d] ciphertext: %w", i, err)
		}
		commitments[i] = Commitment{
			CommitmentType: CommitmentTypeTransactV2,
			Hash:           bytes32Hex(hashes[i]),
			Txid:           txid,
			BlockNumber:    blockNumber,
			Ciphertext:     &formatted,
			UTXOTree:       utxoTree,
			UTXOIndex:      startIndex + i,
		}
	}
	return commitments, nil
}

func formatV2CommitmentCiphertext(ciphertext abiCommitmentCiphertextV2) (CommitmentCiphertextV2Event, error) {
	ivTag := bytes32Hex(ciphertext.Ciphertext[0])
	if len(ivTag) != 64 {
		return CommitmentCiphertextV2Event{}, fmt.Errorf("invalid iv/tag length")
	}
	data := make([]string, 0, 3)
	for _, chunk := range ciphertext.Ciphertext[1:] {
		data = append(data, bytes32Hex(chunk))
	}
	return CommitmentCiphertextV2Event{
		Ciphertext: railcrypto.CiphertextGCM{
			IV:   ivTag[:32],
			Tag:  ivTag[32:],
			Data: data,
		},
		BlindedSenderViewingKey:   bytes32Hex(ciphertext.BlindedSenderViewingKey),
		BlindedReceiverViewingKey: bytes32Hex(ciphertext.BlindedReceiverViewingKey),
		AnnotationData:            dynamicBytesHex(ciphertext.AnnotationData),
		Memo:                      dynamicBytesHex(ciphertext.Memo),
	}, nil
}

func preImageFromABI(preimage abiCommitmentPreimage) (PreImage, error) {
	token, err := tokenDataFromABI(preimage.Token)
	if err != nil {
		return PreImage{}, err
	}
	value, err := railcrypto.BigIntToHex(defaultBigInt(preimage.Value), 16, false)
	if err != nil {
		return PreImage{}, err
	}
	return PreImage{
		NPK:   bytes32Hex(preimage.NPK),
		Token: token,
		Value: value,
	}, nil
}

func tokenDataFromABI(token abiTokenData) (railcrypto.TokenData, error) {
	return railcrypto.SerializeTokenData(
		strings.ToLower(token.TokenAddress.Hex()),
		int(token.TokenType),
		defaultBigInt(token.TokenSubID).String(),
	)
}

func unpackV2EventLog(log ContractLog, eventName string, out any) error {
	event, err := v2Event(eventName)
	if err != nil {
		return err
	}
	if len(log.Topics) == 0 {
		return fmt.Errorf("missing event topic")
	}
	if !strings.EqualFold(log.Topics[0], event.ID.Hex()) {
		return fmt.Errorf("event topic %s invalid: expected %s", log.Topics[0], event.ID.Hex())
	}
	data, err := railcrypto.HexToBytes(log.Data)
	if err != nil {
		return err
	}
	values, err := event.Inputs.Unpack(data)
	if err != nil {
		return err
	}
	return event.Inputs.Copy(out, values)
}

func v2Event(eventName string) (abi.Event, error) {
	contractABI, err := abi.JSON(strings.NewReader(railgunSmartWalletV2EventsABI))
	if err != nil {
		return abi.Event{}, err
	}
	event, ok := contractABI.Events[eventName]
	if !ok {
		return abi.Event{}, fmt.Errorf("unknown V2 Railgun event %s", eventName)
	}
	return event, nil
}

func formatBytes32(value string) (string, error) {
	return railcrypto.FormatHexToByteLength(value, 32, false)
}

func bytes32Hex(value [32]byte) string {
	return railcrypto.BytesToHex(value[:], false)
}

func dynamicBytesHex(value []byte) string {
	return railcrypto.BytesToHex(value, true)
}

func shieldBundleHex(bundle [3][32]byte) []string {
	out := make([]string, len(bundle))
	for i, chunk := range bundle {
		out[i] = "0x" + bytes32Hex(chunk)
	}
	return out
}

func feeString(fees []*big.Int, index int) string {
	if index >= len(fees) || fees[index] == nil || fees[index].Sign() == 0 {
		return ""
	}
	return fees[index].String()
}

func intFromBigInt(value *big.Int, name string) (int, error) {
	if value == nil {
		return 0, fmt.Errorf("%s is required", name)
	}
	if !value.IsInt64() {
		return 0, fmt.Errorf("%s is too large", name)
	}
	return int(value.Int64()), nil
}

func defaultBigInt(value *big.Int) *big.Int {
	if value == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(value)
}
