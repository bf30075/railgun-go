package events

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/txid"
)

const (
	CommitmentTypeTransactV3             = "TransactCommitmentV3"
	RailgunTransactionVersionV3          = "V3"
	GlobalUTXOTreeUnshieldEvent          = 99999
	GlobalUTXOPositionUnshieldEvent      = 99999
	v3AccumulatorStateUpdateEventName    = "AccumulatorStateUpdate"
	v3AccumulatorStateUpdateEventABIJSON = `[
  {
    "anonymous": false,
    "type": "event",
    "name": "AccumulatorStateUpdate",
    "inputs": [
      {
        "indexed": false,
        "name": "update",
        "type": "tuple",
        "components": [
          {"name": "commitments", "type": "bytes32[]"},
          {
            "name": "transactions",
            "type": "tuple[]",
            "components": [
              {"name": "nullifiers", "type": "bytes32[]"},
              {"name": "commitmentsCount", "type": "uint8"},
              {"name": "spendAccumulatorNumber", "type": "uint32"},
              {
                "name": "unshieldPreimage",
                "type": "tuple",
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
              {"name": "boundParamsHash", "type": "bytes32"}
            ]
          },
          {
            "name": "shields",
            "type": "tuple[]",
            "components": [
              {"name": "from", "type": "address"},
              {
                "name": "preimage",
                "type": "tuple",
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
                "name": "ciphertext",
                "type": "tuple",
                "components": [
                  {"name": "encryptedBundle", "type": "bytes32[3]"},
                  {"name": "shieldKey", "type": "bytes32"}
                ]
              }
            ]
          },
          {
            "name": "commitmentCiphertext",
            "type": "tuple[]",
            "components": [
              {"name": "ciphertext", "type": "bytes"},
              {"name": "blindedSenderViewingKey", "type": "bytes32"},
              {"name": "blindedReceiverViewingKey", "type": "bytes32"}
            ]
          },
          {
            "name": "treasuryFees",
            "type": "tuple[]",
            "components": [
              {"name": "tokenID", "type": "bytes32"},
              {"name": "fee", "type": "uint256"}
            ]
          },
          {"name": "senderCiphertext", "type": "bytes"}
        ]
      },
      {"indexed": false, "name": "accumulatorNumber", "type": "uint32"},
      {"indexed": false, "name": "startPosition", "type": "uint224"}
    ]
  }
]`
)

type V3AccumulatorEvents struct {
	CommitmentEvents         []V3CommitmentEvent    `json:"commitmentEvents"`
	NullifierEvents          []Nullifier            `json:"nullifierEvents"`
	UnshieldEvents           []UnshieldStoredEvent  `json:"unshieldEvents"`
	RailgunTransactionEvents []RailgunTransactionV3 `json:"railgunTransactionEvents"`
}

type V3CommitmentEvent struct {
	Txid          string         `json:"txid"`
	TreeNumber    int            `json:"treeNumber"`
	StartPosition int            `json:"startPosition"`
	Commitments   []V3Commitment `json:"commitments"`
	BlockNumber   uint64         `json:"blockNumber"`
}

type V3Commitment struct {
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
	Ciphertext                   *CommitmentCiphertextV3Event `json:"ciphertext,omitempty"`
	RailgunTxid                  string                       `json:"railgunTxid,omitempty"`
	SenderCiphertext             string                       `json:"senderCiphertext,omitempty"`
	TransactCommitmentBatchIndex *int                         `json:"transactCommitmentBatchIndex,omitempty"`
}

type CommitmentCiphertextV3Event struct {
	Ciphertext                railcrypto.CiphertextXChaCha `json:"ciphertext"`
	BlindedSenderViewingKey   string                       `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string                       `json:"blindedReceiverViewingKey"`
}

type UnshieldRailgunTransactionData struct {
	TokenData railcrypto.TokenData `json:"tokenData"`
	ToAddress string               `json:"toAddress"`
	Value     string               `json:"value"`
}

type RailgunTransactionV3 struct {
	Version                   string                          `json:"version"`
	Commitments               []string                        `json:"commitments"`
	Nullifiers                []string                        `json:"nullifiers"`
	BoundParamsHash           string                          `json:"boundParamsHash"`
	BlockNumber               uint64                          `json:"blockNumber"`
	Txid                      string                          `json:"txid"`
	Unshield                  *UnshieldRailgunTransactionData `json:"unshield,omitempty"`
	UTXOTreeIn                int                             `json:"utxoTreeIn"`
	UTXOTreeOut               int                             `json:"utxoTreeOut"`
	UTXOBatchStartPositionOut int                             `json:"utxoBatchStartPositionOut"`
	VerificationHash          string                          `json:"verificationHash,omitempty"`
}

type abiAccumulatorStateUpdateEvent struct {
	Update            abiAccumulatorStateUpdate `abi:"update"`
	AccumulatorNumber uint32                    `abi:"accumulatorNumber"`
	StartPosition     *big.Int                  `abi:"startPosition"`
}

type abiAccumulatorStateUpdate struct {
	Commitments          [][32]byte                      `abi:"commitments"`
	Transactions         []abiV3TransactionConfiguration `abi:"transactions"`
	Shields              []abiV3ShieldConfiguration      `abi:"shields"`
	CommitmentCiphertext []abiCommitmentCiphertextV3     `abi:"commitmentCiphertext"`
	TreasuryFees         []abiTreasuryFee                `abi:"treasuryFees"`
	SenderCiphertext     []byte                          `abi:"senderCiphertext"`
}

type abiV3TransactionConfiguration struct {
	Nullifiers             [][32]byte            `abi:"nullifiers"`
	CommitmentsCount       uint8                 `abi:"commitmentsCount"`
	SpendAccumulatorNumber uint32                `abi:"spendAccumulatorNumber"`
	UnshieldPreimage       abiCommitmentPreimage `abi:"unshieldPreimage"`
	BoundParamsHash        [32]byte              `abi:"boundParamsHash"`
}

type abiV3ShieldConfiguration struct {
	From       common.Address        `abi:"from"`
	Preimage   abiCommitmentPreimage `abi:"preimage"`
	Ciphertext abiShieldCiphertext   `abi:"ciphertext"`
}

type abiCommitmentCiphertextV3 struct {
	Ciphertext                []byte   `abi:"ciphertext"`
	BlindedSenderViewingKey   [32]byte `abi:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey [32]byte `abi:"blindedReceiverViewingKey"`
}

type abiTreasuryFee struct {
	TokenID [32]byte `abi:"tokenID"`
	Fee     *big.Int `abi:"fee"`
}

type treasuryFeePortions struct {
	Shield   *big.Int
	Unshield *big.Int
}

func V3AccumulatorStateUpdateTopic() (string, error) {
	event, err := v3AccumulatorStateUpdateEvent()
	if err != nil {
		return "", err
	}
	return event.ID.Hex(), nil
}

func ParseV3AccumulatorStateUpdateLog(log ContractLog) (V3AccumulatorEvents, error) {
	var decoded abiAccumulatorStateUpdateEvent
	if err := unpackV3AccumulatorEventLog(log, &decoded); err != nil {
		return V3AccumulatorEvents{}, err
	}
	return ProcessV3AccumulatorStateUpdate(decoded, log.TransactionHash, log.BlockNumber)
}

func ProcessV3AccumulatorStateUpdate(event abiAccumulatorStateUpdateEvent, transactionHash string, blockNumber uint64) (V3AccumulatorEvents, error) {
	startPosition, err := intFromBigInt(event.StartPosition, "startPosition")
	if err != nil {
		return V3AccumulatorEvents{}, err
	}
	feeMap, err := v3TreasuryFeeMap(event.Update.Transactions, event.Update.Shields, event.Update.TreasuryFees)
	if err != nil {
		return V3AccumulatorEvents{}, err
	}

	utxoTree := int(event.AccumulatorNumber)
	utxoStartingIndex := startPosition
	commitmentsStartIndex := 0
	out := V3AccumulatorEvents{}

	for i, transaction := range event.Update.Transactions {
		commitmentsCount := int(transaction.CommitmentsCount)
		commitmentsEndIndex := commitmentsStartIndex + commitmentsCount
		if commitmentsEndIndex > len(event.Update.Commitments) {
			return V3AccumulatorEvents{}, fmt.Errorf("expected commitmentHashes length to match commitmentsCount")
		}
		if commitmentsEndIndex > len(event.Update.CommitmentCiphertext) {
			return V3AccumulatorEvents{}, fmt.Errorf("expected commitmentCiphertexts length to match commitmentsCount")
		}
		commitmentHashes := event.Update.Commitments[commitmentsStartIndex:commitmentsEndIndex]
		commitmentCiphertexts := event.Update.CommitmentCiphertext[commitmentsStartIndex:commitmentsEndIndex]
		commitmentsStartIndex = commitmentsEndIndex

		commitmentsWithUnshieldHash := bytes32SliceHexPrefixed(commitmentHashes)
		hasUnshield := defaultBigInt(transaction.UnshieldPreimage.Value).Sign() > 0
		if hasUnshield {
			unshieldHash, err := noteHashFromPreimage(transaction.UnshieldPreimage)
			if err != nil {
				return V3AccumulatorEvents{}, err
			}
			commitmentsWithUnshieldHash = append(commitmentsWithUnshieldHash, "0x"+unshieldHash)
		}

		railgunTransaction, err := FormatV3RailgunTransactionEvent(
			transactionHash,
			blockNumber,
			commitmentsWithUnshieldHash,
			bytes32SliceHexPrefixed(transaction.Nullifiers),
			transaction.UnshieldPreimage,
			bytes32Hex(transaction.BoundParamsHash),
			int(transaction.SpendAccumulatorNumber),
			utxoTree,
			utxoStartingIndex,
			"",
		)
		if err != nil {
			return V3AccumulatorEvents{}, err
		}
		out.RailgunTransactionEvents = append(out.RailgunTransactionEvents, railgunTransaction)

		railgunTxid, err := txid.RailgunTransactionIDHex(
			railgunTransaction.Nullifiers,
			railgunTransaction.Commitments,
			railgunTransaction.BoundParamsHash,
		)
		if err != nil {
			return V3AccumulatorEvents{}, err
		}

		transactEvent, err := FormatV3TransactEvent(
			transactionHash,
			blockNumber,
			bytes32SliceHex(commitmentHashes),
			commitmentCiphertexts,
			utxoTree,
			utxoStartingIndex,
			i,
			dynamicBytesHex(event.Update.SenderCiphertext),
			railgunTxid,
		)
		if err != nil {
			return V3AccumulatorEvents{}, err
		}
		out.CommitmentEvents = append(out.CommitmentEvents, transactEvent)

		nullifiers := FormatV3NullifiedEvents(
			transactionHash,
			blockNumber,
			int(transaction.SpendAccumulatorNumber),
			bytes32SliceHex(transaction.Nullifiers),
		)
		out.NullifierEvents = append(out.NullifierEvents, nullifiers...)

		if hasUnshield {
			unshieldTokenHash, err := tokenHashFromPreimage(transaction.UnshieldPreimage)
			if err != nil {
				return V3AccumulatorEvents{}, err
			}
			unshieldFee := big.NewInt(0)
			if transaction.UnshieldPreimage.Token.TokenType == railcrypto.TokenTypeERC20 {
				portions, ok := feeMap[unshieldTokenHash]
				if !ok {
					return V3AccumulatorEvents{}, fmt.Errorf("expected unshield token hash in treasuryFeeMap")
				}
				totalUnshieldValue := totalV3UnshieldValue(event.Update.Transactions)
				if totalUnshieldValue.Sign() > 0 {
					unshieldFee.Mul(portions.Unshield, transaction.UnshieldPreimage.Value)
					unshieldFee.Div(unshieldFee, totalUnshieldValue)
				}
				if transaction.UnshieldPreimage.Value.Cmp(big.NewInt(400)) >= 0 && unshieldFee.Sign() == 0 {
					return V3AccumulatorEvents{}, fmt.Errorf("expected an unshield fee in treasuryFeeMap")
				}
			}
			unshieldEvent, err := FormatV3UnshieldEvent(
				transactionHash,
				blockNumber,
				transaction.UnshieldPreimage,
				uint(i),
				unshieldFee,
				railgunTxid,
			)
			if err != nil {
				return V3AccumulatorEvents{}, err
			}
			out.UnshieldEvents = append(out.UnshieldEvents, unshieldEvent)
		}

		utxoStartingIndex += commitmentsCount
		if utxoStartingIndex >= txid.TreeMaxItems {
			utxoStartingIndex = 0
			utxoTree++
		}
	}

	for _, shield := range event.Update.Shields {
		shieldFee := big.NewInt(0)
		if shield.Preimage.Token.TokenType == railcrypto.TokenTypeERC20 {
			shieldTokenHash, err := tokenHashFromPreimage(shield.Preimage)
			if err != nil {
				return V3AccumulatorEvents{}, err
			}
			portions, ok := feeMap[shieldTokenHash]
			if !ok {
				return V3AccumulatorEvents{}, fmt.Errorf("expected shield token hash in treasuryFeeMap")
			}
			totalShieldValue := totalV3ShieldValue(event.Update.Shields)
			if totalShieldValue.Sign() > 0 {
				shieldFee.Mul(portions.Shield, shield.Preimage.Value)
				shieldFee.Div(shieldFee, totalShieldValue)
			}
			if shield.Preimage.Value.Cmp(big.NewInt(400)) >= 0 && shieldFee.Sign() == 0 {
				return V3AccumulatorEvents{}, fmt.Errorf("expected a shield fee in treasuryFeeMap")
			}
		}
		shieldEvent, err := FormatV3ShieldEvent(
			transactionHash,
			blockNumber,
			shield.From.Hex(),
			shield.Preimage,
			shield.Ciphertext,
			utxoTree,
			utxoStartingIndex,
			shieldFee,
		)
		if err != nil {
			return V3AccumulatorEvents{}, err
		}
		out.CommitmentEvents = append(out.CommitmentEvents, shieldEvent)

		utxoStartingIndex++
		if utxoStartingIndex >= txid.TreeMaxItems {
			utxoStartingIndex = 0
			utxoTree++
		}
	}

	return out, nil
}

func FormatV3TransactEvent(transactionHash string, blockNumber uint64, commitmentHashes []string, commitmentCiphertexts []abiCommitmentCiphertextV3, utxoTree int, utxoStartingIndex int, transactIndex int, senderCiphertext string, railgunTxid string) (V3CommitmentEvent, error) {
	commitments, err := formatV3TransactCommitments(transactionHash, blockNumber, commitmentHashes, commitmentCiphertexts, utxoTree, utxoStartingIndex, transactIndex, senderCiphertext, railgunTxid)
	if err != nil {
		return V3CommitmentEvent{}, err
	}
	txidHex, err := formatBytes32(transactionHash)
	if err != nil {
		return V3CommitmentEvent{}, err
	}
	return V3CommitmentEvent{
		Txid:          txidHex,
		TreeNumber:    utxoTree,
		StartPosition: utxoStartingIndex,
		Commitments:   commitments,
		BlockNumber:   blockNumber,
	}, nil
}

func FormatV3UnshieldEvent(transactionHash string, blockNumber uint64, unshieldPreimage abiCommitmentPreimage, transactIndex uint, fee *big.Int, railgunTxid string) (UnshieldStoredEvent, error) {
	token, err := tokenDataFromABI(unshieldPreimage.Token)
	if err != nil {
		return UnshieldStoredEvent{}, err
	}
	txidHex, err := formatBytes32(transactionHash)
	if err != nil {
		return UnshieldStoredEvent{}, err
	}
	toAddress, err := railcrypto.FormatHexToByteLength(bytes32Hex(unshieldPreimage.NPK), 20, true)
	if err != nil {
		return UnshieldStoredEvent{}, err
	}
	amount := new(big.Int).Sub(defaultBigInt(unshieldPreimage.Value), defaultBigInt(fee))
	index := transactIndex
	return UnshieldStoredEvent{
		Txid:          txidHex,
		ToAddress:     toAddress,
		TokenType:     token.TokenType,
		TokenAddress:  token.TokenAddress,
		TokenSubID:    token.TokenSubID,
		Amount:        amount.String(),
		Fee:           defaultBigInt(fee).String(),
		BlockNumber:   blockNumber,
		EventLogIndex: &index,
		RailgunTxid:   railgunTxid,
	}, nil
}

func FormatV3NullifiedEvents(transactionHash string, blockNumber uint64, spendAccumulatorNumber int, nullifierHashes []string) []Nullifier {
	txidHex, _ := formatBytes32(transactionHash)
	nullifiers := make([]Nullifier, len(nullifierHashes))
	for i, nullifierHash := range nullifierHashes {
		nullifier, _ := formatBytes32(nullifierHash)
		nullifiers[i] = Nullifier{
			Txid:        txidHex,
			Nullifier:   nullifier,
			TreeNumber:  spendAccumulatorNumber,
			BlockNumber: blockNumber,
		}
	}
	return nullifiers
}

func FormatV3RailgunTransactionEvent(transactionHash string, blockNumber uint64, commitments []string, nullifiers []string, unshieldPreimage abiCommitmentPreimage, boundParamsHash string, utxoTreeIn int, utxoTree int, utxoBatchStartPosition int, verificationHash string) (RailgunTransactionV3, error) {
	txidHex, err := formatBytes32(transactionHash)
	if err != nil {
		return RailgunTransactionV3{}, err
	}
	formattedBoundParamsHash, err := formatBytes32(boundParamsHash)
	if err != nil {
		return RailgunTransactionV3{}, err
	}
	hasUnshield := defaultBigInt(unshieldPreimage.Value).Sign() > 0
	var unshield *UnshieldRailgunTransactionData
	if hasUnshield {
		tokenData, err := tokenDataFromABI(unshieldPreimage.Token)
		if err != nil {
			return RailgunTransactionV3{}, err
		}
		toAddress, err := railcrypto.FormatHexToByteLength(bytes32Hex(unshieldPreimage.NPK), 20, true)
		if err != nil {
			return RailgunTransactionV3{}, err
		}
		unshield = &UnshieldRailgunTransactionData{
			ToAddress: toAddress,
			TokenData: tokenData,
			Value:     defaultBigInt(unshieldPreimage.Value).String(),
		}
	}
	isUnshieldOnly := len(commitments) == 1 && hasUnshield
	utxoTreeOut := utxoTree
	utxoBatchStartPositionOut := utxoBatchStartPosition
	if isUnshieldOnly {
		utxoTreeOut = GlobalUTXOTreeUnshieldEvent
		utxoBatchStartPositionOut = GlobalUTXOPositionUnshieldEvent
	}
	return RailgunTransactionV3{
		Version:                   RailgunTransactionVersionV3,
		Txid:                      txidHex,
		BlockNumber:               blockNumber,
		Commitments:               append([]string(nil), commitments...),
		Nullifiers:                append([]string(nil), nullifiers...),
		BoundParamsHash:           formattedBoundParamsHash,
		Unshield:                  unshield,
		UTXOTreeIn:                utxoTreeIn,
		UTXOTreeOut:               utxoTreeOut,
		UTXOBatchStartPositionOut: utxoBatchStartPositionOut,
		VerificationHash:          verificationHash,
	}, nil
}

func FormatV3ShieldEvent(transactionHash string, blockNumber uint64, from string, shieldPreimage abiCommitmentPreimage, shieldCiphertext abiShieldCiphertext, utxoTree int, utxoIndex int, fee *big.Int) (V3CommitmentEvent, error) {
	commitment, err := formatV3ShieldCommitment(transactionHash, blockNumber, from, shieldPreimage, shieldCiphertext, utxoTree, utxoIndex, fee)
	if err != nil {
		return V3CommitmentEvent{}, err
	}
	txidHex, err := formatBytes32(transactionHash)
	if err != nil {
		return V3CommitmentEvent{}, err
	}
	return V3CommitmentEvent{
		Txid:          txidHex,
		TreeNumber:    utxoTree,
		StartPosition: utxoIndex,
		Commitments:   []V3Commitment{commitment},
		BlockNumber:   blockNumber,
	}, nil
}

func formatV3TransactCommitments(transactionHash string, blockNumber uint64, commitmentHashes []string, commitmentCiphertexts []abiCommitmentCiphertextV3, utxoTree int, utxoStartingIndex int, transactIndex int, senderCiphertext string, railgunTxid string) ([]V3Commitment, error) {
	if len(commitmentHashes) != len(commitmentCiphertexts) {
		return nil, fmt.Errorf("transact hash and ciphertext lengths differ")
	}
	txidHex, err := formatBytes32(transactionHash)
	if err != nil {
		return nil, err
	}
	commitments := make([]V3Commitment, len(commitmentCiphertexts))
	for i, ciphertext := range commitmentCiphertexts {
		formatted, err := FormatV3CommitmentCiphertext(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("commitment[%d] ciphertext: %w", i, err)
		}
		batchIndex := transactIndex + i
		commitments[i] = V3Commitment{
			CommitmentType:               CommitmentTypeTransactV3,
			Hash:                         commitmentHashes[i],
			Txid:                         txidHex,
			BlockNumber:                  blockNumber,
			Ciphertext:                   &formatted,
			UTXOTree:                     utxoTree,
			UTXOIndex:                    utxoStartingIndex + i,
			TransactCommitmentBatchIndex: &batchIndex,
			RailgunTxid:                  railgunTxid,
			SenderCiphertext:             senderCiphertext,
		}
	}
	return commitments, nil
}

func FormatV3CommitmentCiphertext(commitmentCiphertext abiCommitmentCiphertextV3) (CommitmentCiphertextV3Event, error) {
	strippedCiphertext := railcrypto.BytesToHex(commitmentCiphertext.Ciphertext, false)
	if len(strippedCiphertext) < 32 {
		return CommitmentCiphertextV3Event{}, fmt.Errorf("ciphertext too short")
	}
	return CommitmentCiphertextV3Event{
		Ciphertext: railcrypto.CiphertextXChaCha{
			Algorithm: railcrypto.XChaChaPoly1305EncryptionAlgorithm,
			Nonce:     strippedCiphertext[:32],
			Bundle:    strippedCiphertext[32:],
		},
		BlindedSenderViewingKey:   bytes32Hex(commitmentCiphertext.BlindedSenderViewingKey),
		BlindedReceiverViewingKey: bytes32Hex(commitmentCiphertext.BlindedReceiverViewingKey),
	}, nil
}

func formatV3ShieldCommitment(transactionHash string, blockNumber uint64, from string, shieldPreimage abiCommitmentPreimage, shieldCiphertext abiShieldCiphertext, utxoTree int, utxoIndex int, fee *big.Int) (V3Commitment, error) {
	nativePreimage, err := preImageFromABI(shieldPreimage)
	if err != nil {
		return V3Commitment{}, err
	}
	hash, err := noteHashFromPreimage(shieldPreimage)
	if err != nil {
		return V3Commitment{}, err
	}
	txidHex, err := formatBytes32(transactionHash)
	if err != nil {
		return V3Commitment{}, err
	}
	return V3Commitment{
		CommitmentType:  CommitmentTypeShield,
		Hash:            hash,
		Txid:            txidHex,
		BlockNumber:     blockNumber,
		PreImage:        &nativePreimage,
		EncryptedBundle: shieldBundleHex(shieldCiphertext.EncryptedBundle),
		ShieldKey:       "0x" + bytes32Hex(shieldCiphertext.ShieldKey),
		Fee:             defaultBigInt(fee).String(),
		UTXOTree:        utxoTree,
		UTXOIndex:       utxoIndex,
		From:            from,
	}, nil
}

func v3TreasuryFeeMap(transactions []abiV3TransactionConfiguration, shields []abiV3ShieldConfiguration, fees []abiTreasuryFee) (map[string]treasuryFeePortions, error) {
	out := map[string]treasuryFeePortions{}
	for _, treasuryFee := range fees {
		tokenID := bytes32Hex(treasuryFee.TokenID)
		unshieldValue := big.NewInt(0)
		for _, transaction := range transactions {
			tokenHash, err := tokenHashFromPreimage(transaction.UnshieldPreimage)
			if err != nil {
				return nil, err
			}
			if tokenHash == tokenID {
				unshieldValue = defaultBigInt(transaction.UnshieldPreimage.Value)
				break
			}
		}
		shieldValue := big.NewInt(0)
		for _, shield := range shields {
			tokenHash, err := tokenHashFromPreimage(shield.Preimage)
			if err != nil {
				return nil, err
			}
			if tokenHash == tokenID {
				shieldValue = defaultBigInt(shield.Preimage.Value)
				break
			}
		}
		total := new(big.Int).Add(unshieldValue, shieldValue)
		if total.Sign() == 0 {
			out[tokenID] = treasuryFeePortions{Shield: big.NewInt(0), Unshield: big.NewInt(0)}
			continue
		}
		fee := defaultBigInt(treasuryFee.Fee)
		var shieldFee, unshieldFee *big.Int
		if unshieldValue.Cmp(shieldValue) < 0 {
			unshieldFee = new(big.Int).Mul(unshieldValue, fee)
			unshieldFee.Div(unshieldFee, total)
			shieldFee = new(big.Int).Sub(fee, unshieldFee)
		} else {
			shieldFee = new(big.Int).Mul(shieldValue, fee)
			shieldFee.Div(shieldFee, total)
			unshieldFee = new(big.Int).Sub(fee, shieldFee)
		}
		out[tokenID] = treasuryFeePortions{Shield: shieldFee, Unshield: unshieldFee}
	}
	return out, nil
}

func totalV3UnshieldValue(transactions []abiV3TransactionConfiguration) *big.Int {
	total := big.NewInt(0)
	for _, transaction := range transactions {
		total.Add(total, defaultBigInt(transaction.UnshieldPreimage.Value))
	}
	return total
}

func totalV3ShieldValue(shields []abiV3ShieldConfiguration) *big.Int {
	total := big.NewInt(0)
	for _, shield := range shields {
		total.Add(total, defaultBigInt(shield.Preimage.Value))
	}
	return total
}

func tokenHashFromPreimage(preimage abiCommitmentPreimage) (string, error) {
	token, err := tokenDataFromABI(preimage.Token)
	if err != nil {
		return "", err
	}
	return railcrypto.TokenDataHash(token)
}

func noteHashFromPreimage(preimage abiCommitmentPreimage) (string, error) {
	token, err := tokenDataFromABI(preimage.Token)
	if err != nil {
		return "", err
	}
	npk, err := railcrypto.HexToBigInt(bytes32Hex(preimage.NPK))
	if err != nil {
		return "", err
	}
	hash, err := railcrypto.NoteHashFromTokenData(npk, token, defaultBigInt(preimage.Value))
	if err != nil {
		return "", err
	}
	return railcrypto.BigIntToHex(hash, 32, false)
}

func unpackV3AccumulatorEventLog(log ContractLog, out any) error {
	event, err := v3AccumulatorStateUpdateEvent()
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

func v3AccumulatorStateUpdateEvent() (abi.Event, error) {
	contractABI, err := abi.JSON(strings.NewReader(v3AccumulatorStateUpdateEventABIJSON))
	if err != nil {
		return abi.Event{}, err
	}
	event, ok := contractABI.Events[v3AccumulatorStateUpdateEventName]
	if !ok {
		return abi.Event{}, fmt.Errorf("missing V3 accumulator event")
	}
	return event, nil
}

func bytes32SliceHex(values [][32]byte) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = bytes32Hex(value)
	}
	return out
}

func bytes32SliceHexPrefixed(values [][32]byte) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = "0x" + bytes32Hex(value)
	}
	return out
}
