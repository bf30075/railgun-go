package quicksync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"time"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
)

const (
	BSCV2GraphQLEndpoint = "https://rail-squid.squids.live/squid-railgun-bsc-v2/graphql"
	defaultGraphLimit    = 10000
	defaultGraphMaxItems = 16 * 65536
)

type V2GraphOptions struct {
	Endpoint   string
	StartBlock uint64
	MaxItems   int
	HTTPClient *http.Client
}

func FetchV2Graph(ctx context.Context, options V2GraphOptions) (railevents.V2AccumulatedEvents, error) {
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = BSCV2GraphQLEndpoint
	}
	maxItems := options.MaxItems
	if maxItems <= 0 {
		maxItems = defaultGraphMaxItems
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	nullifiers, err := fetchGraphPages[graphNullifier](ctx, client, endpoint, graphNullifiersQuery, "nullifiers", options.StartBlock, maxItems)
	if err != nil {
		return railevents.V2AccumulatedEvents{}, fmt.Errorf("fetch nullifiers: %w", err)
	}
	unshields, err := fetchGraphPages[graphUnshield](ctx, client, endpoint, graphUnshieldsQuery, "unshields", options.StartBlock, maxItems)
	if err != nil {
		return railevents.V2AccumulatedEvents{}, fmt.Errorf("fetch unshields: %w", err)
	}
	commitments, err := fetchGraphPages[graphCommitment](ctx, client, endpoint, graphCommitmentsQuery, "commitments", options.StartBlock, maxItems)
	if err != nil {
		return railevents.V2AccumulatedEvents{}, fmt.Errorf("fetch commitments: %w", err)
	}
	return formatV2GraphEvents(
		removeDuplicateGraphItems(nullifiers),
		removeDuplicateGraphItems(unshields),
		removeDuplicateGraphItems(commitments),
	)
}

func FetchV2GraphCommitmentEvents(ctx context.Context, options V2GraphOptions) ([]railevents.CommitmentEvent, error) {
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = BSCV2GraphQLEndpoint
	}
	maxItems := options.MaxItems
	if maxItems <= 0 {
		maxItems = defaultGraphMaxItems
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	commitments, err := fetchGraphPages[graphCommitment](ctx, client, endpoint, graphCommitmentsQuery, "commitments", options.StartBlock, maxItems)
	if err != nil {
		return nil, fmt.Errorf("fetch commitments: %w", err)
	}
	return formatGraphCommitmentEventsV2(createGraphCommitmentBatches(removeDuplicateGraphItems(commitments)))
}

type graphItem interface {
	graphID() string
	graphBlockNumber() string
}

type graphPageCursor struct {
	BlockNumber string
	ID          string
}

type graphNullifier struct {
	ID              string `json:"id"`
	BlockNumber     string `json:"blockNumber"`
	Nullifier       string `json:"nullifier"`
	TransactionHash string `json:"transactionHash"`
	BlockTimestamp  string `json:"blockTimestamp"`
	TreeNumber      int    `json:"treeNumber"`
}

func (item graphNullifier) graphID() string          { return item.ID }
func (item graphNullifier) graphBlockNumber() string { return item.BlockNumber }

type graphToken struct {
	ID           string `json:"id"`
	TokenType    string `json:"tokenType"`
	TokenSubID   string `json:"tokenSubID"`
	TokenAddress string `json:"tokenAddress"`
}

type graphUnshield struct {
	ID              string     `json:"id"`
	BlockNumber     string     `json:"blockNumber"`
	To              string     `json:"to"`
	TransactionHash string     `json:"transactionHash"`
	Fee             string     `json:"fee"`
	BlockTimestamp  string     `json:"blockTimestamp"`
	Amount          string     `json:"amount"`
	EventLogIndex   string     `json:"eventLogIndex"`
	Token           graphToken `json:"token"`
}

func (item graphUnshield) graphID() string          { return item.ID }
func (item graphUnshield) graphBlockNumber() string { return item.BlockNumber }

type graphPreimage struct {
	ID    string     `json:"id"`
	NPK   string     `json:"npk"`
	Value string     `json:"value"`
	Token graphToken `json:"token"`
}

type graphCiphertext struct {
	ID   string   `json:"id"`
	IV   string   `json:"iv"`
	Tag  string   `json:"tag"`
	Data []string `json:"data"`
}

type graphLegacyCommitmentCiphertext struct {
	ID            string          `json:"id"`
	Ciphertext    graphCiphertext `json:"ciphertext"`
	EphemeralKeys []string        `json:"ephemeralKeys"`
	Memo          []string        `json:"memo"`
}

type graphCommitmentCiphertext struct {
	ID                        string          `json:"id"`
	Ciphertext                graphCiphertext `json:"ciphertext"`
	BlindedSenderViewingKey   string          `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string          `json:"blindedReceiverViewingKey"`
	AnnotationData            string          `json:"annotationData"`
	Memo                      string          `json:"memo"`
}

type graphCommitment struct {
	ID                     string                           `json:"id"`
	TreeNumber             int                              `json:"treeNumber"`
	BatchStartTreePosition int                              `json:"batchStartTreePosition"`
	TreePosition           int                              `json:"treePosition"`
	BlockNumber            string                           `json:"blockNumber"`
	TransactionHash        string                           `json:"transactionHash"`
	BlockTimestamp         string                           `json:"blockTimestamp"`
	CommitmentType         string                           `json:"commitmentType"`
	Hash                   string                           `json:"hash"`
	EncryptedRandom        []string                         `json:"encryptedRandom"`
	Preimage               *graphPreimage                   `json:"preimage"`
	LegacyCiphertext       *graphLegacyCommitmentCiphertext `json:"legacyCiphertext"`
	ShieldKey              string                           `json:"shieldKey"`
	Fee                    string                           `json:"fee"`
	EncryptedBundle        []string                         `json:"encryptedBundle"`
	Ciphertext             *graphCommitmentCiphertext       `json:"ciphertext"`
}

func (item graphCommitment) graphID() string          { return item.ID }
func (item graphCommitment) graphBlockNumber() string { return item.BlockNumber }

type graphCommitmentBatch struct {
	TransactionHash string
	Commitments     []graphCommitment
	TreeNumber      int
	StartPosition   int
	BlockNumber     uint64
}

func fetchGraphPages[T graphItem](ctx context.Context, client *http.Client, endpoint string, query string, field string, startBlock uint64, maxItems int) ([]T, error) {
	var out []T
	cursor := graphPageCursor{BlockNumber: strconv.FormatUint(startBlock, 10)}
	for {
		items, err := fetchGraphPage[T](ctx, client, endpoint, query, field, cursor)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return out, nil
		}
		out = append(out, items...)
		if len(out) >= maxItems || len(items) < defaultGraphLimit {
			if len(out) > maxItems {
				out = out[:maxItems]
			}
			return out, nil
		}
		last := out[len(out)-1]
		cursor = graphPageCursor{
			BlockNumber: last.graphBlockNumber(),
			ID:          last.graphID(),
		}
	}
}

func fetchGraphPage[T graphItem](ctx context.Context, client *http.Client, endpoint string, query string, field string, cursor graphPageCursor) ([]T, error) {
	var response struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	body, err := json.Marshal(map[string]any{
		"query": query,
		"variables": map[string]any{
			"blockNumber": cursor.BlockNumber,
			"id":          cursor.ID,
		},
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("content-type", "application/json")
	httpResponse, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("graphql status %d: %s", httpResponse.StatusCode, string(responseBody))
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, err
	}
	if len(response.Errors) > 0 {
		return nil, fmt.Errorf("graphql error: %s", response.Errors[0].Message)
	}
	raw, ok := response.Data[field]
	if !ok {
		return nil, fmt.Errorf("graphql response missing %s", field)
	}
	var items []T
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func removeDuplicateGraphItems[T graphItem](items []T) []T {
	seen := map[string]struct{}{}
	out := make([]T, 0, len(items))
	for _, item := range items {
		id := item.graphID()
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, item)
	}
	return out
}

func formatV2GraphEvents(nullifiers []graphNullifier, unshields []graphUnshield, commitments []graphCommitment) (railevents.V2AccumulatedEvents, error) {
	nullifierEvents, err := formatGraphNullifiersV2(nullifiers)
	if err != nil {
		return railevents.V2AccumulatedEvents{}, err
	}
	unshieldEvents, err := formatGraphUnshieldsV2(unshields)
	if err != nil {
		return railevents.V2AccumulatedEvents{}, err
	}
	commitmentEvents, err := formatGraphCommitmentEventsV2(createGraphCommitmentBatches(commitments))
	if err != nil {
		return railevents.V2AccumulatedEvents{}, err
	}
	return railevents.V2AccumulatedEvents{
		CommitmentEvents: commitmentEvents,
		NullifierEvents:  nullifierEvents,
		UnshieldEvents:   unshieldEvents,
	}, nil
}

func formatGraphNullifiersV2(nullifiers []graphNullifier) ([]railevents.Nullifier, error) {
	out := make([]railevents.Nullifier, len(nullifiers))
	for i, nullifier := range nullifiers {
		txid, err := formatTo32Bytes(nullifier.TransactionHash, false)
		if err != nil {
			return nil, err
		}
		formattedNullifier, err := formatTo32Bytes(nullifier.Nullifier, false)
		if err != nil {
			return nil, err
		}
		blockNumber, err := parseGraphUint64(nullifier.BlockNumber)
		if err != nil {
			return nil, err
		}
		out[i] = railevents.Nullifier{
			Txid:        txid,
			Nullifier:   formattedNullifier,
			TreeNumber:  nullifier.TreeNumber,
			BlockNumber: blockNumber,
		}
	}
	return out, nil
}

func formatGraphUnshieldsV2(unshields []graphUnshield) ([]railevents.UnshieldStoredEvent, error) {
	out := make([]railevents.UnshieldStoredEvent, len(unshields))
	for i, unshield := range unshields {
		txid, err := formatTo32Bytes(unshield.TransactionHash, false)
		if err != nil {
			return nil, err
		}
		blockNumber, err := parseGraphUint64(unshield.BlockNumber)
		if err != nil {
			return nil, err
		}
		timestamp, err := parseGraphUint64(unshield.BlockTimestamp)
		if err != nil {
			return nil, err
		}
		logIndex, err := parseGraphUint(unshield.EventLogIndex)
		if err != nil {
			return nil, err
		}
		token, err := formatGraphToken(unshield.Token)
		if err != nil {
			return nil, err
		}
		out[i] = railevents.UnshieldStoredEvent{
			Txid:          txid,
			Timestamp:     &timestamp,
			EventLogIndex: &logIndex,
			ToAddress:     railcrypto.Prefix0x(unshield.To),
			TokenType:     token.TokenType,
			TokenAddress:  token.TokenAddress,
			TokenSubID:    token.TokenSubID,
			Amount:        unshield.Amount,
			Fee:           unshield.Fee,
			BlockNumber:   blockNumber,
		}
	}
	return out, nil
}

func createGraphCommitmentBatches(commitments []graphCommitment) []graphCommitmentBatch {
	batchesByPosition := map[string]*graphCommitmentBatch{}
	for _, commitment := range commitments {
		blockNumber, err := parseGraphUint64(commitment.BlockNumber)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%d-%d", commitment.TreeNumber, commitment.BatchStartTreePosition)
		batch := batchesByPosition[key]
		if batch == nil {
			batch = &graphCommitmentBatch{
				TransactionHash: commitment.TransactionHash,
				TreeNumber:      commitment.TreeNumber,
				StartPosition:   commitment.BatchStartTreePosition,
				BlockNumber:     blockNumber,
			}
			batchesByPosition[key] = batch
		}
		batch.Commitments = append(batch.Commitments, commitment)
	}
	out := make([]graphCommitmentBatch, 0, len(batchesByPosition))
	for _, batch := range batchesByPosition {
		sort.Slice(batch.Commitments, func(i int, j int) bool {
			return batch.Commitments[i].TreePosition < batch.Commitments[j].TreePosition
		})
		out = append(out, *batch)
	}
	sort.Slice(out, func(i int, j int) bool {
		if out[i].TreeNumber != out[j].TreeNumber {
			return out[i].TreeNumber < out[j].TreeNumber
		}
		return out[i].StartPosition < out[j].StartPosition
	})
	return out
}

func formatGraphCommitmentEventsV2(batches []graphCommitmentBatch) ([]railevents.CommitmentEvent, error) {
	out := make([]railevents.CommitmentEvent, len(batches))
	for i, batch := range batches {
		txid, err := formatTo32Bytes(batch.TransactionHash, false)
		if err != nil {
			return nil, err
		}
		commitments := make([]railevents.Commitment, len(batch.Commitments))
		for j, commitment := range batch.Commitments {
			formatted, err := formatGraphCommitmentV2(commitment)
			if err != nil {
				return nil, fmt.Errorf("commitment %s: %w", commitment.ID, err)
			}
			commitments[j] = formatted
		}
		out[i] = railevents.CommitmentEvent{
			Txid:          txid,
			Commitments:   commitments,
			TreeNumber:    batch.TreeNumber,
			StartPosition: batch.StartPosition,
			BlockNumber:   batch.BlockNumber,
		}
	}
	return out, nil
}

func formatGraphCommitmentV2(commitment graphCommitment) (railevents.Commitment, error) {
	hash, err := formatDecimalTo32Bytes(commitment.Hash, false)
	if err != nil {
		return railevents.Commitment{}, err
	}
	txid, err := formatTo32Bytes(commitment.TransactionHash, false)
	if err != nil {
		return railevents.Commitment{}, err
	}
	blockNumber, err := parseGraphUint64(commitment.BlockNumber)
	if err != nil {
		return railevents.Commitment{}, err
	}
	timestamp, err := parseGraphUint64(commitment.BlockTimestamp)
	if err != nil {
		return railevents.Commitment{}, err
	}
	out := railevents.Commitment{
		Txid:           txid,
		Timestamp:      &timestamp,
		CommitmentType: graphCommitmentType(commitment.CommitmentType),
		Hash:           hash,
		BlockNumber:    blockNumber,
		UTXOTree:       commitment.TreeNumber,
		UTXOIndex:      commitment.TreePosition,
	}
	switch commitment.CommitmentType {
	case "LegacyGeneratedCommitment":
		preimage, err := formatGraphPreimage(commitment.Preimage)
		if err != nil {
			return railevents.Commitment{}, err
		}
		out.PreImage = &preimage
	case "ShieldCommitment":
		preimage, err := formatGraphPreimage(commitment.Preimage)
		if err != nil {
			return railevents.Commitment{}, err
		}
		out.PreImage = &preimage
		out.EncryptedBundle = cloneStringSlice(commitment.EncryptedBundle)
		out.ShieldKey = commitment.ShieldKey
		out.Fee = commitment.Fee
	case "TransactCommitment":
		ciphertext, err := formatGraphCommitmentCiphertext(commitment.Ciphertext)
		if err != nil {
			return railevents.Commitment{}, err
		}
		out.Ciphertext = &ciphertext
	}
	return out, nil
}

func graphCommitmentType(value string) string {
	if value == "TransactCommitment" {
		return railevents.CommitmentTypeTransactV2
	}
	return value
}

func formatGraphPreimage(preimage *graphPreimage) (railevents.PreImage, error) {
	if preimage == nil {
		return railevents.PreImage{}, fmt.Errorf("preimage is required")
	}
	token, err := formatGraphToken(preimage.Token)
	if err != nil {
		return railevents.PreImage{}, err
	}
	value, err := parseGraphBigInt(preimage.Value)
	if err != nil {
		return railevents.PreImage{}, err
	}
	valueHex, err := railcrypto.BigIntToHex(value, 16, false)
	if err != nil {
		return railevents.PreImage{}, err
	}
	npk, err := formatTo32Bytes(preimage.NPK, false)
	if err != nil {
		return railevents.PreImage{}, err
	}
	return railevents.PreImage{
		NPK:   npk,
		Token: token,
		Value: valueHex,
	}, nil
}

func formatGraphToken(token graphToken) (railcrypto.TokenData, error) {
	tokenType, err := graphTokenType(token.TokenType)
	if err != nil {
		return railcrypto.TokenData{}, err
	}
	return railcrypto.SerializeTokenData(token.TokenAddress, tokenType, token.TokenSubID)
}

func graphTokenType(value string) (int, error) {
	switch value {
	case "ERC20":
		return railcrypto.TokenTypeERC20, nil
	case "ERC721":
		return railcrypto.TokenTypeERC721, nil
	case "ERC1155":
		return railcrypto.TokenTypeERC1155, nil
	default:
		return 0, fmt.Errorf("unsupported token type %s", value)
	}
}

func formatGraphCommitmentCiphertext(ciphertext *graphCommitmentCiphertext) (railevents.CommitmentCiphertextV2Event, error) {
	if ciphertext == nil {
		return railevents.CommitmentCiphertextV2Event{}, fmt.Errorf("ciphertext is required")
	}
	iv, err := formatTo16Bytes(ciphertext.Ciphertext.IV, false)
	if err != nil {
		return railevents.CommitmentCiphertextV2Event{}, err
	}
	tag, err := formatTo16Bytes(ciphertext.Ciphertext.Tag, false)
	if err != nil {
		return railevents.CommitmentCiphertextV2Event{}, err
	}
	data := make([]string, len(ciphertext.Ciphertext.Data))
	for i, chunk := range ciphertext.Ciphertext.Data {
		data[i], err = formatTo32Bytes(chunk, false)
		if err != nil {
			return railevents.CommitmentCiphertextV2Event{}, err
		}
	}
	blindedSender, err := formatTo32Bytes(ciphertext.BlindedSenderViewingKey, false)
	if err != nil {
		return railevents.CommitmentCiphertextV2Event{}, err
	}
	blindedReceiver, err := formatTo32Bytes(ciphertext.BlindedReceiverViewingKey, false)
	if err != nil {
		return railevents.CommitmentCiphertextV2Event{}, err
	}
	return railevents.CommitmentCiphertextV2Event{
		Ciphertext: railcrypto.CiphertextGCM{
			IV:   iv,
			Tag:  tag,
			Data: data,
		},
		BlindedSenderViewingKey:   blindedSender,
		BlindedReceiverViewingKey: blindedReceiver,
		AnnotationData:            ciphertext.AnnotationData,
		Memo:                      ciphertext.Memo,
	}, nil
}

func formatTo16Bytes(value string, prefix bool) (string, error) {
	return railcrypto.FormatHexToByteLength(value, 16, prefix)
}

func formatTo32Bytes(value string, prefix bool) (string, error) {
	return railcrypto.FormatHexToByteLength(value, 32, prefix)
}

func formatDecimalTo32Bytes(value string, prefix bool) (string, error) {
	n, err := parseGraphBigInt(value)
	if err != nil {
		return "", err
	}
	return railcrypto.BigIntToHex(n, 32, prefix)
}

func parseGraphBigInt(value string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok || n.Sign() < 0 {
		return nil, fmt.Errorf("invalid bigint %q", value)
	}
	return n, nil
}

func parseGraphUint64(value string) (uint64, error) {
	n, err := parseGraphBigInt(value)
	if err != nil {
		return 0, err
	}
	if !n.IsUint64() {
		return 0, fmt.Errorf("uint64 overflow %q", value)
	}
	return n.Uint64(), nil
}

func parseGraphUint(value string) (uint, error) {
	n, err := parseGraphUint64(value)
	if err != nil {
		return 0, err
	}
	if uint64(uint(n)) != n {
		return 0, fmt.Errorf("uint overflow %q", value)
	}
	return uint(n), nil
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

const graphNullifiersQuery = `query Nullifiers($blockNumber: BigInt = 0, $id: String = "") {
  nullifiers(
    orderBy: [blockNumber_ASC, id_ASC]
    where: { OR: [{ blockNumber_gt: $blockNumber }, { blockNumber_eq: $blockNumber, id_gt: $id }] }
    limit: 10000
  ) {
    id
    blockNumber
    nullifier
    transactionHash
    blockTimestamp
    treeNumber
  }
}`

const graphUnshieldsQuery = `query Unshields($blockNumber: BigInt = 0, $id: String = "") {
  unshields(
    orderBy: [blockNumber_ASC, id_ASC]
    where: { OR: [{ blockNumber_gt: $blockNumber }, { blockNumber_eq: $blockNumber, id_gt: $id }] }
    limit: 10000
  ) {
    id
    blockNumber
    to
    transactionHash
    fee
    blockTimestamp
    amount
    eventLogIndex
    token {
      id
      tokenType
      tokenSubID
      tokenAddress
    }
  }
}`

const graphCommitmentsQuery = `query Commitments($blockNumber: BigInt = 0, $id: String = "") {
  commitments(
    orderBy: [blockNumber_ASC, id_ASC]
    where: { OR: [{ blockNumber_gt: $blockNumber }, { blockNumber_eq: $blockNumber, id_gt: $id }] }
    limit: 10000
  ) {
    id
    treeNumber
    batchStartTreePosition
    treePosition
    blockNumber
    transactionHash
    blockTimestamp
    commitmentType
    hash
    ... on LegacyGeneratedCommitment {
      id
      treeNumber
      batchStartTreePosition
      treePosition
      blockNumber
      transactionHash
      blockTimestamp
      commitmentType
      hash
      encryptedRandom
      preimage {
        id
        npk
        value
        token {
          id
          tokenType
          tokenSubID
          tokenAddress
        }
      }
    }
    ... on LegacyEncryptedCommitment {
      id
      blockNumber
      blockTimestamp
      transactionHash
      treeNumber
      batchStartTreePosition
      treePosition
      commitmentType
      hash
      legacyCiphertext: ciphertext {
        id
        ciphertext {
          id
          iv
          tag
          data
        }
        ephemeralKeys
        memo
      }
    }
    ... on ShieldCommitment {
      id
      blockNumber
      blockTimestamp
      transactionHash
      treeNumber
      batchStartTreePosition
      treePosition
      commitmentType
      hash
      shieldKey
      fee
      encryptedBundle
      preimage {
        id
        npk
        value
        token {
          id
          tokenType
          tokenSubID
          tokenAddress
        }
      }
    }
    ... on TransactCommitment {
      id
      blockNumber
      blockTimestamp
      transactionHash
      treeNumber
      batchStartTreePosition
      treePosition
      commitmentType
      hash
      ciphertext {
        id
        ciphertext {
          id
          iv
          tag
          data
        }
        blindedSenderViewingKey
        blindedReceiverViewingKey
        annotationData
        memo
      }
    }
  }
}`
