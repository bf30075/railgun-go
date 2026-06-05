package transaction

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"github.com/bf30075/railgun-go/pkg/events"
)

func TestSignAndSendEIP1559TransactionUsesJSONRPCProvider(t *testing.T) {
	privateKey := "0000000000000000000000000000000000000000000000000000000000000001"
	from, err := AddressFromPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var receiptCalls atomic.Int32
	var methods []string
	var sentHash string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request testRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, request.Method)
		switch request.Method {
		case "eth_chainId":
			writeRPCResult(t, w, request.ID, "0x7a69")
		case "eth_getTransactionCount":
			var params []string
			mustUnmarshalParams(t, request.Params, &params)
			assertJSONEqual(t, params, []string{from, "pending"})
			writeRPCResult(t, w, request.ID, "0x5")
		case "eth_estimateGas":
			var params []map[string]string
			mustUnmarshalParams(t, request.Params, &params)
			assertJSONEqual(t, params, []map[string]string{{
				"from":  from,
				"to":    "0x1111111111111111111111111111111111111111",
				"data":  "0xabcdef",
				"value": "0x3039",
			}})
			writeRPCResult(t, w, request.ID, "0x61a8")
		case "eth_getBlockByNumber":
			var params []any
			mustUnmarshalParams(t, request.Params, &params)
			assertJSONEqual(t, params, []any{"latest", false})
			writeRawRPCResult(t, w, request.ID, `{"baseFeePerGas":"0x3b9aca00"}`)
		case "eth_maxPriorityFeePerGas":
			writeRPCResult(t, w, request.ID, "0x77359400")
		case "eth_sendRawTransaction":
			var params []string
			mustUnmarshalParams(t, request.Params, &params)
			if len(params) != 1 {
				t.Fatalf("expected raw tx param, got %d", len(params))
			}
			raw, err := railcrypto.HexToBytes(params[0])
			if err != nil {
				t.Fatal(err)
			}
			var tx types.Transaction
			if err := tx.UnmarshalBinary(raw); err != nil {
				t.Fatal(err)
			}
			if tx.Type() != types.DynamicFeeTxType {
				t.Fatalf("expected EIP-1559 tx type, got %d", tx.Type())
			}
			if tx.Nonce() != 5 {
				t.Fatalf("expected nonce 5, got %d", tx.Nonce())
			}
			if tx.Gas() != 25000 {
				t.Fatalf("expected gas 25000, got %d", tx.Gas())
			}
			if tx.GasFeeCap().Cmp(big.NewInt(4_000_000_000)) != 0 {
				t.Fatalf("expected max fee 4000000000, got %s", tx.GasFeeCap())
			}
			if tx.GasTipCap().Cmp(big.NewInt(2_000_000_000)) != 0 {
				t.Fatalf("expected priority fee 2000000000, got %s", tx.GasTipCap())
			}
			sentHash = tx.Hash().Hex()
			writeRPCResult(t, w, request.ID, sentHash)
		case "eth_getTransactionReceipt":
			var params []string
			mustUnmarshalParams(t, request.Params, &params)
			assertJSONEqual(t, params, []string{sentHash})
			if receiptCalls.Add(1) == 1 {
				writeRawRPCResult(t, w, request.ID, `null`)
				return
			}
			writeRawRPCResult(t, w, request.ID, `{
				"transactionHash": "`+sentHash+`",
				"blockNumber": "0xa",
				"status": "0x1",
				"logs": []
			}`)
		default:
			t.Fatalf("unexpected method %s", request.Method)
		}
	}))
	defer server.Close()

	provider := events.NewJSONRPCLogProvider(server.URL)
	submitted, err := SignAndSendEIP1559Transaction(context.Background(), provider, SendEIP1559TransactionRequest{
		PrivateKey: privateKey,
		To:         "0x1111111111111111111111111111111111111111",
		Data:       "0xabcdef",
		Value:      big.NewInt(12345),
	})
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Hash != sentHash {
		t.Fatalf("expected submitted hash %s, got %s", sentHash, submitted.Hash)
	}
	if submitted.From != from {
		t.Fatalf("expected submitted from %s, got %s", from, submitted.From)
	}
	if submitted.ChainID.Cmp(big.NewInt(31337)) != 0 {
		t.Fatalf("expected chain id 31337, got %s", submitted.ChainID)
	}
	if submitted.Nonce != 5 {
		t.Fatalf("expected nonce 5, got %d", submitted.Nonce)
	}
	if submitted.GasLimit != 25000 {
		t.Fatalf("expected gas limit 25000, got %d", submitted.GasLimit)
	}

	receipt, err := WaitForTransactionReceipt(context.Background(), provider, submitted.Hash, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TransactionHash != submitted.Hash {
		t.Fatalf("expected receipt hash %s, got %s", submitted.Hash, receipt.TransactionHash)
	}
	if receipt.BlockNumber != 10 {
		t.Fatalf("expected receipt block 10, got %d", receipt.BlockNumber)
	}
	if receipt.Status == nil || *receipt.Status != 1 {
		t.Fatalf("expected successful receipt status, got %v", receipt.Status)
	}
	assertJSONEqual(t, methods, []string{
		"eth_chainId",
		"eth_getTransactionCount",
		"eth_estimateGas",
		"eth_getBlockByNumber",
		"eth_maxPriorityFeePerGas",
		"eth_sendRawTransaction",
		"eth_getTransactionReceipt",
		"eth_getTransactionReceipt",
	})
}

func TestSignAndSendEIP1559TransactionWithLatestNonceRetriesNonceAlreadyUsed(t *testing.T) {
	provider := &retryNonceSenderProvider{
		latestNonce: 3,
		failNonce:   3,
	}
	submitted, err := SignAndSendEIP1559TransactionWithLatestNonce(context.Background(), provider, SendEIP1559TransactionRequest{
		PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		To:         "0x1111111111111111111111111111111111111111",
		Data:       "0xabcdef",
		Value:      big.NewInt(12345),
	}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Nonce != 4 {
		t.Fatalf("expected nonce retry to submit with nonce 4, got %d", submitted.Nonce)
	}
	assertJSONEqual(t, provider.countBlockTags, []string{"latest"})
	assertJSONEqual(t, provider.sentNonces, []uint64{3, 4})
}

type testRPCRequest struct {
	ID     uint64            `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

func mustUnmarshalParams(t *testing.T, raw []json.RawMessage, target any) {
	t.Helper()
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatal(err)
	}
}

func writeRPCResult(t *testing.T, w http.ResponseWriter, id uint64, result any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(body)
}

func writeRawRPCResult(t *testing.T, w http.ResponseWriter, id uint64, result string) {
	t.Helper()
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + new(big.Int).SetUint64(id).String() + `,"result":` + result + `}`))
}

type retryNonceSenderProvider struct {
	latestNonce    uint64
	failNonce      uint64
	countBlockTags []string
	sentNonces     []uint64
}

func (provider *retryNonceSenderProvider) ChainID(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 31337, nil
}

func (provider *retryNonceSenderProvider) TransactionCount(ctx context.Context, _ string, blockTag string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	provider.countBlockTags = append(provider.countBlockTags, blockTag)
	return provider.latestNonce, nil
}

func (provider *retryNonceSenderProvider) EstimateGas(ctx context.Context, _ events.TransactionCall) (*big.Int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return big.NewInt(25000), nil
}

func (provider *retryNonceSenderProvider) EIP1559FeeData(ctx context.Context) (events.EIP1559FeeData, error) {
	if err := ctx.Err(); err != nil {
		return events.EIP1559FeeData{}, err
	}
	return events.EIP1559FeeData{
		BaseFeePerGas:        big.NewInt(1_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(2_000_000_000),
		MaxFeePerGas:         big.NewInt(4_000_000_000),
	}, nil
}

func (provider *retryNonceSenderProvider) SendRawTransaction(ctx context.Context, signedTransaction string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	raw, err := railcrypto.HexToBytes(signedTransaction)
	if err != nil {
		return "", err
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return "", err
	}
	nonce := tx.Nonce()
	provider.sentNonces = append(provider.sentNonces, nonce)
	if nonce == provider.failNonce {
		return "", fmt.Errorf("nonce has already been used")
	}
	return tx.Hash().Hex(), nil
}
