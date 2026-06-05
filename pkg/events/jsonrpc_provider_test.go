package events

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJSONRPCLogProviderFilterLogs(t *testing.T) {
	var request jsonrpcRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Method != "eth_getLogs" {
			t.Fatalf("expected eth_getLogs, got %s", request.Method)
		}
		_, _ = w.Write([]byte(`{
			"jsonrpc": "2.0",
			"id": 1,
			"result": [
				{
					"topics": ["0xaaaa", "0xbbbb"],
					"data": "0x1234",
					"transactionHash": "0xcccc",
					"blockNumber": "0x2a",
					"logIndex": "0x7"
				}
			]
		}`))
	}))
	defer server.Close()

	provider := NewJSONRPCLogProvider(server.URL)
	got, err := provider.FilterLogs(context.Background(), LogFilter{
		Addresses: []string{
			"0x1111111111111111111111111111111111111111",
			"0x2222222222222222222222222222222222222222",
		},
		FromBlock: 10,
		ToBlock:   20,
		Topics: [][]string{
			{"0xaaaa", "0xbbbb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := []ContractLog{
		{
			Topics:          []string{"0xaaaa", "0xbbbb"},
			Data:            "0x1234",
			TransactionHash: "0xcccc",
			BlockNumber:     42,
			Index:           7,
		},
	}
	assertJSONEqual(t, got, expected)

	if len(request.Params) != 1 {
		t.Fatalf("expected 1 params item, got %d", len(request.Params))
	}
	filter, ok := request.Params[0].(map[string]any)
	if !ok {
		t.Fatalf("expected object filter, got %T", request.Params[0])
	}
	if filter["fromBlock"] != "0xa" || filter["toBlock"] != "0x14" {
		t.Fatalf("unexpected block filter: %v", filter)
	}
	assertJSONEqual(t, filter["address"], []string{
		"0x1111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222",
	})
	assertJSONEqual(t, filter["topics"], [][]string{{"0xaaaa", "0xbbbb"}})
}

func TestJSONRPCLogProviderReturnsRPCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"jsonrpc": "2.0",
			"id": 1,
			"error": {"code": -32000, "message": "boom"}
		}`))
	}))
	defer server.Close()

	provider := NewJSONRPCLogProvider(server.URL)
	_, err := provider.FilterLogs(context.Background(), LogFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestJSONRPCLogProviderRetriesTemporaryHTTPError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{
				"jsonrpc": "2.0",
				"id": 1,
				"error": {"code": 19, "message": "Temporary internal error. Please retry"}
			}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":[]}`))
	}))
	defer server.Close()

	provider := NewJSONRPCLogProvider(server.URL)
	provider.MaxRetries = 2
	provider.RetryDelay = time.Millisecond
	logs, err := provider.FilterLogs(context.Background(), LogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 0 {
		t.Fatalf("expected no logs, got %d", len(logs))
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestJSONRPCLogProviderBlockNumberAndChainID(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request jsonrpcRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, request.Method)
		switch request.Method {
		case "eth_blockNumber":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x64"}`))
		case "eth_chainId":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":"0x1"}`))
		default:
			t.Fatalf("unexpected method %s", request.Method)
		}
	}))
	defer server.Close()

	provider := NewJSONRPCLogProvider(server.URL)
	blockNumber, err := provider.BlockNumber(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if blockNumber != 100 {
		t.Fatalf("expected block number 100, got %d", blockNumber)
	}
	chainID, err := provider.ChainID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if chainID != 1 {
		t.Fatalf("expected chain id 1, got %d", chainID)
	}
	assertJSONEqual(t, methods, []string{"eth_blockNumber", "eth_chainId"})
}

func TestJSONRPCLogProviderSendRawTransactionAndReceipt(t *testing.T) {
	var requests []jsonrpcRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request jsonrpcRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request)
		switch request.Method {
		case "eth_sendRawTransaction":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xabc123"}`))
		case "eth_getTransactionReceipt":
			_, _ = w.Write([]byte(`{
				"jsonrpc": "2.0",
				"id": 2,
				"result": {
					"transactionHash": "0xabc123",
					"blockNumber": "0x2b",
					"status": "0x1",
					"logs": [
						{
							"topics": ["0xaaaa"],
							"data": "0x9999",
							"transactionHash": "0xabc123",
							"blockNumber": "0x2b",
							"logIndex": "0x3"
						}
					]
				}
			}`))
		default:
			t.Fatalf("unexpected method %s", request.Method)
		}
	}))
	defer server.Close()

	provider := NewJSONRPCLogProvider(server.URL)
	txHash, err := provider.SendRawTransaction(context.Background(), "0xsigned")
	if err != nil {
		t.Fatal(err)
	}
	if txHash != "0xabc123" {
		t.Fatalf("expected tx hash 0xabc123, got %s", txHash)
	}
	receipt, ok, err := provider.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected receipt")
	}
	status := uint64(1)
	expected := TransactionReceipt{
		TransactionHash: "0xabc123",
		BlockNumber:     43,
		Status:          &status,
		Logs: []ContractLog{
			{
				Topics:          []string{"0xaaaa"},
				Data:            "0x9999",
				TransactionHash: "0xabc123",
				BlockNumber:     43,
				Index:           3,
			},
		},
	}
	assertJSONEqual(t, receipt, expected)

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
	assertJSONEqual(t, requests[0].Params, []any{"0xsigned"})
	assertJSONEqual(t, requests[1].Params, []any{"0xabc123"})
}

func TestJSONRPCLogProviderTransactionCountEstimateGasAndCall(t *testing.T) {
	var requests []jsonrpcRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request jsonrpcRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request)
		switch request.Method {
		case "eth_getTransactionCount":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x9"}`))
		case "eth_estimateGas":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":"0x5208"}`))
		case "eth_call":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":"0xdeadbeef"}`))
		default:
			t.Fatalf("unexpected method %s", request.Method)
		}
	}))
	defer server.Close()

	provider := NewJSONRPCLogProvider(server.URL)
	nonce, err := provider.TransactionCount(context.Background(), "0x1111111111111111111111111111111111111111", "pending")
	if err != nil {
		t.Fatal(err)
	}
	if nonce != 9 {
		t.Fatalf("expected nonce 9, got %d", nonce)
	}
	call := TransactionCall{
		From:     "0x1111111111111111111111111111111111111111",
		To:       "0x2222222222222222222222222222222222222222",
		Data:     "0x1234",
		Value:    big.NewInt(123),
		GasLimit: big.NewInt(21000),
	}
	gas, err := provider.EstimateGas(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	if gas.Cmp(big.NewInt(21000)) != 0 {
		t.Fatalf("expected gas 21000, got %s", gas)
	}
	result, err := provider.Call(context.Background(), call, "")
	if err != nil {
		t.Fatal(err)
	}
	if result != "0xdeadbeef" {
		t.Fatalf("expected call result 0xdeadbeef, got %s", result)
	}

	if len(requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(requests))
	}
	assertJSONEqual(t, requests[0].Params, []any{"0x1111111111111111111111111111111111111111", "pending"})
	expectedCall := map[string]any{
		"from":  "0x1111111111111111111111111111111111111111",
		"to":    "0x2222222222222222222222222222222222222222",
		"data":  "0x1234",
		"value": "0x7b",
		"gas":   "0x5208",
	}
	assertJSONEqual(t, requests[1].Params, []any{expectedCall})
	assertJSONEqual(t, requests[2].Params, []any{expectedCall, "latest"})
}

func TestJSONRPCLogProviderTransactionReceiptMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":null}`))
	}))
	defer server.Close()

	provider := NewJSONRPCLogProvider(server.URL)
	_, ok, err := provider.TransactionReceipt(context.Background(), "0xabc123")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected missing receipt")
	}
}
