package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultJSONRPCMaxRetries = 3
	defaultJSONRPCRetryDelay = 200 * time.Millisecond
)

type JSONRPCLogProvider struct {
	Endpoint   string
	Client     *http.Client
	MaxRetries int
	RetryDelay time.Duration

	nextID atomic.Uint64
}

func NewJSONRPCLogProvider(endpoint string) *JSONRPCLogProvider {
	return &JSONRPCLogProvider{Endpoint: endpoint}
}

func (provider *JSONRPCLogProvider) BlockNumber(ctx context.Context) (uint64, error) {
	result, err := provider.call(ctx, "eth_blockNumber", nil)
	if err != nil {
		return 0, err
	}
	var quantity string
	if err := json.Unmarshal(result, &quantity); err != nil {
		return 0, err
	}
	return parseQuantity(quantity)
}

func (provider *JSONRPCLogProvider) ChainID(ctx context.Context) (uint64, error) {
	result, err := provider.call(ctx, "eth_chainId", nil)
	if err != nil {
		return 0, err
	}
	var quantity string
	if err := json.Unmarshal(result, &quantity); err != nil {
		return 0, err
	}
	return parseQuantity(quantity)
}

func (provider *JSONRPCLogProvider) FilterLogs(ctx context.Context, filter LogFilter) ([]ContractLog, error) {
	if provider == nil || provider.Endpoint == "" {
		return nil, fmt.Errorf("json-rpc endpoint is required")
	}
	result, err := provider.call(ctx, "eth_getLogs", []any{ethGetLogsFilter(filter)})
	if err != nil {
		return nil, err
	}
	var logs []ethLog
	if err := json.Unmarshal(result, &logs); err != nil {
		return nil, err
	}
	return contractLogsFromETHLogs(logs)
}

func (provider *JSONRPCLogProvider) call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	maxRetries := provider.maxRetries()
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		result, retry, err := provider.callOnce(ctx, method, params)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !retry || attempt == maxRetries {
			return nil, err
		}
		if err := sleepContext(ctx, provider.retryDelay(attempt)); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (provider *JSONRPCLogProvider) callOnce(ctx context.Context, method string, params []any) (json.RawMessage, bool, error) {
	client := provider.Client
	if client == nil {
		client = http.DefaultClient
	}
	id := provider.nextID.Add(1)
	body, err := json.Marshal(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  paramsOrEmpty(params),
	})
	if err != nil {
		return nil, false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, true, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		err := fmt.Errorf("json-rpc status %d: %s", response.StatusCode, string(responseBody))
		return nil, isRetryableHTTPStatus(response.StatusCode), err
	}
	var decoded jsonrpcResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return nil, false, err
	}
	if decoded.Error != nil {
		err := fmt.Errorf("json-rpc %s error %d: %s", method, decoded.Error.Code, decoded.Error.Message)
		return nil, isRetryableRPCError(decoded.Error), err
	}
	return decoded.Result, false, nil
}

func (provider *JSONRPCLogProvider) maxRetries() int {
	if provider.MaxRetries < 0 {
		return 0
	}
	if provider.MaxRetries == 0 {
		return defaultJSONRPCMaxRetries
	}
	return provider.MaxRetries
}

func (provider *JSONRPCLogProvider) retryDelay(attempt int) time.Duration {
	delay := provider.RetryDelay
	if delay == 0 {
		delay = defaultJSONRPCRetryDelay
	}
	return delay * time.Duration(1<<attempt)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isRetryableHTTPStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func isRetryableRPCError(err *jsonrpcError) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Message)
	return err.Code == 19 || strings.Contains(message, "temporary") || strings.Contains(message, "please retry") || strings.Contains(message, "timeout")
}

type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type jsonrpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ethLog struct {
	Topics          []string `json:"topics"`
	Data            string   `json:"data"`
	TransactionHash string   `json:"transactionHash"`
	BlockNumber     string   `json:"blockNumber"`
	LogIndex        string   `json:"logIndex"`
}

func ethGetLogsFilter(filter LogFilter) map[string]any {
	out := map[string]any{
		"fromBlock": formatQuantity(filter.FromBlock),
		"toBlock":   formatQuantity(filter.ToBlock),
	}
	if len(filter.Addresses) == 1 {
		out["address"] = filter.Addresses[0]
	} else if len(filter.Addresses) > 1 {
		out["address"] = append([]string(nil), filter.Addresses...)
	}
	if len(filter.Topics) > 0 {
		out["topics"] = cloneTopics(filter.Topics)
	}
	return out
}

func formatQuantity(value uint64) string {
	return fmt.Sprintf("0x%x", value)
}

func parseQuantity(value string) (uint64, error) {
	trimmed := strings.TrimPrefix(strings.ToLower(value), "0x")
	if trimmed == "" {
		return 0, fmt.Errorf("empty quantity")
	}
	return strconv.ParseUint(trimmed, 16, 64)
}

func paramsOrEmpty(params []any) []any {
	if params == nil {
		return []any{}
	}
	return params
}
