package events

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

type TransactionReceipt struct {
	TransactionHash string        `json:"transactionHash"`
	BlockNumber     uint64        `json:"blockNumber"`
	Status          *uint64       `json:"status,omitempty"`
	Logs            []ContractLog `json:"logs"`
}

type TransactionCall struct {
	From     string
	To       string
	Data     string
	Value    *big.Int
	GasLimit *big.Int
}

type EIP1559FeeData struct {
	BaseFeePerGas        *big.Int
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
}

func (provider *JSONRPCLogProvider) TransactionCount(ctx context.Context, address string, blockTag string) (uint64, error) {
	result, err := provider.call(ctx, "eth_getTransactionCount", []any{address, blockTagOrLatest(blockTag)})
	if err != nil {
		return 0, err
	}
	var quantity string
	if err := json.Unmarshal(result, &quantity); err != nil {
		return 0, err
	}
	return parseQuantity(quantity)
}

func (provider *JSONRPCLogProvider) BalanceAt(ctx context.Context, address string, blockTag string) (*big.Int, error) {
	result, err := provider.call(ctx, "eth_getBalance", []any{address, blockTagOrLatest(blockTag)})
	if err != nil {
		return nil, err
	}
	var quantity string
	if err := json.Unmarshal(result, &quantity); err != nil {
		return nil, err
	}
	return parseBigQuantity(quantity)
}

func (provider *JSONRPCLogProvider) EstimateGas(ctx context.Context, call TransactionCall) (*big.Int, error) {
	result, err := provider.call(ctx, "eth_estimateGas", []any{ethTransactionCall(call)})
	if err != nil {
		return nil, err
	}
	var quantity string
	if err := json.Unmarshal(result, &quantity); err != nil {
		return nil, err
	}
	return parseBigQuantity(quantity)
}

func (provider *JSONRPCLogProvider) LatestBaseFeePerGas(ctx context.Context) (*big.Int, error) {
	result, err := provider.call(ctx, "eth_getBlockByNumber", []any{"latest", false})
	if err != nil {
		return nil, err
	}
	var block ethBlockHeader
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, err
	}
	if block.BaseFeePerGas == nil {
		return nil, fmt.Errorf("latest block missing baseFeePerGas")
	}
	return parseBigQuantity(*block.BaseFeePerGas)
}

func (provider *JSONRPCLogProvider) MaxPriorityFeePerGas(ctx context.Context) (*big.Int, error) {
	result, err := provider.call(ctx, "eth_maxPriorityFeePerGas", nil)
	if err != nil {
		return nil, err
	}
	var quantity string
	if err := json.Unmarshal(result, &quantity); err != nil {
		return nil, err
	}
	return parseBigQuantity(quantity)
}

func (provider *JSONRPCLogProvider) EIP1559FeeData(ctx context.Context) (EIP1559FeeData, error) {
	baseFee, err := provider.LatestBaseFeePerGas(ctx)
	if err != nil {
		return EIP1559FeeData{}, err
	}
	priorityFee, err := provider.MaxPriorityFeePerGas(ctx)
	if err != nil {
		return EIP1559FeeData{}, err
	}
	maxFee := new(big.Int).Add(new(big.Int).Mul(baseFee, big.NewInt(2)), priorityFee)
	return EIP1559FeeData{
		BaseFeePerGas:        baseFee,
		MaxPriorityFeePerGas: priorityFee,
		MaxFeePerGas:         maxFee,
	}, nil
}

func (provider *JSONRPCLogProvider) Call(ctx context.Context, call TransactionCall, blockTag string) (string, error) {
	result, err := provider.call(ctx, "eth_call", []any{ethTransactionCall(call), blockTagOrLatest(blockTag)})
	if err != nil {
		return "", err
	}
	var data string
	if err := json.Unmarshal(result, &data); err != nil {
		return "", err
	}
	return data, nil
}

func (provider *JSONRPCLogProvider) SendRawTransaction(ctx context.Context, signedTransaction string) (string, error) {
	result, err := provider.call(ctx, "eth_sendRawTransaction", []any{signedTransaction})
	if err != nil {
		return "", err
	}
	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", err
	}
	return txHash, nil
}

func (provider *JSONRPCLogProvider) TransactionReceipt(ctx context.Context, txHash string) (TransactionReceipt, bool, error) {
	result, err := provider.call(ctx, "eth_getTransactionReceipt", []any{txHash})
	if err != nil {
		return TransactionReceipt{}, false, err
	}
	if string(result) == "null" {
		return TransactionReceipt{}, false, nil
	}
	var receipt ethReceipt
	if err := json.Unmarshal(result, &receipt); err != nil {
		return TransactionReceipt{}, false, err
	}
	blockNumber, err := parseQuantity(receipt.BlockNumber)
	if err != nil {
		return TransactionReceipt{}, false, fmt.Errorf("receipt blockNumber: %w", err)
	}
	var status *uint64
	if receipt.Status != nil {
		parsed, err := parseQuantity(*receipt.Status)
		if err != nil {
			return TransactionReceipt{}, false, fmt.Errorf("receipt status: %w", err)
		}
		status = &parsed
	}
	logs, err := contractLogsFromETHLogs(receipt.Logs)
	if err != nil {
		return TransactionReceipt{}, false, err
	}
	return TransactionReceipt{
		TransactionHash: receipt.TransactionHash,
		BlockNumber:     blockNumber,
		Status:          status,
		Logs:            logs,
	}, true, nil
}

type ethReceipt struct {
	TransactionHash string   `json:"transactionHash"`
	BlockNumber     string   `json:"blockNumber"`
	Status          *string  `json:"status"`
	Logs            []ethLog `json:"logs"`
}

type ethBlockHeader struct {
	BaseFeePerGas *string `json:"baseFeePerGas"`
}

func contractLogsFromETHLogs(logs []ethLog) ([]ContractLog, error) {
	out := make([]ContractLog, len(logs))
	for i, log := range logs {
		blockNumber, err := parseQuantity(log.BlockNumber)
		if err != nil {
			return nil, fmt.Errorf("log[%d] blockNumber: %w", i, err)
		}
		logIndex, err := parseQuantity(log.LogIndex)
		if err != nil {
			return nil, fmt.Errorf("log[%d] logIndex: %w", i, err)
		}
		out[i] = ContractLog{
			Topics:          append([]string(nil), log.Topics...),
			Data:            log.Data,
			TransactionHash: log.TransactionHash,
			BlockNumber:     blockNumber,
			Index:           uint(logIndex),
		}
	}
	return out, nil
}

func ethTransactionCall(call TransactionCall) map[string]string {
	out := map[string]string{}
	if call.From != "" {
		out["from"] = call.From
	}
	if call.To != "" {
		out["to"] = call.To
	}
	if call.Data != "" {
		out["data"] = call.Data
	}
	if call.Value != nil {
		out["value"] = formatBigQuantity(call.Value)
	}
	if call.GasLimit != nil {
		out["gas"] = formatBigQuantity(call.GasLimit)
	}
	return out
}

func blockTagOrLatest(blockTag string) string {
	if blockTag == "" {
		return "latest"
	}
	return blockTag
}

func formatBigQuantity(value *big.Int) string {
	if value == nil {
		return "0x0"
	}
	if value.Sign() < 0 {
		return "-0x" + new(big.Int).Abs(value).Text(16)
	}
	return "0x" + value.Text(16)
}

func parseBigQuantity(value string) (*big.Int, error) {
	trimmed := strings.TrimPrefix(strings.ToLower(value), "0x")
	if trimmed == "" {
		return nil, fmt.Errorf("empty quantity")
	}
	n := new(big.Int)
	if _, ok := n.SetString(trimmed, 16); ok {
		return n, nil
	}
	return nil, fmt.Errorf("invalid quantity %q", value)
}
