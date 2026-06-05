package sdk

import (
	"context"
	"fmt"
	"math/big"
	"time"

	railevents "github.com/bf30075/railgun-go/pkg/events"
	railtransaction "github.com/bf30075/railgun-go/pkg/transaction"
)

// SubmittedTransactionWithReceipt 将已提交交易和挖出的 receipt 放在一起。
type SubmittedTransactionWithReceipt struct {
	Transaction railtransaction.SubmittedTransaction
	Receipt     railevents.TransactionReceipt
}

// ProviderCapabilities 描述 Runtime provider 上可用的可选 JSON-RPC 能力。
type ProviderCapabilities struct {
	Logs                bool
	BlockNumber         bool
	NativeBalance       bool
	ContractCalls       bool
	EIP1559Sending      bool
	TransactionReceipts bool
}

// ProviderCapabilities 报告哪些 runtime helper 可以直接使用当前 provider，
// 避免靠失败调用探测能力。
func (runtime *Runtime) ProviderCapabilities() ProviderCapabilities {
	if runtime == nil || runtime.engine == nil || runtime.engine.provider == nil {
		return ProviderCapabilities{}
	}
	provider := runtime.engine.provider
	capabilities := ProviderCapabilities{
		Logs:        true,
		BlockNumber: true,
	}
	_, capabilities.NativeBalance = provider.(nativeBalanceProvider)
	_, capabilities.ContractCalls = provider.(contractCallProvider)
	_, capabilities.EIP1559Sending = provider.(railtransaction.EIP1559SenderProvider)
	_, capabilities.TransactionReceipts = provider.(railtransaction.TransactionReceiptProvider)
	return capabilities
}

// SenderProvider 返回 EIP-1559 发送所需的 provider interface。
func (runtime *Runtime) SenderProvider() (railtransaction.EIP1559SenderProvider, error) {
	if err := runtime.validateProvider(); err != nil {
		return nil, err
	}
	provider, ok := runtime.engine.provider.(railtransaction.EIP1559SenderProvider)
	if !ok {
		return nil, fmt.Errorf("runtime provider does not support EIP-1559 sending")
	}
	return provider, nil
}

// ReceiptProvider 返回轮询 receipt 所需的 provider interface。
func (runtime *Runtime) ReceiptProvider() (railtransaction.TransactionReceiptProvider, error) {
	if err := runtime.validateProvider(); err != nil {
		return nil, err
	}
	provider, ok := runtime.engine.provider.(railtransaction.TransactionReceiptProvider)
	if !ok {
		return nil, fmt.Errorf("runtime provider does not support transaction receipts")
	}
	return provider, nil
}

// SendEIP1559Transaction 签名并提交 EIP-1559 交易。
func (runtime *Runtime) SendEIP1559Transaction(ctx context.Context, request railtransaction.SendEIP1559TransactionRequest) (railtransaction.SubmittedTransaction, error) {
	provider, err := runtime.SenderProvider()
	if err != nil {
		return railtransaction.SubmittedTransaction{}, err
	}
	return railtransaction.SignAndSendEIP1559Transaction(ctx, provider, request)
}

// SendEIP1559TransactionWithLatestNonce 签名并提交 EIP-1559 交易；遇到
// nonce-too-low 错误时，从账户最新 nonce 开始重试。
func (runtime *Runtime) SendEIP1559TransactionWithLatestNonce(ctx context.Context, request railtransaction.SendEIP1559TransactionRequest, maxRetries int) (railtransaction.SubmittedTransaction, error) {
	provider, err := runtime.SenderProvider()
	if err != nil {
		return railtransaction.SubmittedTransaction{}, err
	}
	return railtransaction.SignAndSendEIP1559TransactionWithLatestNonce(ctx, provider, request, maxRetries)
}

// WaitForTransactionReceipt 轮询直到交易 receipt 可用，或 context 被取消。
func (runtime *Runtime) WaitForTransactionReceipt(ctx context.Context, txHash string, pollInterval time.Duration) (railevents.TransactionReceipt, error) {
	provider, err := runtime.ReceiptProvider()
	if err != nil {
		return railevents.TransactionReceipt{}, err
	}
	return railtransaction.WaitForTransactionReceipt(ctx, provider, txHash, pollInterval)
}

// SendEIP1559TransactionAndWait 签名并提交 EIP-1559 交易，然后等待 receipt。
func (runtime *Runtime) SendEIP1559TransactionAndWait(ctx context.Context, request railtransaction.SendEIP1559TransactionRequest, pollInterval time.Duration) (SubmittedTransactionWithReceipt, error) {
	submitted, err := runtime.SendEIP1559Transaction(ctx, request)
	if err != nil {
		return SubmittedTransactionWithReceipt{}, err
	}
	receipt, err := runtime.WaitForTransactionReceipt(ctx, submitted.Hash, pollInterval)
	if err != nil {
		return SubmittedTransactionWithReceipt{}, err
	}
	return SubmittedTransactionWithReceipt{
		Transaction: submitted,
		Receipt:     receipt,
	}, nil
}

// SendEIP1559TransactionWithLatestNonceAndWait 签名并提交交易，处理
// nonce-too-low 重试，然后等待 receipt。
func (runtime *Runtime) SendEIP1559TransactionWithLatestNonceAndWait(ctx context.Context, request railtransaction.SendEIP1559TransactionRequest, maxRetries int, pollInterval time.Duration) (SubmittedTransactionWithReceipt, error) {
	submitted, err := runtime.SendEIP1559TransactionWithLatestNonce(ctx, request, maxRetries)
	if err != nil {
		return SubmittedTransactionWithReceipt{}, err
	}
	receipt, err := runtime.WaitForTransactionReceipt(ctx, submitted.Hash, pollInterval)
	if err != nil {
		return SubmittedTransactionWithReceipt{}, err
	}
	return SubmittedTransactionWithReceipt{
		Transaction: submitted,
		Receipt:     receipt,
	}, nil
}

func (runtime *Runtime) validateProvider() error {
	if runtime == nil {
		return fmt.Errorf("runtime is required")
	}
	if runtime.engine == nil {
		return fmt.Errorf("engine is required")
	}
	if runtime.engine.provider == nil {
		return fmt.Errorf("event provider is required")
	}
	return nil
}

func (runtime *Runtime) blockNumberProvider() (railevents.BlockNumberProvider, error) {
	if err := runtime.validateProvider(); err != nil {
		return nil, err
	}
	return runtime.engine.provider, nil
}

type nativeBalanceProvider interface {
	BalanceAt(ctx context.Context, address string, blockTag string) (*big.Int, error)
}

func (runtime *Runtime) nativeBalanceProvider() (nativeBalanceProvider, error) {
	if err := runtime.validateProvider(); err != nil {
		return nil, err
	}
	provider, ok := runtime.engine.provider.(nativeBalanceProvider)
	if !ok {
		return nil, fmt.Errorf("runtime provider does not support native balances")
	}
	return provider, nil
}
