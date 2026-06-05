package transaction

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/bf30075/railgun-go/pkg/events"
)

type EIP1559SenderProvider interface {
	ChainID(ctx context.Context) (uint64, error)
	TransactionCount(ctx context.Context, address string, blockTag string) (uint64, error)
	EstimateGas(ctx context.Context, call events.TransactionCall) (*big.Int, error)
	EIP1559FeeData(ctx context.Context) (events.EIP1559FeeData, error)
	SendRawTransaction(ctx context.Context, signedTransaction string) (string, error)
}

type TransactionReceiptProvider interface {
	TransactionReceipt(ctx context.Context, txHash string) (events.TransactionReceipt, bool, error)
}

type SendEIP1559TransactionRequest struct {
	PrivateKey string
	To         string
	Data       string
	Value      *big.Int
	ChainID    *big.Int
	Nonce      *uint64
	GasLimit   uint64
	GasFeeCap  *big.Int
	GasTipCap  *big.Int
}

type SubmittedTransaction struct {
	SignedTransaction
	ChainID   *big.Int
	Nonce     uint64
	GasLimit  uint64
	GasFeeCap *big.Int
	GasTipCap *big.Int
	Value     *big.Int
	To        string
	Data      string
}

func SignAndSendEIP1559TransactionWithLatestNonce(ctx context.Context, provider EIP1559SenderProvider, request SendEIP1559TransactionRequest, maxRetries int) (SubmittedTransaction, error) {
	if provider == nil {
		return SubmittedTransaction{}, fmt.Errorf("provider is required")
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	from, err := AddressFromPrivateKey(request.PrivateKey)
	if err != nil {
		return SubmittedTransaction{}, err
	}
	nonce, err := provider.TransactionCount(ctx, from, "latest")
	if err != nil {
		return SubmittedTransaction{}, err
	}
	for attempt := 0; ; attempt++ {
		request.Nonce = &nonce
		submitted, err := SignAndSendEIP1559Transaction(ctx, provider, request)
		if err == nil {
			return submitted, nil
		}
		if attempt >= maxRetries || !isNonceAlreadyUsedError(err) {
			return SubmittedTransaction{}, err
		}
		nonce++
	}
}

func SignAndSendEIP1559Transaction(ctx context.Context, provider EIP1559SenderProvider, request SendEIP1559TransactionRequest) (SubmittedTransaction, error) {
	if provider == nil {
		return SubmittedTransaction{}, fmt.Errorf("provider is required")
	}
	from, err := AddressFromPrivateKey(request.PrivateKey)
	if err != nil {
		return SubmittedTransaction{}, err
	}
	chainID := cloneBigInt(request.ChainID)
	if chainID == nil {
		id, err := provider.ChainID(ctx)
		if err != nil {
			return SubmittedTransaction{}, err
		}
		chainID = new(big.Int).SetUint64(id)
	}
	nonce := uint64(0)
	if request.Nonce == nil {
		nonce, err = provider.TransactionCount(ctx, from, "pending")
		if err != nil {
			return SubmittedTransaction{}, err
		}
	} else {
		nonce = *request.Nonce
	}
	gasLimit := request.GasLimit
	if gasLimit == 0 {
		estimated, err := provider.EstimateGas(ctx, events.TransactionCall{
			From:  from,
			To:    request.To,
			Data:  request.Data,
			Value: request.Value,
		})
		if err != nil {
			return SubmittedTransaction{}, err
		}
		if !estimated.IsUint64() {
			return SubmittedTransaction{}, fmt.Errorf("estimated gas exceeds uint64")
		}
		gasLimit = estimated.Uint64()
	}
	gasFeeCap := cloneBigInt(request.GasFeeCap)
	gasTipCap := cloneBigInt(request.GasTipCap)
	if gasFeeCap == nil || gasTipCap == nil {
		feeData, err := provider.EIP1559FeeData(ctx)
		if err != nil {
			return SubmittedTransaction{}, err
		}
		if gasFeeCap == nil {
			gasFeeCap = cloneBigInt(feeData.MaxFeePerGas)
		}
		if gasTipCap == nil {
			gasTipCap = cloneBigInt(feeData.MaxPriorityFeePerGas)
		}
	}

	signed, err := SignEIP1559Transaction(request.PrivateKey, EIP1559TxRequest{
		ChainID:   chainID,
		Nonce:     nonce,
		To:        request.To,
		Value:     request.Value,
		GasLimit:  gasLimit,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Data:      request.Data,
	})
	if err != nil {
		return SubmittedTransaction{}, err
	}
	providerHash, err := provider.SendRawTransaction(ctx, signed.Raw)
	if err != nil {
		return SubmittedTransaction{}, err
	}
	if !strings.EqualFold(providerHash, signed.Hash) {
		return SubmittedTransaction{}, fmt.Errorf("provider returned tx hash %s, signed hash is %s", providerHash, signed.Hash)
	}
	return SubmittedTransaction{
		SignedTransaction: signed,
		ChainID:           chainID,
		Nonce:             nonce,
		GasLimit:          gasLimit,
		GasFeeCap:         gasFeeCap,
		GasTipCap:         gasTipCap,
		Value:             bigIntOrZero(request.Value),
		To:                request.To,
		Data:              request.Data,
	}, nil
}

func isNonceAlreadyUsedError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "nonce has already been used") || strings.Contains(message, "nonce too low")
}

func WaitForTransactionReceipt(ctx context.Context, provider TransactionReceiptProvider, txHash string, pollInterval time.Duration) (events.TransactionReceipt, error) {
	if provider == nil {
		return events.TransactionReceipt{}, fmt.Errorf("provider is required")
	}
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	for {
		receipt, ok, err := provider.TransactionReceipt(ctx, txHash)
		if err != nil {
			return events.TransactionReceipt{}, err
		}
		if ok {
			return receipt, nil
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return events.TransactionReceipt{}, ctx.Err()
		case <-timer.C:
		}
	}
}
