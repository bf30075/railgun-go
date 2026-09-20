package sdk

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	railaddress "github.com/bf30075/railgun-go/pkg/address"
	"github.com/bf30075/railgun-go/pkg/broadcaster"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railtransaction "github.com/bf30075/railgun-go/pkg/transaction"
)

const (
	defaultUnshieldGasEstimate      = 3_000_000
	defaultBroadcasterFeeUnitScale  = 1_000_000_000_000_000_000 // 1e18
	defaultBroadcasterSelectTimeout = 45 * time.Second
	defaultBroadcasterSelectPoll    = 2 * time.Second
	defaultRandomFeeThresholdPct    = 5
)

// BroadcasterOptions configures the Runtime's public-broadcaster submission path.
//
// By default unshield uses Waku + a random in-threshold broadcaster. Set
// SelfBroadcast to force the legacy EIP-1559 self-send path.
type BroadcasterOptions struct {
	// SelfBroadcast opts out of Waku and pays gas from the wallet EVM key.
	SelfBroadcast bool
	// TrustedFeeSigner overrides the Railway community defaults when non-empty.
	TrustedFeeSigner []string
	// FeeTokenAddress overrides the fee token (defaults to the unshield token).
	FeeTokenAddress string
	// GasEstimate overrides the conservative unshield gas used for fee math.
	GasEstimate uint64
	// SelectTimeout is how long to wait for fee quotes after connecting.
	SelectTimeout time.Duration
	// RandomFeeThresholdPct caps how much higher than the cheapest quote a
	// randomly selected broadcaster may charge (default 5).
	RandomFeeThresholdPct int
	// Transport injects a test transport; nil uses the live Waku transport.
	Transport broadcaster.Transport
	// Client injects a pre-built client (tests).
	Client *broadcaster.Client
}

func cloneBroadcasterOptions(options *BroadcasterOptions) *BroadcasterOptions {
	if options == nil {
		return nil
	}
	cloned := *options
	cloned.TrustedFeeSigner = append([]string{}, options.TrustedFeeSigner...)
	return &cloned
}

func (runtime *Runtime) useBroadcaster(selfBroadcastOverride *bool) bool {
	if selfBroadcastOverride != nil {
		return !*selfBroadcastOverride
	}
	if runtime == nil || runtime.broadcaster == nil {
		return true
	}
	return !runtime.broadcaster.SelfBroadcast
}

func (runtime *Runtime) ensureBroadcasterClient(ctx context.Context) (*broadcaster.Client, error) {
	if runtime == nil {
		return nil, fmt.Errorf("runtime is required")
	}
	runtime.broadcasterMu.Lock()
	defer runtime.broadcasterMu.Unlock()

	if runtime.broadcasterClient != nil && runtime.broadcasterClient.IsStarted() {
		return runtime.broadcasterClient, nil
	}

	opts := BroadcasterOptions{}
	if runtime.broadcaster != nil {
		opts = *runtime.broadcaster
	}
	client := opts.Client
	if client == nil {
		var err error
		client, err = broadcaster.NewClient(broadcaster.Options{
			TrustedFeeSigner: append([]string{}, opts.TrustedFeeSigner...),
			Transport:        opts.Transport,
		})
		if err != nil {
			return nil, err
		}
	}
	if !client.IsStarted() {
		if err := client.Start(ctx, runtime.network.Chain, nil); err != nil {
			return nil, err
		}
	}
	runtime.broadcasterClient = client
	return client, nil
}

func (runtime *Runtime) selectRandomBroadcaster(
	ctx context.Context,
	client *broadcaster.Client,
	tokenAddress string,
	useRelayAdapt bool,
) (broadcaster.SelectedBroadcaster, error) {
	opts := BroadcasterOptions{}
	if runtime.broadcaster != nil {
		opts = *runtime.broadcaster
	}
	timeout := opts.SelectTimeout
	if timeout <= 0 {
		timeout = defaultBroadcasterSelectTimeout
	}
	threshold := opts.RandomFeeThresholdPct
	if threshold <= 0 {
		threshold = defaultRandomFeeThresholdPct
	}
	if feeToken := strings.TrimSpace(opts.FeeTokenAddress); feeToken != "" {
		tokenAddress = feeToken
	}
	deadline := time.Now().Add(timeout)
	for {
		selected, ok := client.FindRandomBroadcasterForToken(runtime.network.Chain, tokenAddress, useRelayAdapt, threshold)
		if ok {
			return selected, nil
		}
		if time.Now().After(deadline) {
			return broadcaster.SelectedBroadcaster{}, fmt.Errorf("no broadcaster available for token %s", tokenAddress)
		}
		select {
		case <-ctx.Done():
			return broadcaster.SelectedBroadcaster{}, ctx.Err()
		case <-time.After(defaultBroadcasterSelectPoll):
		}
	}
}

func (runtime *Runtime) broadcasterGasEstimate() uint64 {
	if runtime != nil && runtime.broadcaster != nil && runtime.broadcaster.GasEstimate > 0 {
		return runtime.broadcaster.GasEstimate
	}
	return defaultUnshieldGasEstimate
}

func calculateBroadcasterFeeAmount(feePerUnitGas string, gasEstimate uint64) (*big.Int, error) {
	perUnit, ok := new(big.Int).SetString(feePerUnitGas, 10)
	if !ok {
		return nil, fmt.Errorf("invalid feePerUnitGas %q", feePerUnitGas)
	}
	if gasEstimate == 0 {
		gasEstimate = defaultUnshieldGasEstimate
	}
	fee := new(big.Int).Mul(perUnit, new(big.Int).SetUint64(gasEstimate))
	fee.Div(fee, big.NewInt(defaultBroadcasterFeeUnitScale))
	if fee.Sign() <= 0 {
		return nil, fmt.Errorf("calculated broadcaster fee is zero")
	}
	return fee, nil
}

func broadcasterFeeOutput(broadcasterRailgunAddress string, tokenData railcrypto.TokenData, feeAmount *big.Int, walletSource string) (railtransaction.RequestTransactOutput, error) {
	addressData, err := railaddress.Decode(broadcasterRailgunAddress)
	if err != nil {
		return railtransaction.RequestTransactOutput{}, fmt.Errorf("broadcaster address: %w", err)
	}
	masterPublicKey, err := railcrypto.NumberishToBigInt(addressData.MasterPublicKey)
	if err != nil {
		return railtransaction.RequestTransactOutput{}, err
	}
	viewingPublicKey, err := railcrypto.HexToBytes(addressData.ViewingPublicKey)
	if err != nil {
		return railtransaction.RequestTransactOutput{}, err
	}
	random, err := randomHex(16)
	if err != nil {
		return railtransaction.RequestTransactOutput{}, err
	}
	return railtransaction.RequestTransactOutput{
		ReceiverMasterPublicKey:  masterPublicKey,
		ReceiverViewingPublicKey: viewingPublicKey,
		Random:                   random,
		Value:                    cloneBigInt(feeAmount),
		TokenData:                tokenData,
		SenderRandom:             railcrypto.MemoSenderRandomNull,
		OutputType:               railcrypto.OutputTypeBroadcasterFee,
		WalletSource:             walletSource,
	}, nil
}

func (runtime *Runtime) submitViaBroadcaster(
	ctx context.Context,
	client *broadcaster.Client,
	selected broadcaster.SelectedBroadcaster,
	txidVersion string,
	to string,
	data string,
	nullifiers []string,
	minGasPrice *big.Int,
	useRelayAdapt bool,
	progress func(TransactionProgress),
	pollInterval time.Duration,
) (SubmittedTransactionWithReceipt, error) {
	reportTransactionProgress(progress, "broadcasting", "sending via Waku broadcaster")
	if minGasPrice == nil {
		minGasPrice = big.NewInt(0)
	}
	tx, err := client.CreateTransaction(
		txidVersion,
		to,
		data,
		selected.RailgunAddress,
		selected.TokenFee.FeesID,
		runtime.network.Chain,
		nullifiers,
		minGasPrice.String(),
		useRelayAdapt,
		map[string]map[string]any{},
	)
	if err != nil {
		return SubmittedTransactionWithReceipt{}, err
	}
	txHash, err := tx.Send(ctx)
	if err != nil {
		return SubmittedTransactionWithReceipt{}, err
	}
	submitted := SubmittedTransactionWithReceipt{
		Transaction: railtransaction.SubmittedTransaction{
			SignedTransaction: railtransaction.SignedTransaction{Hash: txHash},
		},
	}
	if _, err := runtime.ReceiptProvider(); err == nil {
		receipt, waitErr := runtime.WaitForTransactionReceipt(ctx, txHash, normalizedPollInterval(pollInterval))
		if waitErr == nil {
			submitted.Receipt = receipt
			if transactionReverted(submitted) {
				return SubmittedTransactionWithReceipt{}, fmt.Errorf("broadcaster transaction reverted: %s", txHash)
			}
		}
	}
	return submitted, nil
}

func nullifiersFromProved(proved []railtransaction.TransactionStructV2) []string {
	out := make([]string, 0)
	for _, tx := range proved {
		out = append(out, tx.Nullifiers...)
	}
	return out
}

func applyBroadcasterFeeToInputs(inputs *railtransaction.DummyTransactionBatchInputs, fee railtransaction.RequestTransactOutput, minGasPrice *big.Int) error {
	if inputs == nil || len(inputs.Groups) == 0 {
		return fmt.Errorf("transaction inputs are required")
	}
	if minGasPrice != nil {
		inputs.OverallBatchMinGasPrice = cloneBigInt(minGasPrice)
	}
	group := &inputs.Groups[0]
	group.Outputs = append([]railtransaction.RequestTransactOutput{fee}, group.Outputs...)

	feeNoteIV, err := randomHex(16)
	if err != nil {
		return err
	}
	feeAnnIV, err := randomHex(16)
	if err != nil {
		return err
	}
	noteIVs := []string{feeNoteIV}
	annIVs := []string{feeAnnIV}
	if len(inputs.NoteCiphertextV2IVs) > 0 {
		noteIVs = append(noteIVs, inputs.NoteCiphertextV2IVs[0]...)
	}
	if len(inputs.AnnotationV2IVs) > 0 {
		annIVs = append(annIVs, inputs.AnnotationV2IVs[0]...)
	}
	inputs.NoteCiphertextV2IVs = [][]string{noteIVs}
	inputs.AnnotationV2IVs = [][]string{annIVs}
	return nil
}
