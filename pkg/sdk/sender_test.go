package sdk

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtransaction "github.com/bf30075/railgun-go/pkg/transaction"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

func TestRuntimeSendEIP1559TransactionAndWait(t *testing.T) {
	provider := &sdkSenderProvider{}
	runtime := &Runtime{engine: &Engine{provider: provider}}
	result, err := runtime.SendEIP1559TransactionAndWait(context.Background(), railtransaction.SendEIP1559TransactionRequest{
		PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		To:         "0x1111111111111111111111111111111111111111",
		Data:       "0xabcdef",
		Value:      big.NewInt(12345),
	}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if result.Transaction.Hash == "" || result.Transaction.Hash != provider.sentHash {
		t.Fatalf("unexpected submitted transaction hash %s provider %s", result.Transaction.Hash, provider.sentHash)
	}
	if result.Transaction.Nonce != 7 {
		t.Fatalf("expected nonce 7, got %d", result.Transaction.Nonce)
	}
	if result.Transaction.GasLimit != 25000 {
		t.Fatalf("expected gas limit 25000, got %d", result.Transaction.GasLimit)
	}
	if result.Transaction.GasFeeCap.Cmp(big.NewInt(4_000_000_000)) != 0 {
		t.Fatalf("unexpected gas fee cap %s", result.Transaction.GasFeeCap)
	}
	if provider.estimateCall.To != "0x1111111111111111111111111111111111111111" || provider.estimateCall.Data != "0xabcdef" {
		t.Fatalf("unexpected estimate call %+v", provider.estimateCall)
	}
	if result.Receipt.TransactionHash != result.Transaction.Hash || result.Receipt.BlockNumber != 99 {
		t.Fatalf("unexpected receipt %+v", result.Receipt)
	}
	if result.Receipt.Status == nil || *result.Receipt.Status != 1 {
		t.Fatalf("expected successful receipt, got %+v", result.Receipt.Status)
	}
}

func TestRuntimeOptionsProviderInjectsRuntimeCapabilities(t *testing.T) {
	ctx := context.Background()
	provider := &sdkSenderProvider{
		latest:      12,
		balance:     big.NewInt(55),
		latestNonce: 7,
	}
	runtime, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network:  testRuntimeNetworkConfig(),
		Provider: provider,
	}, testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}

	latest, err := runtime.LatestBlock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest != provider.latest {
		t.Fatalf("expected injected provider latest block %d, got %d", provider.latest, latest)
	}

	balance, err := runtime.NativeBalance(ctx, "0x1111111111111111111111111111111111111111", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if balance.Cmp(provider.balance) != 0 {
		t.Fatalf("expected injected provider balance %s, got %s", provider.balance, balance)
	}
	if len(provider.balanceBlockTags) != 1 || provider.balanceBlockTags[0] != "latest" {
		t.Fatalf("expected balance call through injected provider, got %+v", provider.balanceBlockTags)
	}

	sync, err := runtime.Sync(ctx, "provider-injection")
	if err != nil {
		t.Fatal(err)
	}
	result := sync[railcrypto.TXIDVersionV2PoseidonMerkle]
	if !result.Scanned || result.ToBlock != provider.latest || result.Checkpoint.NextBlock != provider.latest+1 {
		t.Fatalf("unexpected injected provider sync result %+v", result)
	}

	submitted, err := runtime.SendEIP1559TransactionAndWait(ctx, railtransaction.SendEIP1559TransactionRequest{
		PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		To:         "0x1111111111111111111111111111111111111111",
		Data:       "0xabcdef",
		Value:      big.NewInt(12345),
	}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if submitted.Transaction.Hash == "" || submitted.Transaction.Hash != provider.sentHash {
		t.Fatalf("expected send through injected provider, got provider=%s result=%+v", provider.sentHash, submitted)
	}
	if submitted.Receipt.TransactionHash != provider.sentHash {
		t.Fatalf("expected receipt through injected provider, got %+v", submitted.Receipt)
	}
}

func TestRuntimeProviderCapabilities(t *testing.T) {
	var nilRuntime *Runtime
	if capabilities := nilRuntime.ProviderCapabilities(); capabilities != (ProviderCapabilities{}) {
		t.Fatalf("expected zero capabilities for nil runtime, got %+v", capabilities)
	}

	runtimeWithoutProvider := &Runtime{engine: &Engine{}}
	if capabilities := runtimeWithoutProvider.ProviderCapabilities(); capabilities != (ProviderCapabilities{}) {
		t.Fatalf("expected zero capabilities without provider, got %+v", capabilities)
	}

	logProviderRuntime := &Runtime{engine: &Engine{provider: &sdkStubProvider{latest: 1}}}
	logCapabilities := logProviderRuntime.ProviderCapabilities()
	if !logCapabilities.Logs || !logCapabilities.BlockNumber {
		t.Fatalf("expected log provider capabilities, got %+v", logCapabilities)
	}
	if logCapabilities.NativeBalance || logCapabilities.ContractCalls || logCapabilities.EIP1559Sending || logCapabilities.TransactionReceipts {
		t.Fatalf("expected only log and block number capabilities, got %+v", logCapabilities)
	}

	fullRuntime := &Runtime{engine: &Engine{provider: &sdkSenderProvider{}}}
	fullCapabilities := fullRuntime.ProviderCapabilities()
	if !fullCapabilities.Logs ||
		!fullCapabilities.BlockNumber ||
		!fullCapabilities.NativeBalance ||
		!fullCapabilities.ContractCalls ||
		!fullCapabilities.EIP1559Sending ||
		!fullCapabilities.TransactionReceipts {
		t.Fatalf("expected full provider capabilities, got %+v", fullCapabilities)
	}
}

func TestRuntimeShieldBaseTokenSendsWithRuntimeSecret(t *testing.T) {
	ctx := context.Background()
	secret, err := railwallet.WalletSecretFromMnemonic(testMnemonic, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	network := testRuntimeNetworkConfig()
	network.ContractAddresses = map[string]string{
		"relayAdaptContract": "0x2222222222222222222222222222222222222222",
		"wrappedBaseToken":   "0x3333333333333333333333333333333333333333",
	}
	provider := &sdkSenderProvider{latestNonce: 7}
	runtime, err := NewRuntimeFromSecret(bundle, secret, RuntimeOptions{
		Network:  network,
		Provider: provider,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := runtime.ShieldBaseToken(ctx, ShieldBaseTokenRequest{
		RecipientRailgunAddress: secret.Railgun.Address,
		Amount:                  big.NewInt(12345),
		PollInterval:            time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Transaction.Transaction.Hash == "" || result.Transaction.Transaction.Hash != provider.sentHash {
		t.Fatalf("expected shield send through SDK runtime, got provider=%s result=%+v", provider.sentHash, result.Transaction)
	}
	if result.To != "0x2222222222222222222222222222222222222222" {
		t.Fatalf("expected relay adapt target, got %s", result.To)
	}
	if result.WrappedBaseToken != "0x3333333333333333333333333333333333333333" {
		t.Fatalf("expected wrapped base token, got %s", result.WrappedBaseToken)
	}
	if result.Value.Cmp(big.NewInt(12345)) != 0 {
		t.Fatalf("expected shield value 12345, got %s", result.Value)
	}
	if result.Transaction.Receipt.TransactionHash != provider.sentHash {
		t.Fatalf("expected receipt from injected provider, got %+v", result.Transaction.Receipt)
	}
	assertStringSlicesEqual(t, provider.nonceBlockTags, []string{"latest"})
}

func TestRuntimeShieldBaseTokenRejectsRevertedReceipt(t *testing.T) {
	ctx := context.Background()
	secret, err := railwallet.WalletSecretFromMnemonic(testMnemonic, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	network := testRuntimeNetworkConfig()
	network.ContractAddresses = map[string]string{
		"relayAdaptContract": "0x2222222222222222222222222222222222222222",
		"wrappedBaseToken":   "0x3333333333333333333333333333333333333333",
	}
	reverted := uint64(0)
	provider := &sdkSenderProvider{receiptStatus: &reverted}
	runtime, err := NewRuntimeFromSecret(bundle, secret, RuntimeOptions{
		Network:  network,
		Provider: provider,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = runtime.ShieldBaseToken(ctx, ShieldBaseTokenRequest{
		RecipientRailgunAddress: secret.Railgun.Address,
		Amount:                  big.NewInt(12345),
		PollInterval:            time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "BNB shield transaction reverted") {
		t.Fatalf("expected reverted BNB shield error, got %v", err)
	}
}

func TestRuntimeShieldERC20StopsWhenApprovalDoesNotIncreaseAllowanceEnough(t *testing.T) {
	ctx := context.Background()
	secret, err := railwallet.WalletSecretFromMnemonic(testMnemonic, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	network := testRuntimeNetworkConfig()
	network.ContractAddresses = map[string]string{
		"railgunSmartWalletV2": "0x2222222222222222222222222222222222222222",
	}
	provider := &sdkSenderProvider{
		latestNonce:     7,
		erc20Balance:    big.NewInt(100),
		allowanceBefore: big.NewInt(0),
		allowanceAfter:  big.NewInt(1),
	}
	runtime, err := NewRuntimeFromSecret(bundle, secret, RuntimeOptions{
		Network:  network,
		Provider: provider,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = runtime.ShieldERC20(ctx, ShieldERC20Request{
		RecipientRailgunAddress: secret.Railgun.Address,
		TokenAddress:            "0x3333333333333333333333333333333333333333",
		Amount:                  big.NewInt(10),
		PollInterval:            time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "allowance after approval is insufficient") {
		t.Fatalf("expected insufficient allowance error, got %v", err)
	}
	if len(provider.sentNonces) != 1 {
		t.Fatalf("expected only approval transaction, got nonces %+v", provider.sentNonces)
	}
}

func TestRuntimeSendEIP1559TransactionWithLatestNonceAndWaitRetries(t *testing.T) {
	provider := &sdkSenderProvider{latestNonce: 7, sendFailures: 1}
	runtime := &Runtime{engine: &Engine{provider: provider}}
	result, err := runtime.SendEIP1559TransactionWithLatestNonceAndWait(context.Background(), railtransaction.SendEIP1559TransactionRequest{
		PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		To:         "0x1111111111111111111111111111111111111111",
		Data:       "0xabcdef",
		Value:      big.NewInt(12345),
	}, 5, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if result.Transaction.Nonce != 8 {
		t.Fatalf("expected retried nonce 8, got %d", result.Transaction.Nonce)
	}
	assertStringSlicesEqual(t, provider.nonceBlockTags, []string{"latest"})
	assertUint64SlicesEqual(t, provider.sentNonces, []uint64{7, 8})
}

func TestRuntimeSendEIP1559TransactionWithLatestNonceAndSync(t *testing.T) {
	ctx := context.Background()
	provider := &sdkSenderProvider{
		latest:        12,
		latestNonce:   7,
		advanceOnSend: true,
	}
	manager := railpoi.NewManager([]railpoi.List{
		{Key: "active", Type: railpoi.ListTypeActive, Name: "active"},
	}, &runtimeFacadePOINode{required: false, active: true})
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, manager, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Bundle:   bundle,
		Chain:    testRuntimeChain,
		Provider: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		engine:  engine,
		bundle:  bundle,
		network: testRuntimeNetworkConfig(),
	}

	result, err := runtime.SendEIP1559TransactionWithLatestNonceAndSync(ctx, railtransaction.SendEIP1559TransactionRequest{
		PrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		To:         "0x1111111111111111111111111111111111111111",
		Data:       "0xabcdef",
		Value:      big.NewInt(12345),
	}, "workflow", 5, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	before := result.BeforeSync.Sync[railcrypto.TXIDVersionV2PoseidonMerkle]
	if !before.Scanned || before.FromBlock != 0 || before.ToBlock != 12 || before.Checkpoint.NextBlock != 13 {
		t.Fatalf("unexpected before sync %+v", before)
	}
	after := result.AfterSync.Sync[railcrypto.TXIDVersionV2PoseidonMerkle]
	if !after.Scanned || after.FromBlock != 13 || after.ToBlock != 13 || after.Checkpoint.NextBlock != 14 {
		t.Fatalf("unexpected after sync %+v", after)
	}
	if result.Submitted.Transaction.Hash == "" || result.Submitted.Receipt.TransactionHash != result.Submitted.Transaction.Hash {
		t.Fatalf("unexpected submitted result %+v", result.Submitted)
	}
	if result.Submitted.Transaction.Nonce != 7 {
		t.Fatalf("expected latest nonce 7, got %d", result.Submitted.Transaction.Nonce)
	}
	assertStringSlicesEqual(t, provider.nonceBlockTags, []string{"latest"})
}

func TestRuntimeSenderRejectsUnsupportedProvider(t *testing.T) {
	runtime := &Runtime{engine: &Engine{provider: &sdkStubProvider{latest: 1}}}
	if _, err := runtime.SendEIP1559Transaction(context.Background(), railtransaction.SendEIP1559TransactionRequest{}); err == nil || !strings.Contains(err.Error(), "EIP-1559 sending") {
		t.Fatalf("expected sender support error, got %v", err)
	}
	if _, err := runtime.WaitForTransactionReceipt(context.Background(), "0xhash", time.Millisecond); err == nil || !strings.Contains(err.Error(), "transaction receipts") {
		t.Fatalf("expected receipt support error, got %v", err)
	}
}

type sdkSenderProvider struct {
	sentHash         string
	estimateCall     railevents.TransactionCall
	latest           uint64
	balance          *big.Int
	balanceBlockTags []string
	erc20Balance     *big.Int
	allowanceBefore  *big.Int
	allowanceAfter   *big.Int
	latestNonce      uint64
	nonceBlockTags   []string
	sentNonces       []uint64
	sendFailures     int
	advanceOnSend    bool
	receiptStatus    *uint64
}

func (provider *sdkSenderProvider) FilterLogs(ctx context.Context, filter railevents.LogFilter) ([]railevents.ContractLog, error) {
	return nil, ctx.Err()
}

func (provider *sdkSenderProvider) BlockNumber(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if provider.latest == 0 {
		return 100, nil
	}
	return provider.latest, nil
}

func (provider *sdkSenderProvider) BalanceAt(ctx context.Context, _ string, blockTag string) (*big.Int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	provider.balanceBlockTags = append(provider.balanceBlockTags, blockTag)
	if provider.balance == nil {
		return big.NewInt(0), nil
	}
	return new(big.Int).Set(provider.balance), nil
}

func (provider *sdkSenderProvider) ChainID(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 31337, nil
}

func (provider *sdkSenderProvider) TransactionCount(ctx context.Context, address string, blockTag string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if address == "" {
		return 0, nil
	}
	provider.nonceBlockTags = append(provider.nonceBlockTags, blockTag)
	if blockTag == "latest" && provider.latestNonce != 0 {
		return provider.latestNonce, nil
	}
	return 7, nil
}

func (provider *sdkSenderProvider) EstimateGas(ctx context.Context, call railevents.TransactionCall) (*big.Int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	provider.estimateCall = call
	return big.NewInt(25000), nil
}

func (provider *sdkSenderProvider) Call(ctx context.Context, call railevents.TransactionCall, blockTag string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	data := strings.ToLower(call.Data)
	switch {
	case strings.HasPrefix(data, "0x70a08231"):
		return uint256Hex(provider.erc20Balance)
	case strings.HasPrefix(data, "0xdd62ed3e"):
		allowance := provider.allowanceBefore
		if len(provider.sentNonces) > 0 {
			allowance = provider.allowanceAfter
		}
		return uint256Hex(allowance)
	default:
		return "", fmt.Errorf("unexpected contract call %s at %s", call.Data, blockTag)
	}
}

func (provider *sdkSenderProvider) EIP1559FeeData(ctx context.Context) (railevents.EIP1559FeeData, error) {
	if err := ctx.Err(); err != nil {
		return railevents.EIP1559FeeData{}, err
	}
	return railevents.EIP1559FeeData{
		BaseFeePerGas:        big.NewInt(1_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(2_000_000_000),
		MaxFeePerGas:         big.NewInt(4_000_000_000),
	}, nil
}

func (provider *sdkSenderProvider) SendRawTransaction(ctx context.Context, signedTransaction string) (string, error) {
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
	provider.sentNonces = append(provider.sentNonces, tx.Nonce())
	if provider.sendFailures > 0 {
		provider.sendFailures--
		return "", fmt.Errorf("nonce too low")
	}
	provider.sentHash = tx.Hash().Hex()
	if provider.advanceOnSend {
		provider.latest++
	}
	return provider.sentHash, nil
}

func (provider *sdkSenderProvider) TransactionReceipt(ctx context.Context, txHash string) (railevents.TransactionReceipt, bool, error) {
	if err := ctx.Err(); err != nil {
		return railevents.TransactionReceipt{}, false, err
	}
	status := uint64(1)
	if provider.receiptStatus != nil {
		status = *provider.receiptStatus
	}
	return railevents.TransactionReceipt{
		TransactionHash: txHash,
		BlockNumber:     99,
		Status:          &status,
		Logs:            []railevents.ContractLog{},
	}, true, nil
}

func uint256Hex(value *big.Int) (string, error) {
	if value == nil {
		value = big.NewInt(0)
	}
	return railcrypto.BigIntToHex(value, 32, true)
}

func assertStringSlicesEqual(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("string slice length mismatch: got %d want %d (%+v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("string slice[%d] mismatch: got %s want %s", i, got[i], want[i])
		}
	}
}

func assertUint64SlicesEqual(t *testing.T, got []uint64, want []uint64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("uint64 slice length mismatch: got %d want %d (%+v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("uint64 slice[%d] mismatch: got %d want %d", i, got[i], want[i])
		}
	}
}
