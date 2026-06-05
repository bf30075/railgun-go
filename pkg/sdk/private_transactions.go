package sdk

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/accounts/abi"

	railaddress "github.com/bf30075/railgun-go/pkg/address"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
	railtransaction "github.com/bf30075/railgun-go/pkg/transaction"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

const (
	defaultMaxNonceRetries          = 5
	defaultTransactionPollInterval  = time.Second
	defaultBscRailgunProxyContract  = "0x590162bf4b50f6576a459b75309ee21d92178a10"
	defaultRailgunArtifactGateway   = "https://ipfs-lb.com/ipfs/"
	defaultRailgunArtifactMasterCID = "QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU"
)

const erc20ABIJSON = `[
  {
    "type": "function",
    "name": "balanceOf",
    "stateMutability": "view",
    "outputs": [{"name": "", "type": "uint256"}],
    "inputs": [{"name": "account", "type": "address"}]
  },
  {
    "type": "function",
    "name": "allowance",
    "stateMutability": "view",
    "outputs": [{"name": "", "type": "uint256"}],
    "inputs": [
      {"name": "owner", "type": "address"},
      {"name": "spender", "type": "address"}
    ]
  },
  {
    "type": "function",
    "name": "approve",
    "stateMutability": "nonpayable",
    "outputs": [{"name": "", "type": "bool"}],
    "inputs": [
      {"name": "spender", "type": "address"},
      {"name": "amount", "type": "uint256"}
    ]
  }
]`

// ShieldERC20Request 配置 ERC20 shield 交易。
type ShieldERC20Request struct {
	RecipientRailgunAddress string
	TokenAddress            string
	Amount                  *big.Int
	Decimals                int
	PollInterval            time.Duration
	MaxNonceRetries         int
	Progress                func(TransactionProgress)
}

// ShieldBaseTokenRequest 配置 base-token shield 交易。
type ShieldBaseTokenRequest struct {
	RecipientRailgunAddress string
	Amount                  *big.Int
	PollInterval            time.Duration
	MaxNonceRetries         int
	Progress                func(TransactionProgress)
}

// ShieldBaseTokenResult 描述已提交的 base-token shield 交易。
type ShieldBaseTokenResult struct {
	FromAddress             string                          `json:"fromAddress"`
	RecipientRailgunAddress string                          `json:"recipientRailgunAddress"`
	RelayAdaptContract      string                          `json:"relayAdaptContract"`
	WrappedBaseToken        string                          `json:"wrappedBaseToken"`
	Amount                  *big.Int                        `json:"amountWei"`
	Transaction             SubmittedTransactionWithReceipt `json:"transaction"`
	To                      string                          `json:"to"`
	Data                    string                          `json:"data"`
	Value                   *big.Int                        `json:"valueWei"`
}

// ShieldERC20Result 描述 approval 状态和已提交的 ERC20 shield 交易。
type ShieldERC20Result struct {
	FromAddress             string                           `json:"fromAddress"`
	RecipientRailgunAddress string                           `json:"recipientRailgunAddress"`
	RailgunSmartWallet      string                           `json:"railgunSmartWallet"`
	TokenAddress            string                           `json:"tokenAddress"`
	Decimals                int                              `json:"decimals"`
	Amount                  *big.Int                         `json:"amountWei"`
	PublicBalance           *big.Int                         `json:"publicBalanceWei"`
	AllowanceBefore         *big.Int                         `json:"allowanceBeforeWei"`
	AllowanceAfter          *big.Int                         `json:"allowanceAfterWei"`
	Approval                *SubmittedTransactionWithReceipt `json:"approval,omitempty"`
	Shield                  SubmittedTransactionWithReceipt  `json:"shield"`
	To                      string                           `json:"to"`
	Data                    string                           `json:"data"`
	Value                   *big.Int                         `json:"valueWei"`
}

// UnshieldBaseTokenV2Request 配置 V2 base-token unshield 交易。
//
// Amount 为 nil 时，runtime 会花费全部可用 WBNB 余额。ArtifactCacheDir 只在没有
// 显式配置 proof artifact 时使用。
type UnshieldBaseTokenV2Request struct {
	RecipientAddress string
	Amount           *big.Int
	Proof            ProofConfig
	ArtifactCacheDir string
	HTTPClient       *http.Client
	PollInterval     time.Duration
	MaxNonceRetries  int
	Progress         func(TransactionProgress)
	ProofProgress    railproof.ProgressCallback
}

// UnshieldBaseTokenV2Result 描述 proof、花费输入和已提交的 base-token unshield
// 交易。
type UnshieldBaseTokenV2Result struct {
	RecipientAddress       string                          `json:"recipientAddress"`
	RelayAdaptContract     string                          `json:"relayAdaptContract"`
	WrappedBaseToken       string                          `json:"wrappedBaseToken"`
	Amount                 *big.Int                        `json:"amountWei"`
	RelayAdaptParamsRandom string                          `json:"relayAdaptParamsRandom"`
	RelayAdaptParams       string                          `json:"relayAdaptParams"`
	Circuit                string                          `json:"circuit"`
	MerkleRoot             string                          `json:"merkleRoot"`
	SpendUTXOs             []UnshieldUTXO                  `json:"spendUtxos"`
	ProofArtifactManifest  string                          `json:"proofArtifactManifest,omitempty"`
	Transaction            SubmittedTransactionWithReceipt `json:"transaction"`
	To                     string                          `json:"to"`
	Data                   string                          `json:"data"`
	Value                  *big.Int                        `json:"valueWei"`
}

// UnshieldERC20V2Request 配置 V2 ERC20 unshield 交易。
//
// Amount 为 nil 时，runtime 会花费全部可用 token 余额。ArtifactCacheDir 只在没有
// 显式配置 proof artifact 时使用。
type UnshieldERC20V2Request struct {
	RecipientAddress string
	TokenData        railcrypto.TokenData
	Amount           *big.Int
	Proof            ProofConfig
	ArtifactCacheDir string
	HTTPClient       *http.Client
	PollInterval     time.Duration
	MaxNonceRetries  int
	Progress         func(TransactionProgress)
	ProofProgress    railproof.ProgressCallback
}

// TransactionProgress 报告私有执行的粗粒度进度。
type TransactionProgress struct {
	Stage   string
	Message string
}

// UnshieldERC20V2Result 描述 proof、花费输入和已提交的 ERC20 unshield 交易。
type UnshieldERC20V2Result struct {
	RecipientAddress      string                          `json:"recipientAddress"`
	RailgunSmartWallet    string                          `json:"railgunSmartWallet"`
	TokenAddress          string                          `json:"tokenAddress"`
	Amount                *big.Int                        `json:"amountWei"`
	Circuit               string                          `json:"circuit"`
	MerkleRoot            string                          `json:"merkleRoot"`
	SpendUTXOs            []UnshieldUTXO                  `json:"spendUtxos"`
	ProofArtifactManifest string                          `json:"proofArtifactManifest,omitempty"`
	Transaction           SubmittedTransactionWithReceipt `json:"transaction"`
	To                    string                          `json:"to"`
	Data                  string                          `json:"data"`
	Value                 *big.Int                        `json:"valueWei"`
}

// UnshieldUTXO 描述 unshield 中花费的一个私有 UTXO。
type UnshieldUTXO struct {
	Nullifier string `json:"nullifier"`
	TXID      string `json:"txid"`
	Tree      uint64 `json:"tree"`
	Position  uint64 `json:"position"`
	ValueWei  string `json:"valueWei"`
}

type contractCallProvider interface {
	Call(ctx context.Context, call railevents.TransactionCall, blockTag string) (string, error)
}

type defaultRailgunArtifactHash struct {
	Variant string
	ZKey    string
	WASM    string
}

var defaultRailgunArtifacts = map[string]defaultRailgunArtifactHash{
	railproof.RailgunArtifactKey(1, 1): {Variant: "01x01", ZKey: "27443e834f807f0d4ce8a0c2a0e028d1d540cba9c3e4d64b864b367e797215f4", WASM: "37a1528543305c64805e3c607940341abf61ba8516f73cfeb625cd09e5bda7a6"},
	railproof.RailgunArtifactKey(1, 2): {Variant: "01x02", ZKey: "8ef8e7abcfb5e60fb593d4d961657465f498435a0835adef05acc09534d7557b", WASM: "6ce87ddb4e33cff9564338a8b1f58047b22809e5d198f243c777d1aa4eaaa1e3"},
	railproof.RailgunArtifactKey(1, 3): {Variant: "01x03", ZKey: "477aeca6a8ed3706f572bce0e99a7054e700a4e3c2ee4499d7013a4d7770e0d0", WASM: "72e55865fccca077f443bae9f1e6762a156ea478a137efc1324fb79153050276"},
	railproof.RailgunArtifactKey(2, 1): {Variant: "02x01", ZKey: "46c11ebba432fce6b8d942c68e665a1b082e1896d9612cf8e632b5ffd763e4fc", WASM: "4a3834b734981268ac8666fed811f89d9c6c318f01a57b391ba7a21ce59314b5"},
	railproof.RailgunArtifactKey(2, 2): {Variant: "02x02", ZKey: "47c279ec3fcc8bdcc7a2fb80078e38ba8ca3a7bbaa608967c3c3af82f1d454e5", WASM: "8595023762a3067b70960be81e1a983c1630c9900d4caef3d608b9d849568829"},
	railproof.RailgunArtifactKey(2, 3): {Variant: "02x03", ZKey: "75611fffbc675993e55964404136df2a4e59821b40103ebe7afafc6c76863d11", WASM: "20ab2f0987f94b6e959fcf11c9d37415c98848acd6a900a0ca75768db3938afa"},
	railproof.RailgunArtifactKey(3, 1): {Variant: "03x01", ZKey: "8c77cf004883d3f3b8ac236d1d4893bc3ce2b5f14f280efa67a3a875387426db", WASM: "d4fee72ffd4d44e3de711330d55def396cb1dc97fd398278bf0e4276bec2937a"},
	railproof.RailgunArtifactKey(3, 2): {Variant: "03x02", ZKey: "9072c04e553fb2ec060362c533a590d1037e387017c8bb004da8e18c97676014", WASM: "0a2f0c62013e02a9ef3a7dc08d0f470bd45a812fea598f3f9ced7b0612b85445"},
	railproof.RailgunArtifactKey(3, 3): {Variant: "03x03", ZKey: "e008d46ba4a249ba79727417b314cf8a4bd4d1cb400468437f791cd8da4410de", WASM: "6ee412340538ddafb422906711c2fdcc4bf8e945c525e336bd54d093820f9922"},
}

type preparedUnshieldBNB struct {
	RecipientAddress       string
	RelayAdaptAddress      string
	WrappedBaseToken       string
	Amount                 *big.Int
	RelayAdaptParamsRandom string
	RelayAdaptParams       string
	Circuit                string
	MerkleRoot             string
	SpendUTXOs             []railwallet.StoredTXO
	Inputs                 railtransaction.DummyTransactionBatchInputs
}

type preparedUnshieldERC20 struct {
	RecipientAddress   string
	RailgunSmartWallet string
	TokenAddress       string
	Amount             *big.Int
	Circuit            string
	MerkleRoot         string
	SpendUTXOs         []railwallet.StoredTXO
	Inputs             railtransaction.DummyTransactionBatchInputs
}

// ShieldBaseToken 通过 RelayAdapt 提交 base-token shield 交易。
func (runtime *Runtime) ShieldBaseToken(ctx context.Context, request ShieldBaseTokenRequest) (ShieldBaseTokenResult, error) {
	if err := runtime.validatePrivateExecution(); err != nil {
		return ShieldBaseTokenResult{}, err
	}
	amount := cloneBigInt(request.Amount)
	if amount.Sign() <= 0 {
		return ShieldBaseTokenResult{}, fmt.Errorf("amount must be greater than zero")
	}
	fromAddress, err := railtransaction.AddressFromPrivateKey(runtime.secret.EthereumPrivateKey)
	if err != nil {
		return ShieldBaseTokenResult{}, err
	}
	relayAdaptAddress, err := normalizedContractAddress(runtime.network, "relayAdaptContract")
	if err != nil {
		return ShieldBaseTokenResult{}, err
	}
	wrappedBaseToken, err := normalizedContractAddress(runtime.network, "wrappedBaseToken")
	if err != nil {
		return ShieldBaseTokenResult{}, err
	}
	reportTransactionProgress(request.Progress, "proving", "building shield note")
	shieldRequest, err := shieldRequestForRailgunAddress(request.RecipientRailgunAddress, wrappedBaseToken, amount)
	if err != nil {
		return ShieldBaseTokenResult{}, err
	}
	populated, err := railtransaction.RelayAdaptPopulateShieldBaseToken(relayAdaptAddress, shieldRequest)
	if err != nil {
		return ShieldBaseTokenResult{}, err
	}
	reportTransactionProgress(request.Progress, "broadcasting", "sending BNB shield transaction")
	submitted, err := runtime.SendEIP1559TransactionWithLatestNonceAndWait(ctx, railtransaction.SendEIP1559TransactionRequest{
		PrivateKey: runtime.secret.EthereumPrivateKey,
		To:         populated.To,
		Data:       populated.Data,
		Value:      populated.Value,
		GasLimit:   uint64FromBigInt(populated.GasLimit),
	}, normalizedMaxNonceRetries(request.MaxNonceRetries), normalizedPollInterval(request.PollInterval))
	if err != nil {
		return ShieldBaseTokenResult{}, err
	}
	if transactionReverted(submitted) {
		callError, ok, callErr := relayAdaptCallError(submitted.Receipt.Logs)
		if callErr != nil {
			return ShieldBaseTokenResult{}, callErr
		}
		if ok {
			return ShieldBaseTokenResult{}, fmt.Errorf("BNB shield transaction reverted: %s (%s)", submitted.Transaction.Hash, callError)
		}
		return ShieldBaseTokenResult{}, fmt.Errorf("BNB shield transaction reverted: %s", submitted.Transaction.Hash)
	}
	return ShieldBaseTokenResult{
		FromAddress:             fromAddress,
		RecipientRailgunAddress: strings.TrimSpace(request.RecipientRailgunAddress),
		RelayAdaptContract:      relayAdaptAddress,
		WrappedBaseToken:        wrappedBaseToken,
		Amount:                  amount,
		Transaction:             submitted,
		To:                      populated.To,
		Data:                    populated.Data,
		Value:                   cloneBigInt(populated.Value),
	}, nil
}

// ShieldERC20 在需要时先 approve allowance，然后提交 ERC20 shield 交易。
func (runtime *Runtime) ShieldERC20(ctx context.Context, request ShieldERC20Request) (ShieldERC20Result, error) {
	if err := runtime.validatePrivateExecution(); err != nil {
		return ShieldERC20Result{}, err
	}
	amount := cloneBigInt(request.Amount)
	if amount.Sign() <= 0 {
		return ShieldERC20Result{}, fmt.Errorf("amount must be greater than zero")
	}
	tokenAddress, err := normalizeTokenAddress(request.TokenAddress)
	if err != nil {
		return ShieldERC20Result{}, err
	}
	fromAddress, err := railtransaction.AddressFromPrivateKey(runtime.secret.EthereumPrivateKey)
	if err != nil {
		return ShieldERC20Result{}, err
	}
	smartWalletAddress, err := railgunSmartWalletV2Address(runtime.network)
	if err != nil {
		return ShieldERC20Result{}, err
	}
	shieldRequest, err := shieldRequestForRailgunAddress(request.RecipientRailgunAddress, tokenAddress, amount)
	if err != nil {
		return ShieldERC20Result{}, err
	}
	data, err := railtransaction.EncodeShieldV2Calldata([]railtransaction.ShieldRequest{shieldRequest})
	if err != nil {
		return ShieldERC20Result{}, err
	}
	caller, err := runtime.contractCaller()
	if err != nil {
		return ShieldERC20Result{}, err
	}
	publicBalance, err := erc20BalanceOf(ctx, caller, tokenAddress, fromAddress)
	if err != nil {
		return ShieldERC20Result{}, err
	}
	if publicBalance.Cmp(amount) < 0 {
		return ShieldERC20Result{}, fmt.Errorf("insufficient public ERC20 balance: have %s need %s", publicBalance.String(), amount.String())
	}
	allowanceBefore, err := erc20Allowance(ctx, caller, tokenAddress, fromAddress, smartWalletAddress)
	if err != nil {
		return ShieldERC20Result{}, err
	}
	result := ShieldERC20Result{
		FromAddress:             fromAddress,
		RecipientRailgunAddress: strings.TrimSpace(request.RecipientRailgunAddress),
		RailgunSmartWallet:      smartWalletAddress,
		TokenAddress:            tokenAddress,
		Decimals:                request.Decimals,
		Amount:                  amount,
		PublicBalance:           cloneBigInt(publicBalance),
		AllowanceBefore:         cloneBigInt(allowanceBefore),
		AllowanceAfter:          cloneBigInt(allowanceBefore),
		To:                      smartWalletAddress,
		Data:                    data,
		Value:                   big.NewInt(0),
	}
	if allowanceBefore.Cmp(amount) < 0 {
		reportTransactionProgress(request.Progress, "approving", "approving ERC20 allowance")
		approveData, err := encodeERC20ApproveCalldata(smartWalletAddress, amount)
		if err != nil {
			return ShieldERC20Result{}, err
		}
		approval, err := runtime.SendEIP1559TransactionWithLatestNonceAndWait(ctx, railtransaction.SendEIP1559TransactionRequest{
			PrivateKey: runtime.secret.EthereumPrivateKey,
			To:         tokenAddress,
			Data:       approveData,
			Value:      big.NewInt(0),
		}, normalizedMaxNonceRetries(request.MaxNonceRetries), normalizedPollInterval(request.PollInterval))
		if err != nil {
			return ShieldERC20Result{}, err
		}
		if transactionReverted(approval) {
			return ShieldERC20Result{}, fmt.Errorf("ERC20 approve transaction reverted: %s", approval.Transaction.Hash)
		}
		result.Approval = &approval
		allowanceAfter, err := erc20Allowance(ctx, caller, tokenAddress, fromAddress, smartWalletAddress)
		if err != nil {
			return ShieldERC20Result{}, err
		}
		result.AllowanceAfter = cloneBigInt(allowanceAfter)
		if allowanceAfter.Cmp(amount) < 0 {
			return ShieldERC20Result{}, fmt.Errorf("ERC20 allowance after approval is insufficient: have %s need %s", allowanceAfter.String(), amount.String())
		}
	}
	reportTransactionProgress(request.Progress, "broadcasting", "sending ERC20 shield transaction")
	submitted, err := runtime.SendEIP1559TransactionWithLatestNonceAndWait(ctx, railtransaction.SendEIP1559TransactionRequest{
		PrivateKey: runtime.secret.EthereumPrivateKey,
		To:         smartWalletAddress,
		Data:       data,
		Value:      big.NewInt(0),
	}, normalizedMaxNonceRetries(request.MaxNonceRetries), normalizedPollInterval(request.PollInterval))
	if err != nil {
		return ShieldERC20Result{}, err
	}
	if transactionReverted(submitted) {
		return ShieldERC20Result{}, fmt.Errorf("ERC20 shield transaction reverted: %s", submitted.Transaction.Hash)
	}
	result.Shield = submitted
	return result, nil
}

// UnshieldBaseTokenV2 生成 proof 并提交 V2 base-token unshield 交易。
func (runtime *Runtime) UnshieldBaseTokenV2(ctx context.Context, request UnshieldBaseTokenV2Request) (UnshieldBaseTokenV2Result, error) {
	if err := runtime.validatePrivateExecution(); err != nil {
		return UnshieldBaseTokenV2Result{}, err
	}
	prepared, err := prepareUnshieldBNB(ctx, runtime, *runtime.secret, runtime.network, cloneBigIntOrNil(request.Amount), request.RecipientAddress)
	if err != nil {
		return UnshieldBaseTokenV2Result{}, err
	}
	unproved, err := unprovedTransactions(*runtime.secret, prepared.Inputs)
	if err != nil {
		return UnshieldBaseTokenV2Result{}, err
	}
	prover, manifestPath, err := runtime.proverForUnshield(ctx, request.Proof, request.ArtifactCacheDir, unproved, request.HTTPClient)
	if err != nil {
		return UnshieldBaseTokenV2Result{}, err
	}
	reportTransactionProgress(request.Progress, "proving", "generating BNB unshield proof")
	proved, err := railtransaction.ProveUnprovedTransactionsV2(ctx, prover, unproved, request.ProofProgress)
	if err != nil {
		return UnshieldBaseTokenV2Result{}, err
	}
	populated, err := railtransaction.RelayAdaptPopulateUnshieldBaseTokenV2(proved, prepared.RelayAdaptAddress, prepared.RecipientAddress, prepared.RelayAdaptParamsRandom, true)
	if err != nil {
		return UnshieldBaseTokenV2Result{}, err
	}
	reportTransactionProgress(request.Progress, "broadcasting", "sending BNB unshield transaction")
	submitted, err := runtime.sendRelayAdaptRequest(ctx, populated, request.MaxNonceRetries, request.PollInterval)
	if err != nil {
		return UnshieldBaseTokenV2Result{}, err
	}
	return UnshieldBaseTokenV2Result{
		RecipientAddress:       prepared.RecipientAddress,
		RelayAdaptContract:     prepared.RelayAdaptAddress,
		WrappedBaseToken:       prepared.WrappedBaseToken,
		Amount:                 cloneBigInt(prepared.Amount),
		RelayAdaptParamsRandom: prepared.RelayAdaptParamsRandom,
		RelayAdaptParams:       prepared.RelayAdaptParams,
		Circuit:                prepared.Circuit,
		MerkleRoot:             prepared.MerkleRoot,
		SpendUTXOs:             unshieldUTXOOutputs(prepared.SpendUTXOs),
		ProofArtifactManifest:  manifestPath,
		Transaction:            submitted,
		To:                     populated.To,
		Data:                   populated.Data,
		Value:                  cloneBigInt(populated.Value),
	}, nil
}

// UnshieldERC20V2 生成 proof 并提交 V2 ERC20 unshield 交易。
func (runtime *Runtime) UnshieldERC20V2(ctx context.Context, request UnshieldERC20V2Request) (UnshieldERC20V2Result, error) {
	if err := runtime.validatePrivateExecution(); err != nil {
		return UnshieldERC20V2Result{}, err
	}
	prepared, err := prepareUnshieldERC20(ctx, runtime, *runtime.secret, runtime.network, request.TokenData, cloneBigIntOrNil(request.Amount), request.RecipientAddress)
	if err != nil {
		return UnshieldERC20V2Result{}, err
	}
	unproved, err := unprovedTransactions(*runtime.secret, prepared.Inputs)
	if err != nil {
		return UnshieldERC20V2Result{}, err
	}
	prover, manifestPath, err := runtime.proverForUnshield(ctx, request.Proof, request.ArtifactCacheDir, unproved, request.HTTPClient)
	if err != nil {
		return UnshieldERC20V2Result{}, err
	}
	reportTransactionProgress(request.Progress, "proving", "generating ERC20 unshield proof")
	proved, err := railtransaction.ProveUnprovedTransactionsV2(ctx, prover, unproved, request.ProofProgress)
	if err != nil {
		return UnshieldERC20V2Result{}, err
	}
	data, err := railtransaction.EncodeTransactV2Calldata(proved)
	if err != nil {
		return UnshieldERC20V2Result{}, err
	}
	populated, err := newTransactionRequest(prepared.RailgunSmartWallet, data, big.NewInt(0), nil)
	if err != nil {
		return UnshieldERC20V2Result{}, err
	}
	reportTransactionProgress(request.Progress, "broadcasting", "sending ERC20 unshield transaction")
	submitted, err := runtime.sendRelayAdaptRequest(ctx, populated, request.MaxNonceRetries, request.PollInterval)
	if err != nil {
		return UnshieldERC20V2Result{}, err
	}
	return UnshieldERC20V2Result{
		RecipientAddress:      prepared.RecipientAddress,
		RailgunSmartWallet:    prepared.RailgunSmartWallet,
		TokenAddress:          prepared.TokenAddress,
		Amount:                cloneBigInt(prepared.Amount),
		Circuit:               prepared.Circuit,
		MerkleRoot:            prepared.MerkleRoot,
		SpendUTXOs:            unshieldUTXOOutputs(prepared.SpendUTXOs),
		ProofArtifactManifest: manifestPath,
		Transaction:           submitted,
		To:                    populated.To,
		Data:                  populated.Data,
		Value:                 cloneBigInt(populated.Value),
	}, nil
}

func (runtime *Runtime) sendRelayAdaptRequest(ctx context.Context, request railtransaction.RelayAdaptTransactionRequest, maxNonceRetries int, pollInterval time.Duration) (SubmittedTransactionWithReceipt, error) {
	submitted, err := runtime.SendEIP1559TransactionWithLatestNonceAndWait(ctx, railtransaction.SendEIP1559TransactionRequest{
		PrivateKey: runtime.secret.EthereumPrivateKey,
		To:         request.To,
		Data:       request.Data,
		Value:      request.Value,
		GasLimit:   uint64FromBigInt(request.GasLimit),
	}, normalizedMaxNonceRetries(maxNonceRetries), normalizedPollInterval(pollInterval))
	if err != nil {
		return SubmittedTransactionWithReceipt{}, err
	}
	if !transactionReverted(submitted) {
		return submitted, nil
	}
	callError, ok, callErr := relayAdaptCallError(submitted.Receipt.Logs)
	if callErr != nil {
		return SubmittedTransactionWithReceipt{}, callErr
	}
	if ok {
		return SubmittedTransactionWithReceipt{}, fmt.Errorf("unshield transaction reverted: %s (%s)", submitted.Transaction.Hash, callError)
	}
	return SubmittedTransactionWithReceipt{}, fmt.Errorf("unshield transaction reverted: %s", submitted.Transaction.Hash)
}

func (runtime *Runtime) validatePrivateExecution() error {
	if runtime == nil {
		return fmt.Errorf("runtime is required")
	}
	if runtime.secret == nil {
		return fmt.Errorf("wallet secret is required")
	}
	if strings.TrimSpace(runtime.secret.EthereumPrivateKey) == "" {
		return fmt.Errorf("wallet EVM private key is required")
	}
	return nil
}

func (runtime *Runtime) contractCaller() (contractCallProvider, error) {
	if err := runtime.validateProvider(); err != nil {
		return nil, err
	}
	caller, ok := runtime.engine.provider.(contractCallProvider)
	if !ok {
		return nil, fmt.Errorf("runtime provider does not support contract calls")
	}
	return caller, nil
}

func prepareUnshieldBNB(ctx context.Context, runtime *Runtime, secret railwallet.WalletSecret, config NetworkConfig, amount *big.Int, recipient string) (preparedUnshieldBNB, error) {
	if runtime == nil || runtime.engine == nil || runtime.engine.wallet == nil {
		return preparedUnshieldBNB{}, fmt.Errorf("runtime wallet is required")
	}
	fromAddress, err := railtransaction.AddressFromPrivateKey(secret.EthereumPrivateKey)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	recipient = strings.TrimSpace(recipient)
	if recipient == "" {
		recipient = fromAddress
	}
	recipient, err = railcrypto.FormatHexToByteLength(recipient, 20, true)
	if err != nil {
		return preparedUnshieldBNB{}, fmt.Errorf("recipient address: %w", err)
	}
	relayAdaptAddress, err := normalizedContractAddress(config, "relayAdaptContract")
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	wrappedBaseToken, err := normalizedContractAddress(config, "wrappedBaseToken")
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	tokenData, err := railcrypto.TokenDataERC20(wrappedBaseToken)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	treeBalances, txoByID, err := spendableTokenTreeBalances(ctx, runtime.engine.wallet, tokenHash)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	if amount == nil {
		amount = transactionTreeBalanceTotal(treeBalances)
	}
	if amount == nil || amount.Sign() <= 0 {
		return preparedUnshieldBNB{}, fmt.Errorf("no positive spendable WBNB balance")
	}
	solution, spendTXOs, err := selectSpendableUTXOs(treeBalances, txoByID, amount)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	inputs, merkleRoot, err := buildUnshieldTokenBatchInputs(ctx, runtime, secret, config, relayAdaptAddress, tokenData, amount, solution, spendTXOs)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	dummyTransactions, err := railtransaction.GenerateDummyTransactionsV2(inputs)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	relayRandom, err := randomHex(31)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	relayParams, err := railtransaction.RelayAdaptParamsUnshieldBaseTokenV2(dummyTransactions, relayAdaptAddress, recipient, relayRandom, true)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	inputs.AdaptID = railtransaction.AdaptID{Contract: relayAdaptAddress, Params: relayParams}
	finalDummyTransactions, err := railtransaction.GenerateDummyTransactionsV2(inputs)
	if err != nil {
		return preparedUnshieldBNB{}, err
	}
	if len(finalDummyTransactions) == 0 {
		return preparedUnshieldBNB{}, fmt.Errorf("no transactions generated")
	}
	circuit := railproof.RailgunArtifactKey(len(finalDummyTransactions[0].Nullifiers), len(finalDummyTransactions[0].Commitments))
	return preparedUnshieldBNB{
		RecipientAddress:       recipient,
		RelayAdaptAddress:      relayAdaptAddress,
		WrappedBaseToken:       wrappedBaseToken,
		Amount:                 cloneBigInt(amount),
		RelayAdaptParamsRandom: relayRandom,
		RelayAdaptParams:       relayParams,
		Circuit:                circuit,
		MerkleRoot:             merkleRoot,
		SpendUTXOs:             spendTXOs,
		Inputs:                 inputs,
	}, nil
}

func prepareUnshieldERC20(ctx context.Context, runtime *Runtime, secret railwallet.WalletSecret, config NetworkConfig, tokenData railcrypto.TokenData, amount *big.Int, recipient string) (preparedUnshieldERC20, error) {
	if runtime == nil || runtime.engine == nil || runtime.engine.wallet == nil {
		return preparedUnshieldERC20{}, fmt.Errorf("runtime wallet is required")
	}
	fromAddress, err := railtransaction.AddressFromPrivateKey(secret.EthereumPrivateKey)
	if err != nil {
		return preparedUnshieldERC20{}, err
	}
	recipient = strings.TrimSpace(recipient)
	if recipient == "" {
		recipient = fromAddress
	}
	recipient, err = railcrypto.FormatHexToByteLength(recipient, 20, true)
	if err != nil {
		return preparedUnshieldERC20{}, fmt.Errorf("recipient address: %w", err)
	}
	smartWalletAddress, err := railgunSmartWalletV2Address(config)
	if err != nil {
		return preparedUnshieldERC20{}, err
	}
	tokenAddress, err := normalizeTokenAddress(tokenData.TokenAddress)
	if err != nil {
		return preparedUnshieldERC20{}, err
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		return preparedUnshieldERC20{}, err
	}
	treeBalances, txoByID, err := spendableTokenTreeBalances(ctx, runtime.engine.wallet, tokenHash)
	if err != nil {
		return preparedUnshieldERC20{}, err
	}
	if amount == nil {
		amount = transactionTreeBalanceTotal(treeBalances)
	}
	if amount == nil || amount.Sign() <= 0 {
		return preparedUnshieldERC20{}, fmt.Errorf("no positive spendable ERC20 balance for %s", tokenAddress)
	}
	solution, spendTXOs, err := selectSpendableUTXOs(treeBalances, txoByID, amount)
	if err != nil {
		return preparedUnshieldERC20{}, err
	}
	inputs, merkleRoot, err := buildUnshieldTokenBatchInputs(ctx, runtime, secret, config, recipient, tokenData, amount, solution, spendTXOs)
	if err != nil {
		return preparedUnshieldERC20{}, err
	}
	dummyTransactions, err := railtransaction.GenerateDummyTransactionsV2(inputs)
	if err != nil {
		return preparedUnshieldERC20{}, err
	}
	if len(dummyTransactions) == 0 {
		return preparedUnshieldERC20{}, fmt.Errorf("no transactions generated")
	}
	circuit := railproof.RailgunArtifactKey(len(dummyTransactions[0].Nullifiers), len(dummyTransactions[0].Commitments))
	return preparedUnshieldERC20{
		RecipientAddress:   recipient,
		RailgunSmartWallet: smartWalletAddress,
		TokenAddress:       tokenAddress,
		Amount:             cloneBigInt(amount),
		Circuit:            circuit,
		MerkleRoot:         merkleRoot,
		SpendUTXOs:         spendTXOs,
		Inputs:             inputs,
	}, nil
}

func selectSpendableUTXOs(treeBalances []railtransaction.TreeBalance, txoByID map[string]railwallet.StoredTXO, amount *big.Int) (railtransaction.SimpleUTXOGroup, []railwallet.StoredTXO, error) {
	solution, err := railtransaction.CreateSimpleSatisfyingUTXOGroup(treeBalances, amount)
	if err != nil {
		return railtransaction.SimpleUTXOGroup{}, nil, err
	}
	spendTXOs := make([]railwallet.StoredTXO, len(solution.UTXOs))
	for i, solutionTXO := range solution.UTXOs {
		txo, ok := txoByID[solutionTXO.ID]
		if !ok {
			return railtransaction.SimpleUTXOGroup{}, nil, fmt.Errorf("missing selected txo %s", solutionTXO.ID)
		}
		spendTXOs[i] = txo
	}
	return solution, spendTXOs, nil
}

func spendableTokenTreeBalances(ctx context.Context, wallet *railwallet.Wallet, tokenHash string) ([]railtransaction.TreeBalance, map[string]railwallet.StoredTXO, error) {
	if wallet == nil {
		return nil, nil, fmt.Errorf("wallet is required")
	}
	txos, err := wallet.State.ListTXOs(ctx)
	if err != nil {
		return nil, nil, err
	}
	treeBalances := []railtransaction.TreeBalance{}
	txoByID := map[string]railwallet.StoredTXO{}
	for _, txo := range txos {
		if txo.TXIDVersion != railcrypto.TXIDVersionV2PoseidonMerkle || txo.SpendTXID != "" {
			continue
		}
		txoTokenHash := txo.TokenHash
		if txoTokenHash == "" {
			txoTokenHash, err = railcrypto.TokenDataHash(txo.TokenData)
			if err != nil {
				return nil, nil, err
			}
		}
		if !strings.EqualFold(railcrypto.Strip0x(txoTokenHash), railcrypto.Strip0x(tokenHash)) {
			continue
		}
		if txo.Value == nil || txo.Value.Sign() <= 0 {
			continue
		}
		if txo.NoteRandom == "" {
			return nil, nil, fmt.Errorf("txo %s is missing note random; delete/resync this wallet state before unshielding", txo.Nullifier)
		}
		bucket := wallet.POIManager.GetBalanceBucket(railpoi.TXO{
			SpendTXID:                   txo.SpendTXID,
			POIsPerList:                 txo.POIsPerList,
			CommitmentType:              txo.CommitmentType,
			OutputType:                  txo.OutputType,
			Value:                       cloneBigInt(txo.Value),
			BlindedCommitment:           txo.BlindedCommitment,
			BlockNumber:                 txo.BlockNumber,
			TransactCreationRailgunTxid: txo.TransactCreationRailgunTxid,
		})
		if bucket != railpoi.WalletBalanceBucketSpendable {
			continue
		}
		for len(treeBalances) <= int(txo.Tree) {
			treeBalances = append(treeBalances, railtransaction.TreeBalance{})
		}
		if treeBalances[txo.Tree].Balance == nil {
			treeBalances[txo.Tree].Balance = big.NewInt(0)
		}
		treeBalances[txo.Tree].Balance.Add(treeBalances[txo.Tree].Balance, txo.Value)
		treeBalances[txo.Tree].UTXOs = append(treeBalances[txo.Tree].UTXOs, railtransaction.SolutionTXO{
			ID:       txo.Nullifier,
			TXID:     txo.TXID,
			Tree:     int(txo.Tree),
			Position: txo.Position,
			Value:    cloneBigInt(txo.Value),
		})
		txoByID[txo.Nullifier] = txo
	}
	return treeBalances, txoByID, nil
}

func transactionTreeBalanceTotal(treeBalances []railtransaction.TreeBalance) *big.Int {
	total := big.NewInt(0)
	for _, treeBalance := range treeBalances {
		if treeBalance.Balance != nil {
			total.Add(total, treeBalance.Balance)
		}
	}
	return total
}

func buildUnshieldTokenBatchInputs(ctx context.Context, runtime *Runtime, secret railwallet.WalletSecret, config NetworkConfig, unshieldAddress string, tokenData railcrypto.TokenData, amount *big.Int, solution railtransaction.SimpleUTXOGroup, spendTXOs []railwallet.StoredTXO) (railtransaction.DummyTransactionBatchInputs, string, error) {
	spendingPublicKey, err := spendingPublicKeyFromSecret(secret)
	if err != nil {
		return railtransaction.DummyTransactionBatchInputs{}, "", err
	}
	batchUTXOs := make([]railtransaction.BatchUTXO, len(spendTXOs))
	merkleRoot := ""
	for i, txo := range spendTXOs {
		proof, err := railwallet.UTXOMerkleProofForTXO(ctx, runtime.engine.wallet.UTXOMerkleTree, txo)
		if err != nil {
			return railtransaction.DummyTransactionBatchInputs{}, "", fmt.Errorf("utxo %s proof: %w", txo.Nullifier, err)
		}
		if merkleRoot == "" {
			merkleRoot = proof.Root
		} else if merkleRoot != proof.Root {
			return railtransaction.DummyTransactionBatchInputs{}, "", fmt.Errorf("selected UTXOs have different merkle roots")
		}
		batchUTXOs[i] = railtransaction.BatchUTXO{
			Position:            txo.Position,
			NoteRandom:          txo.NoteRandom,
			Value:               cloneBigInt(txo.Value),
			MerkleProofElements: append([]string(nil), proof.Elements...),
		}
	}
	if merkleRoot == "" {
		return railtransaction.DummyTransactionBatchInputs{}, "", fmt.Errorf("no UTXOs selected")
	}
	inputs := railtransaction.DummyTransactionBatchInputs{
		Chain: railtransaction.Chain{
			Type: config.Chain.Type,
			ID:   config.Chain.ID,
		},
		OverallBatchMinGasPrice: big.NewInt(0),
		Wallet: railtransaction.BatchWallet{
			MasterPublicKey:   cloneBigInt(runtime.engine.wallet.Keys.MasterPublicKey),
			ViewingPrivateKey: append([]byte(nil), runtime.engine.wallet.Keys.ViewingPrivateKey...),
			ViewingPublicKey:  append([]byte(nil), runtime.engine.wallet.Keys.ViewingPublicKey...),
			SpendingPublicKey: spendingPublicKey,
			NullifyingKey:     cloneBigInt(runtime.engine.wallet.Keys.NullifyingKey),
			WalletSource:      "railgun-go",
		},
		Groups: []railtransaction.DummyTransactionGroup{{
			SpendingTree: uint32(solution.SpendingTree),
			MerkleRoot:   merkleRoot,
			TokenData:    tokenData,
			UTXOs:        batchUTXOs,
			UnshieldOutput: &railtransaction.RequestUnshieldOutput{
				ToAddress: unshieldAddress,
				Value:     cloneBigInt(amount),
				TokenData: tokenData,
			},
		}},
	}
	change := new(big.Int).Sub(solution.Amount, amount)
	if change.Sign() < 0 {
		return railtransaction.DummyTransactionBatchInputs{}, "", fmt.Errorf("selected UTXO amount is below unshield amount")
	}
	if change.Sign() > 0 {
		changeRandom, err := randomHex(16)
		if err != nil {
			return railtransaction.DummyTransactionBatchInputs{}, "", err
		}
		noteIV, err := randomHex(16)
		if err != nil {
			return railtransaction.DummyTransactionBatchInputs{}, "", err
		}
		annotationIV, err := randomHex(16)
		if err != nil {
			return railtransaction.DummyTransactionBatchInputs{}, "", err
		}
		inputs.ChangeRandoms = []string{changeRandom}
		inputs.NoteCiphertextV2IVs = [][]string{{noteIV}}
		inputs.AnnotationV2IVs = [][]string{{annotationIV}}
	}
	return inputs, merkleRoot, nil
}

func unprovedTransactions(secret railwallet.WalletSecret, inputs railtransaction.DummyTransactionBatchInputs) ([]railtransaction.UnprovedTransactionV2, error) {
	spendingPrivateKey, err := spendingPrivateKeyFromSecret(secret)
	if err != nil {
		return nil, err
	}
	return railtransaction.GenerateUnprovedTransactionsV2(inputs, spendingPrivateKey)
}

func spendingPublicKeyFromSecret(secret railwallet.WalletSecret) ([2]*big.Int, error) {
	key0, err := railcrypto.NumberishToBigInt(secret.Railgun.SpendingPublicKey[0])
	if err != nil {
		return [2]*big.Int{}, fmt.Errorf("spending public key[0]: %w", err)
	}
	key1, err := railcrypto.NumberishToBigInt(secret.Railgun.SpendingPublicKey[1])
	if err != nil {
		return [2]*big.Int{}, fmt.Errorf("spending public key[1]: %w", err)
	}
	return [2]*big.Int{key0, key1}, nil
}

func spendingPrivateKeyFromSecret(secret railwallet.WalletSecret) ([]byte, error) {
	if secret.Mnemonic == "" {
		return nil, fmt.Errorf("wallet mnemonic is required to derive the Railgun spending private key")
	}
	path := fmt.Sprintf("m/44'/1984'/0'/0'/%d'", secret.Index)
	node, err := railwallet.DeriveFromMnemonic(secret.Mnemonic, path)
	if err != nil {
		return nil, err
	}
	privateKey, err := railcrypto.HexToBytes(node.Spending.PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("spending private key is empty")
	}
	return privateKey, nil
}

func (runtime *Runtime) proverForUnshield(ctx context.Context, requested ProofConfig, cacheDir string, unproved []railtransaction.UnprovedTransactionV2, requestHTTPClient *http.Client) (*railproof.Prover, string, error) {
	httpClient := requestHTTPClient
	if httpClient == nil && runtime != nil {
		httpClient = runtime.httpClient
	}
	proofConfig, manifestPath, err := runtime.proofConfigForUnshield(ctx, requested, cacheDir, unproved, httpClient)
	if err != nil {
		return nil, "", err
	}
	if runtime != nil && runtime.proofBackend != nil {
		prover, err := NewProver(proofConfig, runtime.proofBackend, httpClient)
		if err != nil {
			return nil, "", err
		}
		return prover, manifestPath, nil
	}
	prover, err := NewRapidsnarkProver(proofConfig, httpClient)
	if err != nil {
		return nil, "", err
	}
	return prover, manifestPath, nil
}

func (runtime *Runtime) proofConfigForUnshield(ctx context.Context, requested ProofConfig, cacheDir string, unproved []railtransaction.UnprovedTransactionV2, httpClient *http.Client) (ProofConfig, string, error) {
	if len(unproved) == 0 {
		return ProofConfig{}, "", fmt.Errorf("no unproved transactions generated")
	}
	config := requested
	if proofConfigEmpty(config) && runtime != nil && runtime.proof != nil {
		config = *runtime.proof
	}
	if config.LocalArtifactManifest != "" || config.RemoteArtifactManifest != "" {
		return config, config.LocalArtifactManifest, nil
	}
	if config.ArtifactSource != "" {
		return ProofConfig{}, "", fmt.Errorf("proof artifact manifest is required for artifact source %s", config.ArtifactSource)
	}
	if strings.TrimSpace(cacheDir) == "" {
		return ProofConfig{}, "", fmt.Errorf("artifact cache dir is required")
	}
	nullifiers := len(unproved[0].Request.PublicInputs.Nullifiers)
	commitments := len(unproved[0].Request.PublicInputs.CommitmentsOut)
	manifestPath, err := ensureDefaultRailgunArtifactManifest(ctx, cacheDir, nullifiers, commitments, httpClient)
	if err != nil {
		return ProofConfig{}, "", err
	}
	config.LocalArtifactManifest = manifestPath
	return config, manifestPath, nil
}

func proofConfigEmpty(config ProofConfig) bool {
	return config.ArtifactSource == "" &&
		config.LocalArtifactManifest == "" &&
		config.RemoteArtifactManifest == "" &&
		config.RapidsnarkProverBinary == ""
}

func ensureDefaultRailgunArtifactManifest(ctx context.Context, cacheDir string, nullifiers int, commitments int, httpClient *http.Client) (string, error) {
	key := railproof.RailgunArtifactKey(nullifiers, commitments)
	spec, ok := defaultRailgunArtifacts[key]
	if !ok {
		return "", fmt.Errorf("no built-in production artifact hash for %s; configure proof artifacts", key)
	}
	artifactDir := filepath.Join(cacheDir, "railgun", spec.Variant)
	wasmPath := filepath.Join(artifactDir, spec.Variant+".wasm")
	zkeyPath := filepath.Join(artifactDir, spec.Variant+".zkey")
	vkeyPath := filepath.Join(artifactDir, spec.Variant+".vkey.json")
	if err := ensureBrotliArtifact(ctx, httpClient, railgunArtifactURL(spec.Variant, "wasm"), wasmPath, spec.WASM); err != nil {
		return "", err
	}
	if err := ensureBrotliArtifact(ctx, httpClient, railgunArtifactURL(spec.Variant, "zkey"), zkeyPath, spec.ZKey); err != nil {
		return "", err
	}
	if err := ensureRawArtifact(ctx, httpClient, railgunArtifactURL(spec.Variant, "vkey"), vkeyPath); err != nil {
		return "", err
	}
	manifest := railproof.LocalArtifactManifest{
		BaseDir: cacheDir,
		Railgun: map[string]railproof.ArtifactPathSet{
			key: {
				WASM: relativeArtifactPath(cacheDir, wasmPath),
				ZKey: relativeArtifactPath(cacheDir, zkeyPath),
				VKey: relativeArtifactPath(cacheDir, vkeyPath),
			},
		},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	manifestPath := filepath.Join(cacheDir, "railgun-artifacts.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return manifestPath, nil
}

func railgunArtifactURL(variant string, artifact string) string {
	switch artifact {
	case "wasm":
		return defaultRailgunArtifactGateway + defaultRailgunArtifactMasterCID + "/prover/snarkjs/" + variant + ".wasm.br"
	case "zkey":
		return defaultRailgunArtifactGateway + defaultRailgunArtifactMasterCID + "/circuits/" + variant + "/zkey.br"
	case "vkey":
		return defaultRailgunArtifactGateway + defaultRailgunArtifactMasterCID + "/circuits/" + variant + "/vkey.json"
	default:
		return ""
	}
}

func ensureBrotliArtifact(ctx context.Context, httpClient *http.Client, url string, path string, expectedSHA256 string) error {
	if ok, err := artifactFileMatches(path, expectedSHA256); err != nil {
		return err
	} else if ok {
		return nil
	}
	data, err := download(ctx, httpClient, url)
	if err != nil {
		return err
	}
	reader := brotli.NewReader(bytes.NewReader(data))
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if err := assertSHA256(decompressed, expectedSHA256); err != nil {
		return err
	}
	return writeFileAtomic(path, decompressed)
}

func ensureRawArtifact(ctx context.Context, httpClient *http.Client, url string, path string) error {
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	data, err := download(ctx, httpClient, url)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func artifactFileMatches(path string, expectedSHA256 string) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := assertSHA256(data, expectedSHA256); err != nil {
		return false, nil
	}
	return true, nil
}

func assertSHA256(data []byte, expected string) error {
	if expected == "" {
		return nil
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("sha256 mismatch: expected %s got %s", expected, actual)
	}
	return nil
}

func download(ctx context.Context, httpClient *http.Client, url string) ([]byte, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func relativeArtifactPath(baseDir string, path string) string {
	relative, err := filepath.Rel(baseDir, path)
	if err != nil || strings.HasPrefix(relative, "..") {
		return path
	}
	return relative
}

func shieldRequestForRailgunAddress(railgunAddress string, tokenAddress string, amount *big.Int) (railtransaction.ShieldRequest, error) {
	if amount == nil || amount.Sign() <= 0 {
		return railtransaction.ShieldRequest{}, fmt.Errorf("amount must be greater than zero")
	}
	decoded, err := railaddress.Decode(railgunAddress)
	if err != nil {
		return railtransaction.ShieldRequest{}, fmt.Errorf("target railgun address: %w", err)
	}
	masterPublicKey, err := railcrypto.NumberishToBigInt(decoded.MasterPublicKey)
	if err != nil {
		return railtransaction.ShieldRequest{}, fmt.Errorf("target master public key: %w", err)
	}
	viewingPublicKey, err := railcrypto.HexToBytes(decoded.ViewingPublicKey)
	if err != nil {
		return railtransaction.ShieldRequest{}, fmt.Errorf("target viewing public key: %w", err)
	}
	tokenData, err := railcrypto.TokenDataERC20(tokenAddress)
	if err != nil {
		return railtransaction.ShieldRequest{}, err
	}
	shieldPrivateKey, err := randomBytes(32)
	if err != nil {
		return railtransaction.ShieldRequest{}, err
	}
	noteRandom, err := randomHex(16)
	if err != nil {
		return railtransaction.ShieldRequest{}, err
	}
	randomGCMIV, err := randomHex(16)
	if err != nil {
		return railtransaction.ShieldRequest{}, err
	}
	receiverCTRIV, err := randomHex(16)
	if err != nil {
		return railtransaction.ShieldRequest{}, err
	}
	return railtransaction.CreateShieldNoteRequest(railtransaction.ShieldNoteInputs{
		MasterPublicKey:          masterPublicKey,
		Random:                   noteRandom,
		Value:                    amount,
		TokenData:                tokenData,
		ShieldPrivateKey:         shieldPrivateKey,
		ReceiverViewingPublicKey: viewingPublicKey,
		RandomGCMIV:              randomGCMIV,
		ReceiverCTRIV:            receiverCTRIV,
	})
}

func unshieldUTXOOutputs(txos []railwallet.StoredTXO) []UnshieldUTXO {
	out := make([]UnshieldUTXO, len(txos))
	for i, txo := range txos {
		value := "0"
		if txo.Value != nil {
			value = txo.Value.String()
		}
		out[i] = UnshieldUTXO{
			Nullifier: txo.Nullifier,
			TXID:      txo.TXID,
			Tree:      txo.Tree,
			Position:  txo.Position,
			ValueWei:  value,
		}
	}
	return out
}

func normalizeTokenAddress(tokenAddress string) (string, error) {
	tokenAddress = strings.TrimSpace(tokenAddress)
	if tokenAddress == "" {
		return "", fmt.Errorf("token is required")
	}
	formatted, err := railcrypto.FormatHexToByteLength(tokenAddress, 20, true)
	if err != nil {
		return "", fmt.Errorf("token address: %w", err)
	}
	return formatted, nil
}

func normalizedContractAddress(config NetworkConfig, key string) (string, error) {
	address := strings.TrimSpace(config.ContractAddresses[key])
	if address == "" {
		return "", fmt.Errorf("network config missing contractAddresses.%s", key)
	}
	formatted, err := railcrypto.FormatHexToByteLength(address, 20, true)
	if err != nil {
		return "", fmt.Errorf("network config contractAddresses.%s: %w", key, err)
	}
	return formatted, nil
}

func railgunSmartWalletV2Address(config NetworkConfig) (string, error) {
	for _, key := range []string{"railgunSmartWalletV2", "proxyContract"} {
		address := strings.TrimSpace(config.ContractAddresses[key])
		if address == "" {
			continue
		}
		formatted, err := railcrypto.FormatHexToByteLength(address, 20, true)
		if err != nil {
			return "", fmt.Errorf("network config contractAddresses.%s: %w", key, err)
		}
		return formatted, nil
	}
	if config.Chain.ID == 56 {
		return defaultBscRailgunProxyContract, nil
	}
	return "", fmt.Errorf("network config missing contractAddresses.railgunSmartWalletV2 or contractAddresses.proxyContract")
}

func newTransactionRequest(to string, data string, value *big.Int, gasLimit *big.Int) (railtransaction.RelayAdaptTransactionRequest, error) {
	address, err := railtransaction.AddressFromHex(to)
	if err != nil {
		return railtransaction.RelayAdaptTransactionRequest{}, err
	}
	if _, err := railcrypto.HexToBytes(data); err != nil {
		return railtransaction.RelayAdaptTransactionRequest{}, err
	}
	var requestGasLimit *big.Int
	if gasLimit != nil {
		requestGasLimit = cloneBigInt(gasLimit)
	}
	return railtransaction.RelayAdaptTransactionRequest{
		To:       address.Hex(),
		Data:     data,
		Value:    cloneBigInt(value),
		GasLimit: requestGasLimit,
	}, nil
}

func erc20ContractABI() (abi.ABI, error) {
	return abi.JSON(strings.NewReader(erc20ABIJSON))
}

func encodeERC20BalanceOfCalldata(owner string) (string, error) {
	contractABI, err := erc20ContractABI()
	if err != nil {
		return "", err
	}
	address, err := railtransaction.AddressFromHex(owner)
	if err != nil {
		return "", err
	}
	packed, err := contractABI.Pack("balanceOf", address)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func encodeERC20AllowanceCalldata(owner string, spender string) (string, error) {
	contractABI, err := erc20ContractABI()
	if err != nil {
		return "", err
	}
	ownerAddress, err := railtransaction.AddressFromHex(owner)
	if err != nil {
		return "", err
	}
	spenderAddress, err := railtransaction.AddressFromHex(spender)
	if err != nil {
		return "", err
	}
	packed, err := contractABI.Pack("allowance", ownerAddress, spenderAddress)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func encodeERC20ApproveCalldata(spender string, amount *big.Int) (string, error) {
	if amount == nil || amount.Sign() < 0 {
		return "", fmt.Errorf("approve amount must be non-negative")
	}
	contractABI, err := erc20ContractABI()
	if err != nil {
		return "", err
	}
	spenderAddress, err := railtransaction.AddressFromHex(spender)
	if err != nil {
		return "", err
	}
	packed, err := contractABI.Pack("approve", spenderAddress, amount)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(packed, true), nil
}

func erc20BalanceOf(ctx context.Context, provider contractCallProvider, tokenAddress string, owner string) (*big.Int, error) {
	data, err := encodeERC20BalanceOfCalldata(owner)
	if err != nil {
		return nil, err
	}
	return erc20CallUint256(ctx, provider, tokenAddress, data)
}

func erc20Allowance(ctx context.Context, provider contractCallProvider, tokenAddress string, owner string, spender string) (*big.Int, error) {
	data, err := encodeERC20AllowanceCalldata(owner, spender)
	if err != nil {
		return nil, err
	}
	return erc20CallUint256(ctx, provider, tokenAddress, data)
}

func erc20CallUint256(ctx context.Context, provider contractCallProvider, tokenAddress string, data string) (*big.Int, error) {
	if provider == nil {
		return nil, fmt.Errorf("JSON-RPC provider is required")
	}
	tokenAddress, err := normalizeTokenAddress(tokenAddress)
	if err != nil {
		return nil, err
	}
	result, err := provider.Call(ctx, railevents.TransactionCall{To: tokenAddress, Data: data}, "latest")
	if err != nil {
		return nil, err
	}
	return parseHexUint256(result)
}

func parseHexUint256(value string) (*big.Int, error) {
	raw := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if raw == "" {
		return nil, fmt.Errorf("empty uint256")
	}
	n, ok := new(big.Int).SetString(raw, 16)
	if !ok {
		return nil, fmt.Errorf("invalid uint256 %q", value)
	}
	if n.Sign() < 0 {
		return nil, fmt.Errorf("uint256 must be non-negative")
	}
	return n, nil
}

func relayAdaptCallError(logs []railevents.ContractLog) (string, bool, error) {
	receiptLogs := make([]railtransaction.RelayAdaptReceiptLog, len(logs))
	for i, log := range logs {
		receiptLogs[i] = railtransaction.RelayAdaptReceiptLog{
			Topics: append([]string(nil), log.Topics...),
			Data:   log.Data,
		}
	}
	return railtransaction.GetRelayAdaptCallError(receiptLogs)
}

func transactionReverted(submitted SubmittedTransactionWithReceipt) bool {
	return submitted.Receipt.Status != nil && *submitted.Receipt.Status == 0
}

func normalizedPollInterval(value time.Duration) time.Duration {
	if value <= 0 {
		return defaultTransactionPollInterval
	}
	return value
}

func normalizedMaxNonceRetries(value int) int {
	if value == 0 {
		return defaultMaxNonceRetries
	}
	if value < 0 {
		return 0
	}
	return value
}

func reportTransactionProgress(progress func(TransactionProgress), stage string, message string) {
	if progress != nil {
		progress(TransactionProgress{Stage: stage, Message: message})
	}
}

func uint64FromBigInt(value *big.Int) uint64 {
	if value == nil || value.Sign() <= 0 || !value.IsUint64() {
		return 0
	}
	return value.Uint64()
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(value)
}

func cloneBigIntOrNil(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func randomBytes(byteLength int) ([]byte, error) {
	out := make([]byte, byteLength)
	if _, err := cryptorand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func randomHex(byteLength int) (string, error) {
	bytes, err := randomBytes(byteLength)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
