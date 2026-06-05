package sdk

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

// RuntimeOptions 配置 Runtime 使用的 provider 和策略。
//
// Network 必填。Provider 可用于测试或自定义传输；当 Provider 为空且
// Network.RPCEndpoint 已设置时，runtime 会从网络配置创建 JSON-RPC provider。
type RuntimeOptions struct {
	Network         NetworkConfig
	Proof           *ProofConfig
	POINode         railpoi.NodeInterface
	TokenDataByHash map[string]railcrypto.TokenData
	// ProofBackend 执行 Railgun 和 POI proof。为空时，只配置 artifact 加载；
	// 直到 native prover 路径需要 rapidsnark 时才使用默认 prover。
	ProofBackend railproof.Backend
	// HTTPClient 用于远程 proof artifact，以及请求没有自带 client 时的默认
	// unshield artifact 下载。
	HTTPClient *http.Client
	Provider   railevents.CheckpointedLogProvider
	// SyncStrategy 将链上事件导入钱包状态。
	SyncStrategy SyncStrategy
}

// Runtime 是一个钱包会话的主要 SDK facade。
//
// Runtime 持有 Engine、网络配置、可选 prover、可选钱包 secret 和同步策略。内部字段
// 保持私有，调用方只能通过显式方法改变会话状态。
type Runtime struct {
	engine       *Engine
	prover       *railproof.Prover
	bundle       WalletBundle
	secret       *railwallet.WalletSecret
	network      NetworkConfig
	proof        *ProofConfig
	proofBackend railproof.Backend
	httpClient   *http.Client
	syncStrategy SyncStrategy
}

// NewRuntime 创建不含 spend/send secret material 的 runtime。
//
// 它适用于只读钱包同步、余额、历史、POI 状态，以及不需要钱包 secret 的本地 proof
// 操作。
func NewRuntime(bundle WalletBundle, options RuntimeOptions) (*Runtime, error) {
	engine, err := NewEngineFromNetworkWithProvider(bundle, options.Network, options.POINode, options.Provider)
	if err != nil {
		return nil, err
	}
	prover, err := runtimeProver(options)
	if err != nil {
		return nil, err
	}
	syncStrategy := options.SyncStrategy
	if syncStrategy == nil {
		syncStrategy = RPCSyncStrategy{}
	}
	return &Runtime{
		engine:       engine,
		prover:       prover,
		bundle:       bundle,
		network:      cloneNetworkConfig(options.Network),
		proof:        cloneProofConfigPtr(options.Proof),
		proofBackend: options.ProofBackend,
		httpClient:   options.HTTPClient,
		syncStrategy: syncStrategy,
	}, nil
}

// NewRuntimeFromSecret 创建可以执行私有交易的 runtime。
//
// 如果 bundle 和 secret 都带有 Railgun 地址，两者必须匹配。这样可以避免用一个钱包
// 的状态和另一个钱包的 spending key 生成 proof。
func NewRuntimeFromSecret(bundle WalletBundle, secret railwallet.WalletSecret, options RuntimeOptions) (*Runtime, error) {
	if err := secret.Validate(); err != nil {
		return nil, err
	}
	if err := validateRuntimeSecretBundle(bundle, secret); err != nil {
		return nil, err
	}
	runtime, err := NewRuntime(bundle, options)
	if err != nil {
		return nil, err
	}
	runtime.secret = &secret
	return runtime, nil
}

func validateRuntimeSecretBundle(bundle WalletBundle, secret railwallet.WalletSecret) error {
	bundleAddress := strings.TrimSpace(bundle.IndexedWallet.Address)
	secretAddress := strings.TrimSpace(secret.Railgun.Address)
	if bundleAddress == "" || secretAddress == "" {
		return nil
	}
	if !strings.EqualFold(bundleAddress, secretAddress) {
		return fmt.Errorf("wallet bundle address %s does not match secret address %s", bundleAddress, secretAddress)
	}
	return nil
}

// NewMemoryRuntimeFromMnemonic 从 mnemonic 派生的 Railgun 钱包创建内存只读 runtime。
func NewMemoryRuntimeFromMnemonic(options RuntimeOptions, mnemonic string, index int) (*Runtime, error) {
	manager, err := options.Network.POIManager(options.POINode)
	if err != nil {
		return nil, err
	}
	bundle, err := NewMemoryWalletFromMnemonic(mnemonic, index, manager, options.TokenDataByHash)
	if err != nil {
		return nil, err
	}
	return NewRuntime(bundle, options)
}

// NewFileRuntimeFromMnemonic 从 mnemonic 派生的 Railgun 钱包创建文件只读 runtime。
func NewFileRuntimeFromMnemonic(dir string, options RuntimeOptions, mnemonic string, index int) (*Runtime, error) {
	manager, err := options.Network.POIManager(options.POINode)
	if err != nil {
		return nil, err
	}
	bundle, err := NewFileWalletFromMnemonic(dir, mnemonic, index, manager, options.TokenDataByHash)
	if err != nil {
		return nil, err
	}
	return NewRuntime(bundle, options)
}

// NewFileRuntimeFromKeystore 加载文件 runtime，并带上私有执行所需的钱包 secret。
func NewFileRuntimeFromKeystore(dir string, keystorePath string, password string, options RuntimeOptions) (*Runtime, error) {
	manager, err := options.Network.POIManager(options.POINode)
	if err != nil {
		return nil, err
	}
	bundle, secret, err := NewFileWalletFromKeystore(dir, keystorePath, password, manager, options.TokenDataByHash)
	if err != nil {
		return nil, err
	}
	return NewRuntimeFromSecret(bundle, secret, options)
}

// NetworkConfig 返回 runtime 网络配置的防御性副本。
func (runtime *Runtime) NetworkConfig() NetworkConfig {
	if runtime == nil {
		return NetworkConfig{}
	}
	return cloneNetworkConfig(runtime.network)
}

// WalletAddress 返回该 runtime 的 indexed Railgun 地址。
func (runtime *Runtime) WalletAddress() string {
	if runtime == nil {
		return ""
	}
	if runtime.bundle.IndexedWallet.Address != "" {
		return runtime.bundle.IndexedWallet.Address
	}
	if runtime.secret != nil {
		return runtime.secret.Railgun.Address
	}
	return ""
}

// DefaultScans 返回 runtime engine active TXID version 对应的 checkpoint scan。
func (runtime *Runtime) DefaultScans(keyPrefix string) (map[string]railevents.CheckpointedScan, error) {
	if runtime == nil {
		return nil, fmt.Errorf("runtime is required")
	}
	engine, err := runtime.requireEngine()
	if err != nil {
		return nil, err
	}
	return runtime.network.defaultScans(keyPrefix, engine.activeTXIDVersions())
}

// LatestBlock 读取 provider 的最新区块号。
func (runtime *Runtime) LatestBlock(ctx context.Context) (uint64, error) {
	provider, err := runtime.blockNumberProvider()
	if err != nil {
		return 0, err
	}
	return provider.BlockNumber(ctx)
}

// NativeBalance 通过 runtime provider 读取 EVM 原生币余额。
func (runtime *Runtime) NativeBalance(ctx context.Context, address string, blockTag string) (*big.Int, error) {
	provider, err := runtime.nativeBalanceProvider()
	if err != nil {
		return nil, err
	}
	return provider.BalanceAt(ctx, address, blockTag)
}

// SyncCursor 报告整体和 per-version checkpoint 进度。
func (runtime *Runtime) SyncCursor(ctx context.Context, keyPrefix string) (SyncCursor, error) {
	engine, err := runtime.requireEngine()
	if err != nil {
		return SyncCursor{}, err
	}
	scans, err := runtime.DefaultScans(keyPrefix)
	if err != nil {
		return SyncCursor{}, err
	}
	cursor := SyncCursor{Versions: map[string]SyncVersionCursor{}}
	first := true
	for txidVersion, scan := range scans {
		nextBlock := scan.StartBlock
		if checkpoint, ok, err := engine.stores.Checkpoints.LoadCheckpoint(ctx, scan.Key); err != nil {
			return SyncCursor{}, err
		} else if ok {
			nextBlock = checkpoint.NextBlock
		}
		version := SyncVersionCursor{NextBlock: nextBlock}
		if nextBlock > 0 {
			version.SyncedBlock = nextBlock - 1
		}
		cursor.Versions[txidVersion] = version
		if first || nextBlock < cursor.NextBlock {
			cursor.NextBlock = nextBlock
		}
		if first || version.SyncedBlock < cursor.SyncedBlock {
			cursor.SyncedBlock = version.SyncedBlock
		}
		first = false
	}
	return cursor, nil
}

// RequireProver 返回已配置的 prover；若未配置，则返回原因。
func (runtime *Runtime) RequireProver() (*railproof.Prover, error) {
	if runtime == nil {
		return nil, fmt.Errorf("runtime is required")
	}
	if runtime.prover == nil {
		return nil, fmt.Errorf("prover is not configured")
	}
	return runtime.prover, nil
}

func runtimeProver(options RuntimeOptions) (*railproof.Prover, error) {
	if options.Proof == nil {
		return nil, nil
	}
	prover, err := NewProver(*options.Proof, options.ProofBackend, options.HTTPClient)
	if err != nil {
		return nil, err
	}
	return prover, nil
}

func cloneProofConfigPtr(config *ProofConfig) *ProofConfig {
	if config == nil {
		return nil
	}
	clone := *config
	return &clone
}

func cloneNetworkConfig(config NetworkConfig) NetworkConfig {
	clone := config
	if config.ContractAddresses != nil {
		clone.ContractAddresses = make(map[string]string, len(config.ContractAddresses))
		for key, value := range config.ContractAddresses {
			clone.ContractAddresses[key] = value
		}
	}
	if config.ScanAddresses != nil {
		clone.ScanAddresses = make(map[string][]string, len(config.ScanAddresses))
		for key, values := range config.ScanAddresses {
			clone.ScanAddresses[key] = cloneStringSlice(values)
		}
	}
	if config.POI.Lists != nil {
		clone.POI.Lists = append([]railpoi.List(nil), config.POI.Lists...)
	}
	if config.POI.LaunchBlocks != nil {
		clone.POI.LaunchBlocks = append([]railpoi.LaunchBlockConfig(nil), config.POI.LaunchBlocks...)
	}
	return clone
}
