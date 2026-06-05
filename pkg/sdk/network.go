package sdk

import (
	"encoding/json"
	"fmt"
	"os"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

const defaultScanAddressKey = "default"

// NetworkConfig 描述 SDK engine 需要的链、provider、扫描、POI 和合约配置。
type NetworkConfig struct {
	// Name 是可选的可读网络名称。
	Name string `json:"name,omitempty"`
	// Chain 标识 EVM 链。
	Chain railchain.Chain `json:"chain"`
	// RPCEndpoint 在没有注入 provider 时使用。
	RPCEndpoint string `json:"rpcEndpoint,omitempty"`
	// SupportsV3 为这条链启用 V3 TXID 扫描。
	SupportsV3 bool `json:"supportsV3,omitempty"`
	// ContractAddresses 保存 RelayAdapt 等执行合约地址。
	ContractAddresses map[string]string `json:"contractAddresses,omitempty"`
	// ScanAddresses 将 TXID version 映射到 Railgun 事件合约地址。
	ScanAddresses map[string][]string `json:"scanAddresses,omitempty"`
	// DefaultStartBlock 是 checkpoint 扫描的默认起始区块。
	DefaultStartBlock uint64 `json:"defaultStartBlock,omitempty"`
	// DefaultChunkSize 限制每次 provider 日志扫描的区块范围。
	DefaultChunkSize uint64 `json:"defaultChunkSize,omitempty"`
	// DefaultConfirmations 让扫描落后于 provider 最新区块。
	DefaultConfirmations uint64 `json:"defaultConfirmations,omitempty"`
	// POI 配置钱包余额策略使用的 POI list 和 launch block。
	POI railpoi.ManagerConfig `json:"poi,omitempty"`
}

// ParseNetworkConfig 解码并验证 JSON 网络配置。
func ParseNetworkConfig(data []byte) (NetworkConfig, error) {
	var config NetworkConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return NetworkConfig{}, err
	}
	if err := config.Validate(); err != nil {
		return NetworkConfig{}, err
	}
	return config, nil
}

// LoadNetworkConfig 从磁盘读取并解析 JSON 网络配置。
func LoadNetworkConfig(path string) (NetworkConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return NetworkConfig{}, err
	}
	return ParseNetworkConfig(data)
}

// Validate 检查链身份、配置地址和 POI launch block。
func (config NetworkConfig) Validate() error {
	if _, err := railchain.FullNetworkIDHex(config.Chain); err != nil {
		return err
	}
	for name, address := range config.ContractAddresses {
		if _, err := normalizeEVMAddress(address); err != nil {
			return fmt.Errorf("contractAddresses[%s]: %w", name, err)
		}
	}
	for txidVersion, addresses := range config.ScanAddresses {
		if txidVersion == "" {
			return fmt.Errorf("scan address txid version is required")
		}
		for i, address := range addresses {
			if _, err := normalizeEVMAddress(address); err != nil {
				return fmt.Errorf("scanAddresses[%s][%d]: %w", txidVersion, i, err)
			}
		}
	}
	for i, launchBlock := range config.POI.LaunchBlocks {
		if _, err := railchain.FullNetworkIDHex(launchBlock.Chain); err != nil {
			return fmt.Errorf("poi.launchBlocks[%d]: %w", i, err)
		}
	}
	return nil
}

// Apply 验证配置并注册链级 SDK 能力。
func (config NetworkConfig) Apply() error {
	if err := config.Validate(); err != nil {
		return err
	}
	if config.SupportsV3 {
		railchain.AddSupportsV3(config.Chain)
	}
	return nil
}

// JSONRPCProvider 为该网络构造默认 JSON-RPC provider。
func (config NetworkConfig) JSONRPCProvider() (railevents.CheckpointedLogProvider, error) {
	if config.RPCEndpoint == "" {
		return nil, fmt.Errorf("rpc endpoint is required")
	}
	return railevents.NewJSONRPCLogProvider(config.RPCEndpoint), nil
}

// POIManager 从网络 POI 配置构造 POI manager。
func (config NetworkConfig) POIManager(node railpoi.NodeInterface) (*railpoi.Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return railpoi.NewManagerFromConfig(config.POI, node), nil
}

// DefaultScans 验证配置并创建 checkpoint scan，不注册全局链能力。
func (config NetworkConfig) DefaultScans(keyPrefix string) (map[string]railevents.CheckpointedScan, error) {
	return config.defaultScans(keyPrefix, config.activeTXIDVersions())
}

func (config NetworkConfig) defaultScans(keyPrefix string, txidVersions []string) (map[string]railevents.CheckpointedScan, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	scans := map[string]railevents.CheckpointedScan{}
	for _, txidVersion := range txidVersions {
		scans[txidVersion] = railevents.CheckpointedScan{
			Key:           scanCheckpointKey(keyPrefix, txidVersion),
			Addresses:     config.scanAddresses(txidVersion),
			StartBlock:    config.DefaultStartBlock,
			ChunkSize:     config.DefaultChunkSize,
			Confirmations: config.DefaultConfirmations,
		}
	}
	return scans, nil
}

// NewEngineFromNetwork 创建 engine；RPCEndpoint 已设置时使用配置里的 JSON-RPC
// provider 配置。
func NewEngineFromNetwork(bundle WalletBundle, config NetworkConfig, node railpoi.NodeInterface) (*Engine, error) {
	return NewEngineFromNetworkWithProvider(bundle, config, node, nil)
}

// NewEngineFromNetworkWithProvider 创建 engine；如果传入 provider，则使用该 provider。
func NewEngineFromNetworkWithProvider(bundle WalletBundle, config NetworkConfig, node railpoi.NodeInterface, provider railevents.CheckpointedLogProvider) (*Engine, error) {
	if err := config.Apply(); err != nil {
		return nil, err
	}
	if provider == nil && config.RPCEndpoint != "" {
		var err error
		provider, err = config.JSONRPCProvider()
		if err != nil {
			return nil, err
		}
	}
	if bundle.Wallet == nil {
		return nil, fmt.Errorf("wallet is required")
	}
	manager, err := config.POIManager(node)
	if err != nil {
		return nil, err
	}
	bundle.Wallet.POIManager = manager
	return NewEngine(EngineConfig{
		Bundle:       bundle,
		Chain:        config.Chain,
		Provider:     provider,
		TXIDVersions: config.activeTXIDVersions(),
	})
}

// NewMemoryEngineFromMnemonic 从 mnemonic 创建内存 engine。
func NewMemoryEngineFromMnemonic(config NetworkConfig, mnemonic string, index int, node railpoi.NodeInterface, tokenDataByHash map[string]railcrypto.TokenData) (*Engine, WalletBundle, error) {
	manager, err := config.POIManager(node)
	if err != nil {
		return nil, WalletBundle{}, err
	}
	bundle, err := NewMemoryWalletFromMnemonic(mnemonic, index, manager, tokenDataByHash)
	if err != nil {
		return nil, WalletBundle{}, err
	}
	engine, err := NewEngineFromNetwork(bundle, config, node)
	if err != nil {
		return nil, WalletBundle{}, err
	}
	return engine, bundle, nil
}

// NewFileEngineFromMnemonic 从 mnemonic 创建文件 engine。
func NewFileEngineFromMnemonic(dir string, config NetworkConfig, mnemonic string, index int, node railpoi.NodeInterface, tokenDataByHash map[string]railcrypto.TokenData) (*Engine, WalletBundle, error) {
	manager, err := config.POIManager(node)
	if err != nil {
		return nil, WalletBundle{}, err
	}
	bundle, err := NewFileWalletFromMnemonic(dir, mnemonic, index, manager, tokenDataByHash)
	if err != nil {
		return nil, WalletBundle{}, err
	}
	engine, err := NewEngineFromNetwork(bundle, config, node)
	if err != nil {
		return nil, WalletBundle{}, err
	}
	return engine, bundle, nil
}

// NewFileEngineFromKeystore 从 keystore 加载文件 engine 和钱包 secret。
func NewFileEngineFromKeystore(dir string, keystorePath string, password string, config NetworkConfig, node railpoi.NodeInterface, tokenDataByHash map[string]railcrypto.TokenData) (*Engine, WalletBundle, railwallet.WalletSecret, error) {
	manager, err := config.POIManager(node)
	if err != nil {
		return nil, WalletBundle{}, railwallet.WalletSecret{}, err
	}
	bundle, secret, err := NewFileWalletFromKeystore(dir, keystorePath, password, manager, tokenDataByHash)
	if err != nil {
		return nil, WalletBundle{}, railwallet.WalletSecret{}, err
	}
	engine, err := NewEngineFromNetwork(bundle, config, node)
	if err != nil {
		return nil, WalletBundle{}, railwallet.WalletSecret{}, err
	}
	return engine, bundle, secret, nil
}

func (config NetworkConfig) activeTXIDVersions() []string {
	versions := []string{railcrypto.TXIDVersionV2PoseidonMerkle}
	if config.SupportsV3 {
		versions = append(versions, railcrypto.TXIDVersionV3PoseidonMerkle)
	}
	return versions
}

func (config NetworkConfig) scanAddresses(txidVersion string) []string {
	addresses := config.ScanAddresses[txidVersion]
	if len(addresses) == 0 {
		addresses = config.ScanAddresses[defaultScanAddressKey]
	}
	return cloneStringSlice(addresses)
}

func scanCheckpointKey(prefix string, txidVersion string) string {
	if prefix == "" {
		return txidVersion
	}
	return prefix + ":" + txidVersion
}

func normalizeEVMAddress(address string) (string, error) {
	return railcrypto.FormatHexToByteLength(address, 20, true)
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}
