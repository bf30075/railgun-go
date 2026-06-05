package sdk

import (
	"fmt"
	"os"
	"path/filepath"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

const (
	stateFileName          = "wallet-state.json"
	checkpointsFileName    = "checkpoints.json"
	txidsFileName          = "txids.json"
	txidMerkleTreeFileName = "txid-merkle-tree.json"
	utxoMerkleTreePebble   = "utxo-merkle-tree.pebble"
	spentPOIEventsFileName = "spent-poi-events.json"
	walletDetailsFileName  = "wallet-details.json"
)

// StoreSet 组合一个钱包会话需要的持久化后端。
//
// 测试和临时运行使用 NewMemoryStores；需要持久化钱包状态、checkpoint、
// TXID store 和 UTXO Merkle 数据时使用 NewFileStores。
type StoreSet struct {
	State          railwallet.StateStore
	Checkpoints    railevents.CheckpointStore
	TXIDStore      railtxid.TransactionStore
	TXIDMerkleTree railtxid.MerkleTreeStore
	UTXOMerkleTree railutxotree.Store
	SpentPOIEvents railwallet.SpentPOIEventStore
	Details        railwallet.WalletDetailsStore
}

// WalletBundle 将钱包状态和扫描身份放在一起。
//
// 它刻意不包含 spend/send secret。RuntimeFromSecret 会在之后绑定这些 secret，
// 并验证 secret 属于同一个 indexed Railgun wallet。
type WalletBundle struct {
	Wallet        *railwallet.Wallet
	Stores        StoreSet
	IndexedWallet railwallet.IndexedWallet
}

// NewMemoryStores 返回用于测试和临时 runtime 的内存 store。
func NewMemoryStores() StoreSet {
	return StoreSet{
		State:          railwallet.NewMemoryStateStore(),
		Checkpoints:    railevents.NewMemoryCheckpointStore(),
		TXIDStore:      railtxid.NewMemoryTransactionStore(),
		TXIDMerkleTree: railtxid.NewMemoryMerkleTreeStore(),
		UTXOMerkleTree: railutxotree.NewMemoryStore(),
		SpentPOIEvents: railwallet.NewMemorySpentPOIEventStore(),
		Details:        railwallet.NewMemoryWalletDetailsStore(),
	}
}

// NewFileStores 返回以 dir 为根目录的文件 store。
func NewFileStores(dir string) (StoreSet, error) {
	if dir == "" {
		return StoreSet{}, fmt.Errorf("store directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return StoreSet{}, err
	}
	return StoreSet{
		State:          railwallet.NewFileStateStore(filepath.Join(dir, stateFileName)),
		Checkpoints:    railevents.FileCheckpointStore{Path: filepath.Join(dir, checkpointsFileName)},
		TXIDStore:      railtxid.NewFileTransactionStore(filepath.Join(dir, txidsFileName)),
		TXIDMerkleTree: railtxid.NewFileMerkleTreeStore(filepath.Join(dir, txidMerkleTreeFileName)),
		UTXOMerkleTree: railutxotree.NewPebbleStore(filepath.Join(dir, utxoMerkleTreePebble)),
		SpentPOIEvents: railwallet.NewFileSpentPOIEventStore(filepath.Join(dir, spentPOIEventsFileName)),
		Details:        railwallet.NewFileWalletDetailsStore(filepath.Join(dir, walletDetailsFileName)),
	}, nil
}

// NewWallet 使用显式 store、scan key 和 POI manager 创建钱包。
func NewWallet(stores StoreSet, keys railwallet.ScanKeys, poiManager *railpoi.Manager) (*railwallet.Wallet, error) {
	if err := stores.validate(); err != nil {
		return nil, err
	}
	if poiManager == nil {
		poiManager = railpoi.NewManager(nil, nil)
	}
	return railwallet.NewWalletWithAllStoresAndDetails(
		stores.State,
		stores.Checkpoints,
		keys,
		poiManager,
		stores.TXIDStore,
		stores.TXIDMerkleTree,
		stores.UTXOMerkleTree,
		stores.SpentPOIEvents,
		stores.Details,
	)
}

// NewWalletFromMnemonic 从 mnemonic 派生 scan key 并创建钱包 bundle。
func NewWalletFromMnemonic(stores StoreSet, mnemonic string, index int, poiManager *railpoi.Manager, tokenDataByHash map[string]railcrypto.TokenData) (WalletBundle, error) {
	indexedWallet, keys, err := ScanKeysFromMnemonic(mnemonic, index, tokenDataByHash)
	if err != nil {
		return WalletBundle{}, err
	}
	wallet, err := NewWallet(stores, keys, poiManager)
	if err != nil {
		return WalletBundle{}, err
	}
	return WalletBundle{
		Wallet:        wallet,
		Stores:        stores,
		IndexedWallet: indexedWallet,
	}, nil
}

// NewMemoryWalletFromMnemonic 从 mnemonic 创建内存钱包 bundle。
func NewMemoryWalletFromMnemonic(mnemonic string, index int, poiManager *railpoi.Manager, tokenDataByHash map[string]railcrypto.TokenData) (WalletBundle, error) {
	return NewWalletFromMnemonic(NewMemoryStores(), mnemonic, index, poiManager, tokenDataByHash)
}

// NewFileWalletFromMnemonic 从 mnemonic 创建文件钱包 bundle。
func NewFileWalletFromMnemonic(dir string, mnemonic string, index int, poiManager *railpoi.Manager, tokenDataByHash map[string]railcrypto.TokenData) (WalletBundle, error) {
	stores, err := NewFileStores(dir)
	if err != nil {
		return WalletBundle{}, err
	}
	return NewWalletFromMnemonic(stores, mnemonic, index, poiManager, tokenDataByHash)
}

// NewWalletFromSecret 使用已加载的钱包 secret 创建钱包 bundle。
func NewWalletFromSecret(stores StoreSet, secret railwallet.WalletSecret, poiManager *railpoi.Manager, tokenDataByHash map[string]railcrypto.TokenData) (WalletBundle, error) {
	if err := secret.Validate(); err != nil {
		return WalletBundle{}, err
	}
	if secret.Mnemonic == "" {
		return WalletBundle{}, fmt.Errorf("wallet secret mnemonic is required")
	}
	return NewWalletFromMnemonic(stores, secret.Mnemonic, secret.Index, poiManager, tokenDataByHash)
}

// NewFileWalletFromKeystore 加载钱包 secret 并创建文件钱包 bundle。
func NewFileWalletFromKeystore(dir string, keystorePath string, password string, poiManager *railpoi.Manager, tokenDataByHash map[string]railcrypto.TokenData) (WalletBundle, railwallet.WalletSecret, error) {
	secret, err := railwallet.LoadWalletSecret(keystorePath, password)
	if err != nil {
		return WalletBundle{}, railwallet.WalletSecret{}, err
	}
	stores, err := NewFileStores(dir)
	if err != nil {
		return WalletBundle{}, railwallet.WalletSecret{}, err
	}
	bundle, err := NewWalletFromSecret(stores, secret, poiManager, tokenDataByHash)
	if err != nil {
		return WalletBundle{}, railwallet.WalletSecret{}, err
	}
	return bundle, secret, nil
}

// CreateFileWalletFromMnemonic 保存钱包 secret keystore 并创建文件钱包 bundle。
func CreateFileWalletFromMnemonic(dir string, keystorePath string, mnemonic string, railgunIndex int, evmIndex uint32, password string, options railwallet.KeystoreOptions, poiManager *railpoi.Manager, tokenDataByHash map[string]railcrypto.TokenData) (WalletBundle, railwallet.WalletSecret, error) {
	secret, err := railwallet.WalletSecretFromMnemonic(mnemonic, railgunIndex, evmIndex)
	if err != nil {
		return WalletBundle{}, railwallet.WalletSecret{}, err
	}
	if err := railwallet.SaveWalletSecret(keystorePath, secret, password, options); err != nil {
		return WalletBundle{}, railwallet.WalletSecret{}, err
	}
	bundle, err := NewFileWalletFromMnemonic(dir, mnemonic, railgunIndex, poiManager, tokenDataByHash)
	if err != nil {
		return WalletBundle{}, railwallet.WalletSecret{}, err
	}
	return bundle, secret, nil
}

// ScanKeysFromMnemonic 派生引擎使用的 indexed Railgun wallet 和 scan key。
func ScanKeysFromMnemonic(mnemonic string, index int, tokenDataByHash map[string]railcrypto.TokenData) (railwallet.IndexedWallet, railwallet.ScanKeys, error) {
	if !railwallet.ValidateMnemonic(mnemonic) {
		return railwallet.IndexedWallet{}, railwallet.ScanKeys{}, fmt.Errorf("invalid mnemonic")
	}
	if index < 0 {
		return railwallet.IndexedWallet{}, railwallet.ScanKeys{}, fmt.Errorf("wallet index must be non-negative")
	}
	indexedWallet, err := railwallet.DeriveIndexedWallet(mnemonic, index)
	if err != nil {
		return railwallet.IndexedWallet{}, railwallet.ScanKeys{}, err
	}
	viewingPath := fmt.Sprintf("m/420'/1984'/0'/0'/%d'", index)
	viewingNode, err := railwallet.DeriveFromMnemonic(mnemonic, viewingPath)
	if err != nil {
		return railwallet.IndexedWallet{}, railwallet.ScanKeys{}, err
	}
	masterPublicKey, err := railcrypto.NumberishToBigInt(indexedWallet.MasterPublicKey)
	if err != nil {
		return railwallet.IndexedWallet{}, railwallet.ScanKeys{}, fmt.Errorf("master public key: %w", err)
	}
	viewingPrivateKey, err := railcrypto.HexToBytes(viewingNode.Viewing.PrivateKey)
	if err != nil {
		return railwallet.IndexedWallet{}, railwallet.ScanKeys{}, fmt.Errorf("viewing private key: %w", err)
	}
	viewingPublicKey, err := railcrypto.HexToBytes(indexedWallet.ViewingPublicKey)
	if err != nil {
		return railwallet.IndexedWallet{}, railwallet.ScanKeys{}, fmt.Errorf("viewing public key: %w", err)
	}
	nullifyingKey, err := railcrypto.NumberishToBigInt(indexedWallet.NullifyingKey)
	if err != nil {
		return railwallet.IndexedWallet{}, railwallet.ScanKeys{}, fmt.Errorf("nullifying key: %w", err)
	}
	return indexedWallet, railwallet.ScanKeys{
		MasterPublicKey:   masterPublicKey,
		ViewingPrivateKey: viewingPrivateKey,
		ViewingPublicKey:  viewingPublicKey,
		NullifyingKey:     nullifyingKey,
		TokenDataByHash:   cloneTokenDataByHash(tokenDataByHash),
	}, nil
}

func (stores StoreSet) validate() error {
	if stores.State == nil {
		return fmt.Errorf("state store is required")
	}
	if stores.Checkpoints == nil {
		return fmt.Errorf("checkpoint store is required")
	}
	if stores.TXIDStore == nil {
		return fmt.Errorf("txid store is required")
	}
	if stores.TXIDMerkleTree == nil {
		return fmt.Errorf("txid merkle tree store is required")
	}
	if stores.UTXOMerkleTree == nil {
		return fmt.Errorf("utxo merkle tree store is required")
	}
	if stores.SpentPOIEvents == nil {
		return fmt.Errorf("spent poi event store is required")
	}
	if stores.Details == nil {
		return fmt.Errorf("wallet details store is required")
	}
	return nil
}

func cloneTokenDataByHash(tokenDataByHash map[string]railcrypto.TokenData) map[string]railcrypto.TokenData {
	if tokenDataByHash == nil {
		return nil
	}
	out := make(map[string]railcrypto.TokenData, len(tokenDataByHash))
	for hash, tokenData := range tokenDataByHash {
		out[hash] = tokenData
	}
	return out
}
