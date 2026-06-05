package sdk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
)

func TestNetworkConfigCreatesEngineAndDefaultScans(t *testing.T) {
	raw := []byte(`{
		"name": "local-testnet",
		"chain": {"type": 0, "id": 424242},
		"rpcEndpoint": "http://127.0.0.1:8545",
		"supportsV3": true,
		"contractAddresses": {
			"railgunLogic": "0x3333333333333333333333333333333333333333"
		},
		"scanAddresses": {
			"V2_PoseidonMerkle": ["0x1111111111111111111111111111111111111111"],
			"default": ["0x2222222222222222222222222222222222222222"]
		},
		"defaultStartBlock": 100,
		"defaultChunkSize": 250,
		"defaultConfirmations": 5,
		"poi": {
			"lists": [
				{"key": "active", "type": "Active", "name": "active", "description": "Active list"}
			],
			"launchBlocks": [
				{"chain": {"type": 0, "id": 424242}, "blockNumber": 99}
			]
		}
	}`)
	config, err := ParseNetworkConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	scans, err := config.DefaultScans("wallet")
	if err != nil {
		t.Fatal(err)
	}
	v2 := scans[railcrypto.TXIDVersionV2PoseidonMerkle]
	if v2.Key != "wallet:"+railcrypto.TXIDVersionV2PoseidonMerkle || v2.StartBlock != 100 || v2.ChunkSize != 250 || v2.Confirmations != 5 {
		t.Fatalf("unexpected v2 scan %+v", v2)
	}
	if len(v2.Addresses) != 1 || v2.Addresses[0] != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("unexpected v2 addresses %+v", v2.Addresses)
	}
	v3 := scans[railcrypto.TXIDVersionV3PoseidonMerkle]
	if v3.Key != "wallet:"+railcrypto.TXIDVersionV3PoseidonMerkle {
		t.Fatalf("unexpected v3 scan %+v", v3)
	}
	if len(v3.Addresses) != 1 || v3.Addresses[0] != "0x2222222222222222222222222222222222222222" {
		t.Fatalf("unexpected v3 fallback addresses %+v", v3.Addresses)
	}

	engine, bundle, err := NewMemoryEngineFromMnemonic(config, testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if engine.chain != config.Chain || bundle.Wallet == nil {
		t.Fatalf("unexpected engine %+v bundle %+v", engine, bundle)
	}
	provider, ok := engine.provider.(*railevents.JSONRPCLogProvider)
	if !ok || provider.Endpoint != "http://127.0.0.1:8545" {
		t.Fatalf("unexpected provider %+v", engine.provider)
	}
	if keys := engine.wallet.POIManager.GetActiveListKeys(); len(keys) != 1 || keys[0] != "active" {
		t.Fatalf("unexpected active list keys %+v", keys)
	}
	if launchBlock, ok := engine.wallet.POIManager.LaunchBlock(config.Chain); !ok || launchBlock != 99 {
		t.Fatalf("unexpected launch block %d ok %v", launchBlock, ok)
	}
}

func TestNetworkConfigDefaultScansDoesNotApplyGlobalChainState(t *testing.T) {
	chain := railchain.Chain{Type: 0, ID: 77770001}
	if railchain.SupportsV3(chain) {
		t.Fatalf("test chain unexpectedly supports V3 before config apply")
	}
	config := NetworkConfig{
		Chain:      chain,
		SupportsV3: true,
		ScanAddresses: map[string][]string{
			defaultScanAddressKey: {"0x1111111111111111111111111111111111111111"},
		},
	}

	scans, err := config.DefaultScans("pure")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scans[railcrypto.TXIDVersionV3PoseidonMerkle]; !ok {
		t.Fatalf("expected DefaultScans to include V3 from config, got %+v", scans)
	}
	if railchain.SupportsV3(chain) {
		t.Fatalf("DefaultScans should not mutate global chain V3 support")
	}
	if err := config.Apply(); err != nil {
		t.Fatal(err)
	}
	if !railchain.SupportsV3(chain) {
		t.Fatalf("Apply should register global chain V3 support")
	}
}

func TestNetworkConfigTXIDVersionsAreRuntimeScoped(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 77770003}
	v3Config := NetworkConfig{Chain: chain, SupportsV3: true}
	v3Runtime, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network: v3Config,
	}, testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !stringSliceContains(v3Runtime.engine.activeTXIDVersions(), railcrypto.TXIDVersionV3PoseidonMerkle) {
		t.Fatalf("expected V3 runtime versions, got %+v", v3Runtime.engine.activeTXIDVersions())
	}
	if !railchain.SupportsV3(chain) {
		t.Fatalf("expected V3 config to register global chain support")
	}

	v2Config := NetworkConfig{Chain: chain}
	v2Runtime, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network:  v2Config,
		Provider: &sdkStubProvider{latest: 12},
	}, testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stringSliceContains(v2Runtime.engine.activeTXIDVersions(), railcrypto.TXIDVersionV3PoseidonMerkle) {
		t.Fatalf("expected V2-only runtime versions, got %+v", v2Runtime.engine.activeTXIDVersions())
	}
	scans, err := v2Runtime.DefaultScans("isolated")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scans[railcrypto.TXIDVersionV3PoseidonMerkle]; ok {
		t.Fatalf("expected V2-only scans despite global support, got %+v", scans)
	}
	results, err := v2Runtime.Sync(ctx, "isolated")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := results[railcrypto.TXIDVersionV3PoseidonMerkle]; ok {
		t.Fatalf("expected V2-only sync results, got %+v", results)
	}
}

func TestLoadNetworkConfigAndKeystoreEngine(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "network.json")
	configJSON := `{
		"chain": {"type": 0, "id": 424243},
		"rpcEndpoint": "http://127.0.0.1:9545",
		"supportsV3": true,
		"scanAddresses": {"default": ["0x1111111111111111111111111111111111111111"]}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadNetworkConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(tmpDir, "state")
	keystorePath := filepath.Join(tmpDir, "wallet.keystore.json")
	if _, _, err := CreateFileWalletFromMnemonic(stateDir, keystorePath, testMnemonic, 0, 0, "password", testKeystoreOptions(), railpoi.NewManager(nil, nil), nil); err != nil {
		t.Fatal(err)
	}
	engine, bundle, secret, err := NewFileEngineFromKeystore(stateDir, keystorePath, "password", config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if engine.indexedWallet.Address == "" || bundle.IndexedWallet.Address != secret.Railgun.Address {
		t.Fatalf("unexpected loaded engine bundle %+v secret %+v", bundle, secret)
	}
}

func TestNetworkConfigRejectsInvalidInputs(t *testing.T) {
	_, err := ParseNetworkConfig([]byte(`{
		"chain": {"type": 0, "id": 1},
		"contractAddresses": {"railgunLogic": "not-an-address"}
	}`))
	if err == nil || !strings.Contains(err.Error(), "contractAddresses[railgunLogic]") {
		t.Fatalf("expected contract address error, got %v", err)
	}
	_, err = ParseNetworkConfig([]byte(`{
		"chain": {"type": 0, "id": 1},
		"scanAddresses": {"": ["0x1111111111111111111111111111111111111111"]}
	}`))
	if err == nil || !strings.Contains(err.Error(), "scan address txid version") {
		t.Fatalf("expected scan key error, got %v", err)
	}
	_, err = (NetworkConfig{Chain: railchain.Chain{Type: 0, ID: 1}}).JSONRPCProvider()
	if err == nil || !strings.Contains(err.Error(), "rpc endpoint") {
		t.Fatalf("expected rpc endpoint error, got %v", err)
	}
}
