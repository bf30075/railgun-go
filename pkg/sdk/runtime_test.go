package sdk

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railevents "github.com/bf30075/railgun-go/pkg/events"
	railpoi "github.com/bf30075/railgun-go/pkg/poi"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

var testRuntimeChain = railchain.Chain{Type: 0, ID: 424244}

func TestMemoryRuntimeFromMnemonicCreatesEngineAndProver(t *testing.T) {
	network := testRuntimeNetworkConfig()
	proofConfig := ProofConfig{LocalArtifactManifest: writeSDKLocalArtifactManifest(t)}
	runtime, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network: network,
		Proof:   &proofConfig,
	}, testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.engine == nil || runtime.engine.wallet == nil {
		t.Fatal("expected engine wallet")
	}
	if runtime.prover == nil {
		t.Fatal("expected prover")
	}
	if runtime.bundle.IndexedWallet.Address == "" {
		t.Fatal("expected indexed wallet address")
	}
	scans, err := runtime.DefaultScans("runtime")
	if err != nil {
		t.Fatal(err)
	}
	if scans[railcrypto.TXIDVersionV2PoseidonMerkle].Key != "runtime:"+railcrypto.TXIDVersionV2PoseidonMerkle {
		t.Fatalf("unexpected scans %+v", scans)
	}
	if _, err := runtime.RequireProver(); err != nil {
		t.Fatal(err)
	}
	proofConfig.LocalArtifactManifest = "mutated"
	if runtime.proof.LocalArtifactManifest == "mutated" {
		t.Fatal("expected runtime to clone proof config")
	}
}

func TestFileRuntimeFromKeystoreLoadsSecret(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")
	keystorePath := filepath.Join(tmpDir, "wallet.keystore.json")
	if _, _, err := CreateFileWalletFromMnemonic(stateDir, keystorePath, testMnemonic, 0, 0, "password", testKeystoreOptions(), nil, nil); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewFileRuntimeFromKeystore(stateDir, keystorePath, "password", RuntimeOptions{
		Network: testRuntimeNetworkConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.secret == nil || runtime.secret.Railgun.Address == "" {
		t.Fatalf("expected loaded secret, got %+v", runtime.secret)
	}
	if runtime.engine.indexedWallet.Address != runtime.secret.Railgun.Address {
		t.Fatalf("expected engine wallet to match secret")
	}
}

func TestRuntimeFromSecretRejectsMismatchedWalletBundle(t *testing.T) {
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := railwallet.WalletSecretFromMnemonic(testMnemonic, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewRuntimeFromSecret(bundle, secret, RuntimeOptions{
		Network: testRuntimeNetworkConfig(),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match secret address") {
		t.Fatalf("expected mismatched bundle/secret error, got %v", err)
	}
}

func TestRuntimeWithoutProofConfigHasNoProver(t *testing.T) {
	runtime, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network: testRuntimeNetworkConfig(),
	}, testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.prover != nil {
		t.Fatal("expected no prover")
	}
	if _, err := runtime.RequireProver(); err == nil || !strings.Contains(err.Error(), "prover is not configured") {
		t.Fatalf("expected missing prover error, got %v", err)
	}
}

func TestRuntimeNetworkConfigReturnsDefensiveCopy(t *testing.T) {
	network := testRuntimeNetworkConfig()
	network.ContractAddresses = map[string]string{"wrappedBaseToken": "0x1111111111111111111111111111111111111111"}
	network.POI.Lists = []railpoi.List{{Key: "active", Type: railpoi.ListTypeActive, Name: "active"}}
	network.POI.LaunchBlocks = []railpoi.LaunchBlockConfig{{Chain: testRuntimeChain, BlockNumber: 10}}
	runtime, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network: network,
	}, testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}

	clone := runtime.NetworkConfig()
	clone.ContractAddresses["wrappedBaseToken"] = "0x2222222222222222222222222222222222222222"
	clone.ScanAddresses[defaultScanAddressKey][0] = "0x3333333333333333333333333333333333333333"
	clone.POI.Lists[0].Key = "mutated"
	clone.POI.LaunchBlocks[0].BlockNumber = 99

	again := runtime.NetworkConfig()
	if again.ContractAddresses["wrappedBaseToken"] != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("contract address clone leaked mutation: %+v", again.ContractAddresses)
	}
	if again.ScanAddresses[defaultScanAddressKey][0] != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("scan address clone leaked mutation: %+v", again.ScanAddresses)
	}
	if again.POI.Lists[0].Key != "active" {
		t.Fatalf("POI list clone leaked mutation: %+v", again.POI.Lists)
	}
	if again.POI.LaunchBlocks[0].BlockNumber != 10 {
		t.Fatalf("POI launch block clone leaked mutation: %+v", again.POI.LaunchBlocks)
	}
}

func TestRuntimeSyncCursorReportsPerVersionAndOverallMinimum(t *testing.T) {
	ctx := context.Background()
	network := testRuntimeNetworkConfig()
	network.Chain = railchain.Chain{Type: 0, ID: 424245}
	network.SupportsV3 = true
	network.DefaultStartBlock = 10
	runtime, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network: network,
	}, testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	scans, err := runtime.DefaultScans("cursor")
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := runtime.engine.stores.Checkpoints
	if err := checkpoints.SaveCheckpoint(ctx, scans[railcrypto.TXIDVersionV2PoseidonMerkle].Key, railevents.ScanCheckpoint{NextBlock: 20}); err != nil {
		t.Fatal(err)
	}
	if err := checkpoints.SaveCheckpoint(ctx, scans[railcrypto.TXIDVersionV3PoseidonMerkle].Key, railevents.ScanCheckpoint{NextBlock: 50}); err != nil {
		t.Fatal(err)
	}

	cursor, err := runtime.SyncCursor(ctx, "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if cursor.NextBlock != 20 || cursor.SyncedBlock != 19 {
		t.Fatalf("expected overall cursor at V2 lagging block, got %+v", cursor)
	}
	v2 := cursor.Versions[railcrypto.TXIDVersionV2PoseidonMerkle]
	v3 := cursor.Versions[railcrypto.TXIDVersionV3PoseidonMerkle]
	if v2.NextBlock != 20 || v2.SyncedBlock != 19 {
		t.Fatalf("unexpected V2 cursor %+v", v2)
	}
	if v3.NextBlock != 50 || v3.SyncedBlock != 49 {
		t.Fatalf("unexpected V3 cursor %+v", v3)
	}
}

func TestRuntimeDefaultScansUsesEngineTXIDVersions(t *testing.T) {
	network := testRuntimeNetworkConfig()
	network.SupportsV3 = true
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Bundle:       bundle,
		Chain:        network.Chain,
		TXIDVersions: []string{railcrypto.TXIDVersionV2PoseidonMerkle},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		engine:  engine,
		network: network,
	}

	scans, err := runtime.DefaultScans("runtime-versions")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scans[railcrypto.TXIDVersionV2PoseidonMerkle]; !ok {
		t.Fatalf("expected V2 scan, got %+v", scans)
	}
	if _, ok := scans[railcrypto.TXIDVersionV3PoseidonMerkle]; ok {
		t.Fatalf("expected Runtime.DefaultScans to follow engine versions, got %+v", scans)
	}
}

func TestRuntimeRejectsInvalidProofConfig(t *testing.T) {
	proofConfig := ProofConfig{ArtifactSource: ArtifactSourceLocal}
	_, err := NewMemoryRuntimeFromMnemonic(RuntimeOptions{
		Network: testRuntimeNetworkConfig(),
		Proof:   &proofConfig,
	}, testMnemonic, 0)
	if err == nil || !strings.Contains(err.Error(), "localArtifactManifest") {
		t.Fatalf("expected proof config error, got %v", err)
	}
}

func testRuntimeNetworkConfig() NetworkConfig {
	return NetworkConfig{
		Chain:       testRuntimeChain,
		RPCEndpoint: "http://127.0.0.1:8545",
		ScanAddresses: map[string][]string{
			defaultScanAddressKey: {"0x1111111111111111111111111111111111111111"},
		},
	}
}
