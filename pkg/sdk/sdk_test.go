package sdk

import (
	"context"
	"math/big"
	"path/filepath"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railtxid "github.com/bf30075/railgun-go/pkg/txid"
	railutxotree "github.com/bf30075/railgun-go/pkg/utxotree"
	railwallet "github.com/bf30075/railgun-go/pkg/wallet"
)

const testMnemonic = "test test test test test test test test test test test junk"

func TestNewMemoryWalletFromMnemonicBuildsUsableWallet(t *testing.T) {
	ctx := context.Background()
	bundle, err := NewMemoryWalletFromMnemonic(testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Wallet == nil {
		t.Fatal("expected wallet")
	}
	if bundle.IndexedWallet.Address == "" {
		t.Fatal("expected indexed wallet address")
	}
	if bundle.Wallet.TXIDStore == nil || bundle.Wallet.TXIDMerkleTree == nil || bundle.Wallet.UTXOMerkleTree == nil {
		t.Fatal("expected wallet to include txid and utxo stores")
	}

	txo := testStoredTXO(t, "memory-nullifier")
	if err := bundle.Wallet.State.UpsertTXO(ctx, txo); err != nil {
		t.Fatal(err)
	}
	txos, err := bundle.Wallet.State.ListTXOs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(txos) != 1 || txos[0].Nullifier != "memory-nullifier" {
		t.Fatalf("unexpected txos %+v", txos)
	}
}

func TestNewFileWalletFromMnemonicPersistsStores(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bundle, err := NewFileWalletFromMnemonic(dir, testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	txo := testStoredTXO(t, "file-nullifier")
	if err := bundle.Wallet.State.UpsertTXO(ctx, txo); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Wallet.UTXOMerkleTree.UpsertLeaf(ctx, railutxotree.Leaf{
		Tree:        txo.Tree,
		Index:       txo.Position,
		Hash:        txo.CommitmentHash,
		BlockNumber: txo.BlockNumber,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Wallet.TXIDStore.UpsertTransaction(ctx, railtxid.Transaction{
		Version:     "V3",
		RailgunTxid: "railgun-txid",
		Txid:        "0xtxid",
		BlockNumber: txo.BlockNumber,
	}); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileWalletFromMnemonic(dir, testMnemonic, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	txos, err := reopened.Wallet.State.ListTXOs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(txos) != 1 || txos[0].Nullifier != "file-nullifier" || txos[0].Value.String() != "7" {
		t.Fatalf("unexpected persisted txos %+v", txos)
	}
	if _, ok, err := reopened.Wallet.UTXOMerkleTree.GetLeaf(ctx, txo.Tree, txo.Position); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected persisted utxo tree leaf")
	}
	if _, ok, err := reopened.Wallet.TXIDStore.GetByRailgunTxid(ctx, "railgun-txid"); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expected persisted txid transaction")
	}
}

func TestCreateAndLoadFileWalletFromKeystore(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")
	keystorePath := filepath.Join(tmpDir, "wallet.keystore.json")
	created, secret, err := CreateFileWalletFromMnemonic(
		stateDir,
		keystorePath,
		testMnemonic,
		0,
		0,
		"password",
		testKeystoreOptions(),
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secret.EthereumPrivateKey == "" {
		t.Fatal("expected ethereum private key")
	}
	if created.IndexedWallet.Address != secret.Railgun.Address {
		t.Fatalf("expected bundle address %s, got %s", secret.Railgun.Address, created.IndexedWallet.Address)
	}

	loaded, loadedSecret, err := NewFileWalletFromKeystore(stateDir, keystorePath, "password", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if loadedSecret.Railgun.Address != secret.Railgun.Address {
		t.Fatalf("expected loaded address %s, got %s", secret.Railgun.Address, loadedSecret.Railgun.Address)
	}
	if loaded.IndexedWallet.MasterPublicKey != created.IndexedWallet.MasterPublicKey {
		t.Fatalf("expected loaded wallet to match created wallet")
	}
	if _, _, err := NewFileWalletFromKeystore(stateDir, keystorePath, "wrong-password", nil, nil); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestScanKeysFromMnemonicRejectsInvalidInputs(t *testing.T) {
	if _, _, err := ScanKeysFromMnemonic("not a mnemonic", 0, nil); err == nil {
		t.Fatal("expected invalid mnemonic error")
	}
	if _, _, err := ScanKeysFromMnemonic(testMnemonic, -1, nil); err == nil {
		t.Fatal("expected negative index error")
	}
}

func TestNewWalletRejectsMissingStoreSetDependencies(t *testing.T) {
	_, keys, err := ScanKeysFromMnemonic(testMnemonic, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewWallet(StoreSet{}, keys, nil); err == nil {
		t.Fatal("expected missing store error")
	}
}

func TestNewWalletFromSecretRequiresMnemonic(t *testing.T) {
	_, err := NewWalletFromSecret(NewMemoryStores(), railwallet.WalletSecret{
		Railgun: railwallet.IndexedWallet{Address: "0zk-public-only"},
	}, nil, nil)
	if err == nil {
		t.Fatal("expected public-only secret to fail")
	}
}

func testStoredTXO(t *testing.T, nullifier string) railwallet.StoredTXO {
	t.Helper()
	tokenData, err := railcrypto.TokenDataERC20("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		t.Fatal(err)
	}
	commitmentHash, err := railcrypto.BigIntToHex(big.NewInt(1), 32, false)
	if err != nil {
		t.Fatal(err)
	}
	return railwallet.StoredTXO{
		TXIDVersion:    railcrypto.TXIDVersionV3PoseidonMerkle,
		Tree:           0,
		Position:       1,
		BlockNumber:    10,
		Nullifier:      nullifier,
		CommitmentHash: commitmentHash,
		TokenHash:      tokenHash,
		TokenData:      tokenData,
		Value:          big.NewInt(7),
	}
}

func testKeystoreOptions() railwallet.KeystoreOptions {
	return railwallet.KeystoreOptions{
		ScryptN: 1024,
		ScryptR: 8,
		ScryptP: 1,
		KeyLen:  32,
	}
}
