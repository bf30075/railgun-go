package wallet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalletSecretFromMnemonicDerivesRailgunAndEthereumKeys(t *testing.T) {
	fixtures := loadWalletFixtures(t)
	secret, err := WalletSecretFromMnemonic(fixtures.Indexed.Mnemonic, fixtures.Indexed.Index, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, secret.Railgun, fixtures.Indexed)

	evm := fixtures.Mnemonic.EVM[0]
	secret, err = WalletSecretFromMnemonic(evm.Mnemonic, 0, evm.Index)
	if err != nil {
		t.Fatal(err)
	}
	if secret.EthereumPrivateKey != evm.PrivateKey {
		t.Fatalf("expected ethereum private key %s, got %s", evm.PrivateKey, secret.EthereumPrivateKey)
	}
}

func TestEncryptWalletSecretRoundTripsWithoutPlaintextLeak(t *testing.T) {
	secret := testKeystoreSecret(t)
	keystore, err := EncryptWalletSecret(secret, "correct horse battery staple", testKeystoreOptions())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(keystore)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret.Mnemonic) {
		t.Fatal("encrypted keystore contains plaintext mnemonic")
	}
	if strings.Contains(string(raw), secret.EthereumPrivateKey) {
		t.Fatal("encrypted keystore contains plaintext ethereum private key")
	}

	decrypted, err := DecryptWalletSecret(keystore, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, decrypted, secret)
}

func TestDecryptWalletSecretAcceptsLegacyAAD(t *testing.T) {
	secret := testKeystoreSecret(t)
	keystore, err := encryptWalletSecretWithAAD(secret, "password", testKeystoreOptions(), legacyKeystoreAAD)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptWalletSecret(keystore, "password")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, decrypted, secret)
}

func TestFileKeystoreRoundTripsAndRejectsWrongPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet.keystore.json")
	secret := testKeystoreSecret(t)
	if err := SaveWalletSecret(path, secret, "password", testKeystoreOptions()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected keystore file mode 0600, got %o", info.Mode().Perm())
	}

	decrypted, err := LoadWalletSecret(path, "password")
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, decrypted, secret)

	if _, err := LoadWalletSecret(path, "wrong-password"); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestKeystoreRejectsInvalidInputs(t *testing.T) {
	secret := testKeystoreSecret(t)
	if _, err := EncryptWalletSecret(secret, "", testKeystoreOptions()); err == nil {
		t.Fatal("expected empty password to fail")
	}
	secret.Mnemonic = "not a valid mnemonic"
	if _, err := EncryptWalletSecret(secret, "password", testKeystoreOptions()); err == nil {
		t.Fatal("expected invalid mnemonic to fail")
	}
	if _, err := ReadKeystore(""); err == nil {
		t.Fatal("expected empty path to fail")
	}
}

func testKeystoreSecret(t *testing.T) WalletSecret {
	t.Helper()
	fixtures := loadWalletFixtures(t)
	evm := fixtures.Mnemonic.EVM[0]
	secret, err := WalletSecretFromMnemonic(fixtures.Indexed.Mnemonic, fixtures.Indexed.Index, evm.Index)
	if err != nil {
		t.Fatal(err)
	}
	secret.Metadata = map[string]string{
		"label": "test wallet",
	}
	return secret
}

func testKeystoreOptions() KeystoreOptions {
	return KeystoreOptions{
		ScryptN: 1024,
		ScryptR: 8,
		ScryptP: 1,
		KeyLen:  32,
	}
}
