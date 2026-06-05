package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const (
	KeystoreVersion   = 1
	keystoreKDF       = "scrypt"
	keystoreCipher    = "aes-256-gcm"
	keystoreAAD       = "railgun-go-wallet-keystore-v1"
	legacyKeystoreAAD = "railway-wallet-keystore-v1"
)

type WalletSecret struct {
	Mnemonic           string            `json:"mnemonic,omitempty"`
	Index              int               `json:"index,omitempty"`
	Railgun            IndexedWallet     `json:"railgun,omitempty"`
	EthereumPrivateKey string            `json:"ethereumPrivateKey,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

type KeystoreOptions struct {
	ScryptN int
	ScryptR int
	ScryptP int
	KeyLen  int
}

type EncryptedKeystore struct {
	Version    int               `json:"version"`
	KDF        string            `json:"kdf"`
	KDFParams  KeystoreKDFParams `json:"kdfParams"`
	Cipher     string            `json:"cipher"`
	Salt       string            `json:"salt"`
	Nonce      string            `json:"nonce"`
	Ciphertext string            `json:"ciphertext"`
}

type KeystoreKDFParams struct {
	N      int `json:"n"`
	R      int `json:"r"`
	P      int `json:"p"`
	KeyLen int `json:"keyLen"`
}

func WalletSecretFromMnemonic(mnemonic string, railgunIndex int, evmIndex uint32) (WalletSecret, error) {
	if !ValidateMnemonic(mnemonic) {
		return WalletSecret{}, fmt.Errorf("invalid mnemonic")
	}
	if railgunIndex < 0 {
		return WalletSecret{}, fmt.Errorf("railgun index must be non-negative")
	}
	indexed, err := DeriveIndexedWallet(mnemonic, railgunIndex)
	if err != nil {
		return WalletSecret{}, err
	}
	ethereumPrivateKey, err := MnemonicTo0xPrivateKey(mnemonic, evmIndex)
	if err != nil {
		return WalletSecret{}, err
	}
	return WalletSecret{
		Mnemonic:           mnemonic,
		Index:              railgunIndex,
		Railgun:            indexed,
		EthereumPrivateKey: ethereumPrivateKey,
	}, nil
}

func EncryptWalletSecret(secret WalletSecret, password string, options KeystoreOptions) (EncryptedKeystore, error) {
	return encryptWalletSecretWithAAD(secret, password, options, keystoreAAD)
}

func encryptWalletSecretWithAAD(secret WalletSecret, password string, options KeystoreOptions, aad string) (EncryptedKeystore, error) {
	if err := secret.Validate(); err != nil {
		return EncryptedKeystore{}, err
	}
	params := normalizeKeystoreOptions(options)
	salt, err := randomBytes(32)
	if err != nil {
		return EncryptedKeystore{}, err
	}
	nonce, err := randomBytes(12)
	if err != nil {
		return EncryptedKeystore{}, err
	}
	key, err := deriveKeystoreKey(password, salt, params)
	if err != nil {
		return EncryptedKeystore{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedKeystore{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedKeystore{}, err
	}
	plaintext, err := json.Marshal(secret)
	if err != nil {
		return EncryptedKeystore{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))
	return EncryptedKeystore{
		Version:    KeystoreVersion,
		KDF:        keystoreKDF,
		KDFParams:  params,
		Cipher:     keystoreCipher,
		Salt:       railcrypto.BytesToHex(salt, false),
		Nonce:      railcrypto.BytesToHex(nonce, false),
		Ciphertext: railcrypto.BytesToHex(ciphertext, false),
	}, nil
}

func DecryptWalletSecret(keystore EncryptedKeystore, password string) (WalletSecret, error) {
	if err := validateKeystoreHeader(keystore); err != nil {
		return WalletSecret{}, err
	}
	salt, err := hex.DecodeString(railcrypto.Strip0x(keystore.Salt))
	if err != nil {
		return WalletSecret{}, fmt.Errorf("salt: %w", err)
	}
	nonce, err := hex.DecodeString(railcrypto.Strip0x(keystore.Nonce))
	if err != nil {
		return WalletSecret{}, fmt.Errorf("nonce: %w", err)
	}
	ciphertext, err := hex.DecodeString(railcrypto.Strip0x(keystore.Ciphertext))
	if err != nil {
		return WalletSecret{}, fmt.Errorf("ciphertext: %w", err)
	}
	key, err := deriveKeystoreKey(password, salt, keystore.KDFParams)
	if err != nil {
		return WalletSecret{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return WalletSecret{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return WalletSecret{}, err
	}
	var plaintext []byte
	var decryptErr error
	for _, aad := range []string{keystoreAAD, legacyKeystoreAAD} {
		plaintext, decryptErr = gcm.Open(nil, nonce, ciphertext, []byte(aad))
		if decryptErr == nil {
			break
		}
	}
	if decryptErr != nil {
		return WalletSecret{}, fmt.Errorf("decrypt keystore: %w", decryptErr)
	}
	var secret WalletSecret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return WalletSecret{}, err
	}
	if err := secret.Validate(); err != nil {
		return WalletSecret{}, err
	}
	return secret, nil
}

func SaveWalletSecret(path string, secret WalletSecret, password string, options KeystoreOptions) error {
	keystore, err := EncryptWalletSecret(secret, password, options)
	if err != nil {
		return err
	}
	return WriteKeystore(path, keystore)
}

func LoadWalletSecret(path string, password string) (WalletSecret, error) {
	keystore, err := ReadKeystore(path)
	if err != nil {
		return WalletSecret{}, err
	}
	return DecryptWalletSecret(keystore, password)
}

func WriteKeystore(path string, keystore EncryptedKeystore) error {
	if path == "" {
		return fmt.Errorf("keystore path is required")
	}
	if err := validateKeystoreHeader(keystore); err != nil {
		return err
	}
	data, err := json.MarshalIndent(keystore, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func ReadKeystore(path string) (EncryptedKeystore, error) {
	if path == "" {
		return EncryptedKeystore{}, fmt.Errorf("keystore path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return EncryptedKeystore{}, err
	}
	var keystore EncryptedKeystore
	if err := json.Unmarshal(data, &keystore); err != nil {
		return EncryptedKeystore{}, err
	}
	if err := validateKeystoreHeader(keystore); err != nil {
		return EncryptedKeystore{}, err
	}
	return keystore, nil
}

func (secret WalletSecret) Validate() error {
	if secret.Mnemonic == "" && secret.Railgun.Address == "" && secret.EthereumPrivateKey == "" {
		return fmt.Errorf("wallet secret is empty")
	}
	if secret.Mnemonic != "" && !ValidateMnemonic(secret.Mnemonic) {
		return fmt.Errorf("invalid mnemonic")
	}
	if secret.Index < 0 {
		return fmt.Errorf("wallet index must be non-negative")
	}
	return nil
}

func normalizeKeystoreOptions(options KeystoreOptions) KeystoreKDFParams {
	if options.ScryptN == 0 {
		options.ScryptN = 1 << 15
	}
	if options.ScryptR == 0 {
		options.ScryptR = 8
	}
	if options.ScryptP == 0 {
		options.ScryptP = 1
	}
	if options.KeyLen == 0 {
		options.KeyLen = 32
	}
	return KeystoreKDFParams{
		N:      options.ScryptN,
		R:      options.ScryptR,
		P:      options.ScryptP,
		KeyLen: options.KeyLen,
	}
}

func deriveKeystoreKey(password string, salt []byte, params KeystoreKDFParams) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("keystore password is required")
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("keystore salt must be at least 16 bytes")
	}
	if params.N <= 1 || params.R <= 0 || params.P <= 0 || params.KeyLen != 32 {
		return nil, fmt.Errorf("invalid keystore kdf parameters")
	}
	return scrypt.Key([]byte(password), salt, params.N, params.R, params.P, params.KeyLen)
}

func validateKeystoreHeader(keystore EncryptedKeystore) error {
	if keystore.Version != KeystoreVersion {
		return fmt.Errorf("unsupported keystore version %d", keystore.Version)
	}
	if keystore.KDF != keystoreKDF {
		return fmt.Errorf("unsupported keystore kdf %s", keystore.KDF)
	}
	if keystore.Cipher != keystoreCipher {
		return fmt.Errorf("unsupported keystore cipher %s", keystore.Cipher)
	}
	if keystore.Salt == "" || keystore.Nonce == "" || keystore.Ciphertext == "" {
		return fmt.Errorf("keystore is missing encrypted fields")
	}
	return nil
}

func randomBytes(length int) ([]byte, error) {
	out := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, err
	}
	return out, nil
}
