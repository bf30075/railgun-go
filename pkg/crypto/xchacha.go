package railcrypto

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	XChaChaEncryptionAlgorithm         = "XChaCha"
	XChaChaPoly1305EncryptionAlgorithm = "XChaChaPoly1305"
)

type CiphertextXChaCha struct {
	Algorithm string `json:"algorithm"`
	Nonce     string `json:"nonce"`
	Bundle    string `json:"bundle"`
}

func XChaCha20EncryptHex(plaintextHex string, key []byte, nonceHex string) (CiphertextXChaCha, error) {
	bundle, err := xChaCha20XORHex(plaintextHex, key, nonceHex)
	if err != nil {
		return CiphertextXChaCha{}, err
	}
	return CiphertextXChaCha{
		Algorithm: XChaChaEncryptionAlgorithm,
		Nonce:     nonceHex,
		Bundle:    bundle,
	}, nil
}

func XChaCha20DecryptHex(ciphertext CiphertextXChaCha, key []byte) (string, error) {
	if ciphertext.Algorithm != XChaChaEncryptionAlgorithm {
		return "", fmt.Errorf("invalid ciphertext for XChaCha: %s", ciphertext.Algorithm)
	}
	return xChaCha20XORHex(ciphertext.Bundle, key, ciphertext.Nonce)
}

func XChaCha20Poly1305EncryptHex(plaintextHex string, key []byte, nonceHex string) (CiphertextXChaCha, error) {
	if len(key) != chacha20poly1305.KeySize {
		return CiphertextXChaCha{}, fmt.Errorf("invalid key length: expected %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	nonce := xChaChaNonceFromRailgunNonce(nonceHex)
	plaintext, err := HexToBytes(plaintextHex)
	if err != nil {
		return CiphertextXChaCha{}, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return CiphertextXChaCha{}, err
	}
	return CiphertextXChaCha{
		Algorithm: XChaChaPoly1305EncryptionAlgorithm,
		Nonce:     nonceHex,
		Bundle:    BytesToHex(aead.Seal(nil, nonce, plaintext, nil), false),
	}, nil
}

func XChaCha20Poly1305DecryptHex(ciphertext CiphertextXChaCha, key []byte) (string, error) {
	if ciphertext.Algorithm != XChaChaPoly1305EncryptionAlgorithm {
		return "", fmt.Errorf("invalid ciphertext for XChaChaPoly1305: %s", ciphertext.Algorithm)
	}
	if len(key) != chacha20poly1305.KeySize {
		return "", fmt.Errorf("invalid key length: expected %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	bundle, err := HexToBytes(ciphertext.Bundle)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	plaintext, err := aead.Open(nil, xChaChaNonceFromRailgunNonce(ciphertext.Nonce), bundle, nil)
	if err != nil {
		return "", err
	}
	return BytesToHex(plaintext, false), nil
}

func xChaCha20XORHex(inputHex string, key []byte, nonceHex string) (string, error) {
	if len(key) != chacha20poly1305.KeySize {
		return "", fmt.Errorf("invalid key length: expected %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	input, err := HexToBytes(inputHex)
	if err != nil {
		return "", err
	}
	stream, err := chacha20.NewUnauthenticatedCipher(key, xChaChaNonceFromRailgunNonce(nonceHex))
	if err != nil {
		return "", err
	}
	out := make([]byte, len(input))
	stream.XORKeyStream(out, input)
	return BytesToHex(out, false), nil
}

func xChaChaNonceFromRailgunNonce(nonceHex string) []byte {
	hash := sha256.Sum256([]byte(nonceHex))
	return hash[:chacha20poly1305.NonceSizeX]
}
