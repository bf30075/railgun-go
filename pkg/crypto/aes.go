package railcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type CiphertextGCM struct {
	IV   string   `json:"iv"`
	Tag  string   `json:"tag"`
	Data []string `json:"data"`
}

type CiphertextCTR struct {
	IV   string   `json:"iv"`
	Data []string `json:"data"`
}

func AESGCMEncryptHex(plaintext []string, keyHex string, ivHex string) (CiphertextGCM, error) {
	key, err := fixedBytesFromHex(keyHex, 32, "key")
	if err != nil {
		return CiphertextGCM{}, err
	}
	iv, err := fixedBytesFromHex(ivHex, 16, "iv")
	if err != nil {
		return CiphertextGCM{}, err
	}
	plaintextBytes, lengths, err := concatHexBlocks(plaintext)
	if err != nil {
		return CiphertextGCM{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return CiphertextGCM{}, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return CiphertextGCM{}, err
	}
	sealed := aead.Seal(nil, iv, plaintextBytes, nil)
	ciphertext := sealed[:len(sealed)-aead.Overhead()]
	tag := sealed[len(sealed)-aead.Overhead():]
	return CiphertextGCM{
		IV:   BytesToHex(iv, false),
		Tag:  BytesToHex(tag, false),
		Data: splitHexBlocks(ciphertext, lengths),
	}, nil
}

func AESGCMDecryptHex(ciphertext CiphertextGCM, keyHex string) ([]string, error) {
	key, err := fixedBytesFromHex(keyHex, 32, "key")
	if err != nil {
		return nil, err
	}
	iv, err := fixedBytesFromHex(ciphertext.IV, 16, "iv")
	if err != nil {
		return nil, err
	}
	tag, err := fixedBytesFromHex(ciphertext.Tag, 16, "tag")
	if err != nil {
		return nil, err
	}
	ciphertextBytes, lengths, err := concatHexBlocks(ciphertext.Data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte{}, ciphertextBytes...), tag...)
	plaintext, err := aead.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt ciphertext: %w", err)
	}
	return splitHexBlocks(plaintext, lengths), nil
}

func AESCTREncryptHex(plaintext []string, keyHex string, ivHex string) (CiphertextCTR, error) {
	key, err := fixedBytesFromHex(keyHex, 32, "key")
	if err != nil {
		return CiphertextCTR{}, err
	}
	iv, err := fixedBytesFromHex(ivHex, 16, "iv")
	if err != nil {
		return CiphertextCTR{}, err
	}
	plaintextBytes, lengths, err := concatHexBlocks(plaintext)
	if err != nil {
		return CiphertextCTR{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return CiphertextCTR{}, err
	}
	out := make([]byte, len(plaintextBytes))
	cipher.NewCTR(block, iv).XORKeyStream(out, plaintextBytes)
	return CiphertextCTR{
		IV:   BytesToHex(iv, false),
		Data: splitHexBlocks(out, lengths),
	}, nil
}

func AESCTRDecryptHex(ciphertext CiphertextCTR, keyHex string) ([]string, error) {
	key, err := fixedBytesFromHex(keyHex, 32, "key")
	if err != nil {
		return nil, err
	}
	iv, err := fixedBytesFromHex(ciphertext.IV, 16, "iv")
	if err != nil {
		return nil, err
	}
	ciphertextBytes, lengths, err := concatHexBlocks(ciphertext.Data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertextBytes))
	cipher.NewCTR(block, iv).XORKeyStream(out, ciphertextBytes)
	return splitHexBlocks(out, lengths), nil
}

func fixedBytesFromHex(value string, expectedLength int, name string) ([]byte, error) {
	out, err := HexToBytes(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(out) != expectedLength {
		return nil, fmt.Errorf("invalid %s length: expected %d bytes, got %d", name, expectedLength, len(out))
	}
	return out, nil
}

func concatHexBlocks(values []string) ([]byte, []int, error) {
	lengths := make([]int, len(values))
	var out []byte
	for i, value := range values {
		decoded, err := HexToBytes(value)
		if err != nil {
			return nil, nil, fmt.Errorf("block[%d]: %w", i, err)
		}
		lengths[i] = len(decoded)
		out = append(out, decoded...)
	}
	return out, lengths, nil
}

func splitHexBlocks(value []byte, lengths []int) []string {
	out := make([]string, len(lengths))
	offset := 0
	for i, length := range lengths {
		out[i] = BytesToHex(value[offset:offset+length], false)
		offset += length
	}
	return out
}
