package broadcaster

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"

	"filippo.io/edwards25519"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	"golang.org/x/crypto/curve25519"
)

// EncryptDataWithSharedKeyResponse mirrors the wallet helper return value.
type EncryptDataWithSharedKeyResponse struct {
	EncryptedData EncryptedData
	RandomPubKey  string
	SharedKey     []byte
}

// EncryptDataWithSharedKey mirrors @railgun-community/wallet encryptDataWithSharedKey:
// random ed25519 keypair + noble-compatible X25519 shared secret + AES-256-GCM JSON.
func EncryptDataWithSharedKey(data any, externalPubKey []byte) (EncryptDataWithSharedKeyResponse, error) {
	if len(externalPubKey) != 32 {
		return EncryptDataWithSharedKeyResponse{}, fmt.Errorf("external viewing public key must be 32 bytes")
	}
	randomPriv := make([]byte, 32)
	if _, err := rand.Read(randomPriv); err != nil {
		return EncryptDataWithSharedKeyResponse{}, err
	}
	randomPub, err := railcrypto.PublicViewingKey(randomPriv)
	if err != nil {
		return EncryptDataWithSharedKeyResponse{}, err
	}
	sharedKey, err := X25519SharedSecret(randomPriv, externalPubKey)
	if err != nil {
		return EncryptDataWithSharedKeyResponse{}, err
	}
	encrypted, err := EncryptJSONDataWithSharedKey(data, sharedKey)
	if err != nil {
		return EncryptDataWithSharedKeyResponse{}, err
	}
	return EncryptDataWithSharedKeyResponse{
		EncryptedData: encrypted,
		RandomPubKey:  railcrypto.BytesToHex(randomPub, false),
		SharedKey:     sharedKey,
	}, nil
}

// DecryptAESGCM256 decrypts EncryptedData with a shared key; returns nil object on failure.
func DecryptAESGCM256(encrypted EncryptedData, sharedKey []byte) (map[string]any, bool) {
	obj, err := TryDecryptJSONDataWithSharedKey(encrypted, sharedKey)
	if err != nil {
		return nil, false
	}
	return obj, true
}

// EncryptJSONDataWithSharedKey mirrors engine encryptJSONDataWithSharedKey.
func EncryptJSONDataWithSharedKey(data any, sharedKey []byte) (EncryptedData, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return EncryptedData{}, err
	}
	chunks := chunkBytesToHex(raw, 32)
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return EncryptedData{}, err
	}
	ciphertext, err := railcrypto.AESGCMEncryptHex(chunks, railcrypto.BytesToHex(sharedKey, false), railcrypto.BytesToHex(iv, false))
	if err != nil {
		return EncryptedData{}, err
	}
	return ciphertextToEncryptedJSONData(ciphertext), nil
}

// TryDecryptJSONDataWithSharedKey mirrors engine tryDecryptJSONDataWithSharedKey.
func TryDecryptJSONDataWithSharedKey(encrypted EncryptedData, sharedKey []byte) (map[string]any, error) {
	ct, err := encryptedDataToCiphertext(encrypted)
	if err != nil {
		return nil, err
	}
	chunks, err := railcrypto.AESGCMDecryptHex(ct, railcrypto.BytesToHex(sharedKey, false))
	if err != nil {
		return nil, err
	}
	combined, err := combineHexChunks(chunks)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(combined, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// X25519SharedSecret matches @noble/ed25519 getSharedSecret(privateKey, publicKey).
func X25519SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("public key must be 32 bytes")
	}
	h := sha512.Sum512(privateKey)
	var sk [32]byte
	copy(sk[:], h[:32])
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64

	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("public key point: %w", err)
	}
	shared, err := curve25519.X25519(sk[:], point.BytesMontgomery())
	if err != nil {
		return nil, err
	}
	return shared, nil
}

func ciphertextToEncryptedJSONData(ciphertext railcrypto.CiphertextGCM) EncryptedData {
	ivTag := "0x" + railcrypto.Strip0x(ciphertext.IV) + railcrypto.Strip0x(ciphertext.Tag)
	combined := "0x"
	for _, block := range ciphertext.Data {
		combined += railcrypto.Strip0x(block)
	}
	return EncryptedData{ivTag, combined}
}

func encryptedDataToCiphertext(encrypted EncryptedData) (railcrypto.CiphertextGCM, error) {
	ivTag := railcrypto.Strip0x(encrypted[0])
	if len(ivTag) < 64 {
		return railcrypto.CiphertextGCM{}, fmt.Errorf("invalid encrypted data iv/tag")
	}
	iv := ivTag[:32]
	tag := ivTag[32:64]
	chunks := chunkHex(railcrypto.Strip0x(encrypted[1]), 64)
	return railcrypto.CiphertextGCM{
		IV:   iv,
		Tag:  tag,
		Data: chunks,
	}, nil
}

func chunkBytesToHex(value []byte, size int) []string {
	out := make([]string, 0, (len(value)+size-1)/size)
	for i := 0; i < len(value); i += size {
		end := i + size
		if end > len(value) {
			end = len(value)
		}
		out = append(out, railcrypto.BytesToHex(value[i:end], false))
	}
	return out
}

func chunkHex(value string, hexLen int) []string {
	out := make([]string, 0, (len(value)+hexLen-1)/hexLen)
	for i := 0; i < len(value); i += hexLen {
		end := i + hexLen
		if end > len(value) {
			end = len(value)
		}
		out = append(out, value[i:end])
	}
	return out
}

func combineHexChunks(chunks []string) ([]byte, error) {
	var out []byte
	for i, chunk := range chunks {
		decoded, err := railcrypto.HexToBytes(chunk)
		if err != nil {
			return nil, fmt.Errorf("chunk[%d]: %w", i, err)
		}
		out = append(out, decoded...)
	}
	return out, nil
}
