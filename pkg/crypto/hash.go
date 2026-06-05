package railcrypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/sha3"
)

func SHA256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return BytesToHex(hash[:], false)
}

func SHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	out := make([]byte, len(hash))
	copy(out, hash[:])
	return out
}

func Keccak256HexBytes(data []byte) string {
	h := sha3.NewLegacyKeccak256()
	writeHash(h, data)
	return BytesToHex(h.Sum(nil), false)
}

func Keccak256Hex(value string) (string, error) {
	data, err := HexToBytes(value)
	if err != nil {
		return "", err
	}
	return Keccak256HexBytes(data), nil
}

func writeHash(h hash.Hash, data []byte) {
	_, _ = h.Write(data)
}
