package railcrypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/iden3/go-iden3-crypto/v2/babyjub"
)

type PoseidonSignature struct {
	R8 [2]*big.Int
	S  *big.Int
}

var ed25519SubgroupOrder = mustDecimal("7237005577332262213973186563042994240857116359379907606001950938285454250989")

func PublicSpendingKey(privateKey []byte) ([2]*big.Int, error) {
	key, err := babyJubPrivateKey(privateKey)
	if err != nil {
		return [2]*big.Int{}, err
	}
	pub := key.Public()
	return [2]*big.Int{new(big.Int).Set(pub.X), new(big.Int).Set(pub.Y)}, nil
}

func SignPoseidon(privateKey []byte, message *big.Int) (PoseidonSignature, error) {
	key, err := babyJubPrivateKey(privateKey)
	if err != nil {
		return PoseidonSignature{}, err
	}
	sig, err := key.SignPoseidon(message)
	if err != nil {
		return PoseidonSignature{}, err
	}
	return PoseidonSignature{
		R8: [2]*big.Int{new(big.Int).Set(sig.R8.X), new(big.Int).Set(sig.R8.Y)},
		S:  new(big.Int).Set(sig.S),
	}, nil
}

func VerifyPoseidon(message *big.Int, signature PoseidonSignature, publicKey [2]*big.Int) bool {
	pub := babyjub.PublicKey(babyjub.Point{
		X: new(big.Int).Set(publicKey[0]),
		Y: new(big.Int).Set(publicKey[1]),
	})
	sig := &babyjub.Signature{
		R8: &babyjub.Point{
			X: new(big.Int).Set(signature.R8[0]),
			Y: new(big.Int).Set(signature.R8[1]),
		},
		S: new(big.Int).Set(signature.S),
	}
	return pub.VerifyPoseidon(message, sig) == nil
}

func PublicViewingKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != ed25519.SeedSize {
		return nil, errors.New("ed25519 private viewing key must be 32 bytes")
	}
	key := ed25519.NewKeyFromSeed(privateKey)
	pub := key.Public().(ed25519.PublicKey)
	out := make([]byte, len(pub))
	copy(out, pub)
	return out, nil
}

func SignED25519(message []byte, privateKey []byte) ([]byte, error) {
	if len(privateKey) != ed25519.SeedSize {
		return nil, errors.New("ed25519 private key must be 32 bytes")
	}
	key := ed25519.NewKeyFromSeed(privateKey)
	return ed25519.Sign(key, message), nil
}

func VerifyED25519(message []byte, signature []byte, publicKey []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

func PrivateScalarFromPrivateKey(privateKey []byte) (*big.Int, error) {
	if len(privateKey) != ed25519.SeedSize {
		return nil, errors.New("ed25519 private key must be 32 bytes")
	}
	digest := sha512.Sum512(privateKey)
	head := adjustBytes25519(digest[:32], "le")
	scalar := littleEndianBytesToBigInt(head)
	scalar.Mod(scalar, ed25519SubgroupOrder)
	if scalar.Sign() == 0 {
		return new(big.Int).Set(ed25519SubgroupOrder), nil
	}
	return scalar, nil
}

func SharedSymmetricKey(privateKey []byte, publicKey []byte) ([]byte, error) {
	scalarBig, err := PrivateScalarFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	scalarBytes, err := bigIntToLittleEndian32(scalarBig)
	if err != nil {
		return nil, err
	}
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("private scalar: %w", err)
	}
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("public key point: %w", err)
	}
	sharedPoint := new(edwards25519.Point).ScalarMult(scalar, point)
	hash := sha256.Sum256(sharedPoint.Bytes())
	out := make([]byte, len(hash))
	copy(out, hash[:])
	return out, nil
}

func SharedSymmetricKeyLegacy(privateKey []byte, publicKey []byte) ([]byte, error) {
	scalarBig, err := PrivateScalarFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	scalarBytes, err := bigIntToLittleEndian32(scalarBig)
	if err != nil {
		return nil, err
	}
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("private scalar: %w", err)
	}
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("public key point: %w", err)
	}
	return new(edwards25519.Point).ScalarMult(scalar, point).Bytes(), nil
}

func NoteBlindingKeys(senderViewingPublicKey []byte, receiverViewingPublicKey []byte, sharedRandom string, senderRandom string) ([]byte, []byte, error) {
	scalar, err := blindingScalar(sharedRandom, senderRandom)
	if err != nil {
		return nil, nil, err
	}
	blindedSender, err := scalarMultEd25519(senderViewingPublicKey, scalar)
	if err != nil {
		return nil, nil, fmt.Errorf("sender viewing key: %w", err)
	}
	blindedReceiver, err := scalarMultEd25519(receiverViewingPublicKey, scalar)
	if err != nil {
		return nil, nil, fmt.Errorf("receiver viewing key: %w", err)
	}
	return blindedSender, blindedReceiver, nil
}

func UnblindNoteKey(blindedNoteKey []byte, sharedRandom string, senderRandom string) ([]byte, error) {
	scalar, err := blindingScalar(sharedRandom, senderRandom)
	if err != nil {
		return nil, err
	}
	inverse := new(edwards25519.Scalar).Invert(scalar)
	point, err := new(edwards25519.Point).SetBytes(blindedNoteKey)
	if err != nil {
		return nil, fmt.Errorf("blinded note key point: %w", err)
	}
	return new(edwards25519.Point).ScalarMult(inverse, point).Bytes(), nil
}

func NoteBlindingKeysLegacy(senderViewingPublicKey []byte, receiverViewingPublicKey []byte, sharedRandom string, senderRandom string) ([]byte, []byte, error) {
	scalar, err := blindingScalarLegacy(sharedRandom, senderRandom)
	if err != nil {
		return nil, nil, err
	}
	blindedSender, err := scalarMultEd25519(senderViewingPublicKey, scalar)
	if err != nil {
		return nil, nil, fmt.Errorf("sender viewing key: %w", err)
	}
	blindedReceiver, err := scalarMultEd25519(receiverViewingPublicKey, scalar)
	if err != nil {
		return nil, nil, fmt.Errorf("receiver viewing key: %w", err)
	}
	return blindedSender, blindedReceiver, nil
}

func UnblindNoteKeyLegacy(blindedNoteKey []byte, sharedRandom string, senderRandom string) ([]byte, error) {
	scalar, err := blindingScalarLegacy(sharedRandom, senderRandom)
	if err != nil {
		return nil, err
	}
	inverse := new(edwards25519.Scalar).Invert(scalar)
	point, err := new(edwards25519.Point).SetBytes(blindedNoteKey)
	if err != nil {
		return nil, fmt.Errorf("blinded note key point: %w", err)
	}
	return new(edwards25519.Point).ScalarMult(inverse, point).Bytes(), nil
}

func babyJubPrivateKey(privateKey []byte) (*babyjub.PrivateKey, error) {
	if len(privateKey) != 32 {
		return nil, errors.New("babyjub private key must be 32 bytes")
	}
	var key babyjub.PrivateKey
	copy(key[:], privateKey)
	return &key, nil
}

func blindingScalar(sharedRandom string, senderRandom string) (*edwards25519.Scalar, error) {
	shared, err := HexToBigInt(sharedRandom)
	if err != nil {
		return nil, fmt.Errorf("shared random: %w", err)
	}
	sender, err := HexToBigInt(senderRandom)
	if err != nil {
		return nil, fmt.Errorf("sender random: %w", err)
	}
	finalRandom := new(big.Int).Xor(shared, sender)
	finalRandomHex, err := BigIntToHex(finalRandom, 32, false)
	if err != nil {
		return nil, err
	}
	finalRandomBytes, err := HexToBytes(finalRandomHex)
	if err != nil {
		return nil, err
	}
	seedHash := sha512.Sum512(finalRandomBytes)
	scalarBig := new(big.Int).SetBytes(seedHash[:])
	scalarBig.Mod(scalarBig, ed25519SubgroupOrder)
	scalarBytes, err := bigIntToLittleEndian32(scalarBig)
	if err != nil {
		return nil, err
	}
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("blinding scalar: %w", err)
	}
	return scalar, nil
}

func blindingScalarLegacy(sharedRandom string, senderRandom string) (*edwards25519.Scalar, error) {
	shared, err := HexToBigInt(sharedRandom)
	if err != nil {
		return nil, fmt.Errorf("shared random: %w", err)
	}
	sender, err := HexToBigInt(senderRandom)
	if err != nil {
		return nil, fmt.Errorf("sender random: %w", err)
	}
	finalRandom := new(big.Int).Xor(shared, sender)
	finalRandomHex, err := BigIntToHex(finalRandom, 32, false)
	if err != nil {
		return nil, err
	}
	finalRandomBytes, err := HexToBytes(finalRandomHex)
	if err != nil {
		return nil, err
	}
	seedHash := sha256.Sum256(finalRandomBytes)
	adjusted := adjustBytes25519(seedHash[:], "le")
	scalarBig := new(big.Int).SetBytes(adjusted)
	scalarBig.Mod(scalarBig, ed25519SubgroupOrder)
	scalarBytes, err := bigIntToLittleEndian32(scalarBig)
	if err != nil {
		return nil, err
	}
	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("legacy blinding scalar: %w", err)
	}
	return scalar, nil
}

func scalarMultEd25519(publicKey []byte, scalar *edwards25519.Scalar) ([]byte, error) {
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("public key point: %w", err)
	}
	return new(edwards25519.Point).ScalarMult(scalar, point).Bytes(), nil
}

func adjustBytes25519(value []byte, endian string) []byte {
	out := make([]byte, len(value))
	copy(out, value)
	switch endian {
	case "be":
		out[31] &= 0b11111000
		out[0] &= 0b01111111
		out[0] |= 0b01000000
	case "le":
		out[0] &= 0b11111000
		out[31] &= 0b01111111
		out[31] |= 0b01000000
	}
	return out
}

func littleEndianBytesToBigInt(value []byte) *big.Int {
	reversed := make([]byte, len(value))
	for i := range value {
		reversed[len(value)-1-i] = value[i]
	}
	return new(big.Int).SetBytes(reversed)
}

func bigIntToLittleEndian32(value *big.Int) ([]byte, error) {
	if value.Sign() < 0 {
		return nil, errors.New("scalar must be positive")
	}
	bigEndian := value.Bytes()
	if len(bigEndian) > 32 {
		return nil, errors.New("scalar exceeds 32 bytes")
	}
	out := make([]byte, 32)
	for i := range bigEndian {
		out[i] = bigEndian[len(bigEndian)-1-i]
	}
	return out, nil
}
