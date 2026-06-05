package railcrypto

import (
	"math/big"
)

func MasterPublicKey(spendingPublicKey [2]*big.Int, nullifyingKey *big.Int) (*big.Int, error) {
	return Poseidon(spendingPublicKey[0], spendingPublicKey[1], nullifyingKey)
}

func NotePublicKey(masterPublicKey *big.Int, randomHex string) (*big.Int, error) {
	random, err := HexToBigInt(randomHex)
	if err != nil {
		return nil, err
	}
	return Poseidon(masterPublicKey, random)
}

func NoteHash(notePublicKey *big.Int, tokenHash string, value *big.Int) (*big.Int, error) {
	token, err := HexToBigInt(tokenHash)
	if err != nil {
		return nil, err
	}
	return Poseidon(notePublicKey, token, value)
}

func NoteHashFromTokenData(notePublicKey *big.Int, tokenData TokenData, value *big.Int) (*big.Int, error) {
	tokenHash, err := TokenDataHash(tokenData)
	if err != nil {
		return nil, err
	}
	return NoteHash(notePublicKey, tokenHash, value)
}

func UnshieldNoteHash(toAddress string, tokenData TokenData, value *big.Int) (*big.Int, error) {
	notePublicKey, err := HexToBigInt(toAddress)
	if err != nil {
		return nil, err
	}
	return NoteHashFromTokenData(notePublicKey, tokenData, value)
}

func Nullifier(nullifyingKey *big.Int, leafIndex uint64) (*big.Int, error) {
	return Poseidon(nullifyingKey, new(big.Int).SetUint64(leafIndex))
}

func BlindedCommitment(commitmentHash string, npk *big.Int, globalTreePosition *big.Int) (string, error) {
	commitment, err := HexToBigInt(commitmentHash)
	if err != nil {
		return "", err
	}
	hash, err := Poseidon(commitment, npk, globalTreePosition)
	if err != nil {
		return "", err
	}
	return BigIntToHex(hash, 32, true)
}

func BlindedUnshield(railgunTxid string) (string, error) {
	n, err := HexToBigInt(railgunTxid)
	if err != nil {
		return "", err
	}
	return BigIntToHex(n, 32, true)
}
