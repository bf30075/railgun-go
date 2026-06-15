// Package address implements encoding and decoding of RAILGUN 0zk addresses.
package address

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const (
	Prefix             = "0zk"
	AddressLengthLimit = 127
	AddressVersion     = 1
	allChainsNetworkID = "ffffffffffffffff"
)

type Chain struct {
	Type int `json:"type"`
	ID   int `json:"id"`
}

type AddressData struct {
	MasterPublicKey  string `json:"masterPublicKey"`
	ViewingPublicKey string `json:"viewingPublicKey"`
	Chain            *Chain `json:"chain,omitempty"`
	Version          int    `json:"version"`
}

func Encode(addressData AddressData) (string, error) {
	mpk, err := railcrypto.NumberishToBigInt(addressData.MasterPublicKey)
	if err != nil {
		return "", fmt.Errorf("master public key: %w", err)
	}
	masterPublicKey, err := railcrypto.BigIntToHex(mpk, 32, false)
	if err != nil {
		return "", err
	}
	viewingPublicKey, err := railcrypto.FormatHexToByteLength(addressData.ViewingPublicKey, 32, false)
	if err != nil {
		return "", fmt.Errorf("viewing public key: %w", err)
	}
	networkID, err := chainToNetworkID(addressData.Chain)
	if err != nil {
		return "", err
	}
	addressHex := fmt.Sprintf("%02x%s%s%s", AddressVersion, masterPublicKey, xorNetworkID(networkID), viewingPublicKey)
	addressBytes, err := hex.DecodeString(addressHex)
	if err != nil {
		return "", err
	}
	return bech32mEncode(Prefix, addressBytes)
}

func Decode(value string) (AddressData, error) {
	hrp, payload, err := bech32mDecode(value)
	if err != nil {
		if strings.Contains(err.Error(), "checksum") {
			return AddressData{}, fmt.Errorf("invalid checksum")
		}
		return AddressData{}, fmt.Errorf("failed to decode bech32 address: %w", err)
	}
	if hrp != Prefix {
		return AddressData{}, fmt.Errorf("failed to decode bech32 address: invalid address prefix")
	}
	data := railcrypto.BytesToHex(payload, false)
	if len(data) != 146 {
		return AddressData{}, fmt.Errorf("failed to decode bech32 address: invalid payload length")
	}
	versionN, err := railcrypto.HexToBigInt(data[:2])
	if err != nil {
		return AddressData{}, err
	}
	version := int(versionN.Int64())
	if version != AddressVersion {
		return AddressData{}, fmt.Errorf("failed to decode bech32 address: incorrect address version")
	}
	networkID := xorNetworkID(data[66:82])
	chain, err := networkIDToChain(networkID)
	if err != nil {
		return AddressData{}, err
	}
	mpk, err := railcrypto.HexToBigInt(data[2:66])
	if err != nil {
		return AddressData{}, err
	}
	return AddressData{
		MasterPublicKey:  mpk.String(),
		ViewingPublicKey: data[82:146],
		Chain:            chain,
		Version:          version,
	}, nil
}

func chainToNetworkID(chain *Chain) (string, error) {
	if chain == nil {
		return allChainsNetworkID, nil
	}
	if chain.Type < 0 || chain.Type > 255 {
		return "", fmt.Errorf("chain type exceeds uint8")
	}
	if chain.ID < 0 {
		return "", fmt.Errorf("chain id must be non-negative")
	}
	chainID := new(big.Int).SetInt64(int64(chain.ID))
	if chainID.BitLen() > 56 {
		return "", fmt.Errorf("chain id exceeds uint56")
	}
	return fmt.Sprintf("%02x%014x", chain.Type, chain.ID), nil
}

func networkIDToChain(networkID string) (*Chain, error) {
	if networkID == allChainsNetworkID {
		return nil, nil
	}
	if len(networkID) != 16 {
		return nil, fmt.Errorf("invalid network id length")
	}
	chainType, err := railcrypto.HexToBigInt(networkID[:2])
	if err != nil {
		return nil, err
	}
	chainID, err := railcrypto.HexToBigInt(networkID[2:16])
	if err != nil {
		return nil, err
	}
	return &Chain{Type: int(chainType.Int64()), ID: int(chainID.Int64())}, nil
}

func xorNetworkID(chainID string) string {
	chainIDBytes, err := hex.DecodeString(chainID)
	if err != nil {
		return ""
	}
	railgun := []byte("railgun")
	for i := range chainIDBytes {
		if i < len(railgun) {
			chainIDBytes[i] ^= railgun[i]
		}
	}
	return railcrypto.BytesToHex(chainIDBytes, false)
}
