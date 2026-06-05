package wallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"

	"github.com/bf30075/railgun-go/pkg/address"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

const hardenedOffset = 0x80000000

var derivationPathPattern = regexp.MustCompile(`^m(/[0-9]+')+$`)

type KeyNode struct {
	ChainKey  string `json:"chainKey"`
	ChainCode string `json:"chainCode"`
}

type SpendingKeyPair struct {
	PrivateKey string    `json:"privateKey"`
	PublicKey  [2]string `json:"pubkey"`
}

type ViewingKeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"pubkey"`
}

type DerivedNode struct {
	Node          KeyNode         `json:"node"`
	Spending      SpendingKeyPair `json:"spendingKeyPair"`
	Viewing       ViewingKeyPair  `json:"viewingKeyPair"`
	NullifyingKey string          `json:"nullifyingKey"`
}

type IndexedWallet struct {
	Mnemonic          string    `json:"mnemonic"`
	Index             int       `json:"index"`
	SpendingPublicKey [2]string `json:"spendingPublicKey"`
	ViewingPublicKey  string    `json:"viewingPublicKey"`
	NullifyingKey     string    `json:"nullifyingKey"`
	MasterPublicKey   string    `json:"masterPublicKey"`
	Address           string    `json:"address"`
}

func MnemonicToSeed(mnemonic string, password string) string {
	seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
	return railcrypto.BytesToHex(seed, false)
}

func GenerateMnemonic(strength int) (string, error) {
	if strength == 0 {
		strength = 128
	}
	if strength != 128 && strength != 192 && strength != 256 {
		return "", fmt.Errorf("strength must be 128, 192, or 256")
	}
	entropy, err := bip39.NewEntropy(strength)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

func MnemonicToEntropy(mnemonic string) (string, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(entropy, false), nil
}

func MnemonicFromEntropy(entropyHex string) (string, error) {
	entropy, err := hex.DecodeString(railcrypto.Strip0x(entropyHex))
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

func MnemonicTo0xPrivateKey(mnemonic string, derivationIndex uint32) (string, error) {
	key, err := derive0xKey(mnemonic, derivationIndex)
	if err != nil {
		return "", err
	}
	privateKey, err := privateKeyBytesFromBIP32(key)
	if err != nil {
		return "", err
	}
	return railcrypto.BytesToHex(privateKey, false), nil
}

func MnemonicTo0xAddress(mnemonic string, derivationIndex uint32) (string, error) {
	key, err := derive0xKey(mnemonic, derivationIndex)
	if err != nil {
		return "", err
	}
	privateKey, err := privateKeyBytesFromBIP32(key)
	if err != nil {
		return "", err
	}
	ecdsaPrivateKey, err := ethcrypto.ToECDSA(privateKey)
	if err != nil {
		return "", err
	}
	return ethcrypto.PubkeyToAddress(ecdsaPrivateKey.PublicKey).Hex(), nil
}

func MasterKeyFromSeed(seedHex string) (KeyNode, error) {
	return hmacSHA512Node([]byte("babyjubjub seed"), seedHex)
}

func DeriveFromMnemonic(mnemonic string, path string) (DerivedNode, error) {
	seed := MnemonicToSeed(mnemonic, "")
	node, err := MasterKeyFromSeed(seed)
	if err != nil {
		return DerivedNode{}, err
	}
	derived, err := Derive(node, path)
	if err != nil {
		return DerivedNode{}, err
	}
	return BuildDerivedNode(derived)
}

func DeriveIndexedWallet(mnemonic string, index int) (IndexedWallet, error) {
	spendingPath := fmt.Sprintf("m/44'/1984'/0'/0'/%d'", index)
	viewingPath := fmt.Sprintf("m/420'/1984'/0'/0'/%d'", index)
	spendingNode, err := DeriveFromMnemonic(mnemonic, spendingPath)
	if err != nil {
		return IndexedWallet{}, err
	}
	viewingNode, err := DeriveFromMnemonic(mnemonic, viewingPath)
	if err != nil {
		return IndexedWallet{}, err
	}
	spendingPublicKey := [2]*big.Int{
		mustDecimalBigInt(spendingNode.Spending.PublicKey[0]),
		mustDecimalBigInt(spendingNode.Spending.PublicKey[1]),
	}
	nullifyingKey := mustDecimalBigInt(viewingNode.NullifyingKey)
	masterPublicKey, err := railcrypto.MasterPublicKey(spendingPublicKey, nullifyingKey)
	if err != nil {
		return IndexedWallet{}, err
	}
	encodedAddress, err := address.Encode(address.AddressData{
		MasterPublicKey:  masterPublicKey.String(),
		ViewingPublicKey: viewingNode.Viewing.PublicKey,
		Version:          address.AddressVersion,
	})
	if err != nil {
		return IndexedWallet{}, err
	}
	return IndexedWallet{
		Mnemonic:          mnemonic,
		Index:             index,
		SpendingPublicKey: spendingNode.Spending.PublicKey,
		ViewingPublicKey:  viewingNode.Viewing.PublicKey,
		NullifyingKey:     viewingNode.NullifyingKey,
		MasterPublicKey:   masterPublicKey.String(),
		Address:           encodedAddress,
	}, nil
}

func Derive(node KeyNode, path string) (KeyNode, error) {
	segments, err := PathSegments(path)
	if err != nil {
		return KeyNode{}, err
	}
	out := node
	for _, segment := range segments {
		out, err = ChildKeyDerivationHardened(out, segment)
		if err != nil {
			return KeyNode{}, err
		}
	}
	return out, nil
}

func ChildKeyDerivationHardened(node KeyNode, index int) (KeyNode, error) {
	if index < 0 {
		return KeyNode{}, fmt.Errorf("index must be non-negative")
	}
	if index > 0x7fffffff {
		return KeyNode{}, fmt.Errorf("index exceeds hardened range")
	}
	indexFormatted := fmt.Sprintf("%08x", uint32(index+hardenedOffset))
	preimage := "00" + railcrypto.Strip0x(node.ChainKey) + indexFormatted
	chainCode, err := hex.DecodeString(railcrypto.Strip0x(node.ChainCode))
	if err != nil {
		return KeyNode{}, err
	}
	return hmacSHA512Node(chainCode, preimage)
}

func PathSegments(path string) ([]int, error) {
	if !derivationPathPattern.MatchString(path) {
		return nil, fmt.Errorf("invalid derivation path")
	}
	rawSegments := strings.Split(path, "/")[1:]
	segments := make([]int, len(rawSegments))
	for i, segment := range rawSegments {
		parsed, err := strconv.Atoi(strings.TrimSuffix(segment, "'"))
		if err != nil {
			return nil, fmt.Errorf("invalid derivation path")
		}
		segments[i] = parsed
	}
	return segments, nil
}

func BuildDerivedNode(node KeyNode) (DerivedNode, error) {
	privateKey, err := railcrypto.HexToBytes(node.ChainKey)
	if err != nil {
		return DerivedNode{}, err
	}
	spendingPublicKey, err := railcrypto.PublicSpendingKey(privateKey)
	if err != nil {
		return DerivedNode{}, err
	}
	viewingPublicKey, err := railcrypto.PublicViewingKey(privateKey)
	if err != nil {
		return DerivedNode{}, err
	}
	privateKeyBigInt, err := railcrypto.HexToBigInt(node.ChainKey)
	if err != nil {
		return DerivedNode{}, err
	}
	nullifyingKey, err := railcrypto.Poseidon(privateKeyBigInt)
	if err != nil {
		return DerivedNode{}, err
	}
	return DerivedNode{
		Node: node,
		Spending: SpendingKeyPair{
			PrivateKey: railcrypto.BytesToHex(privateKey, false),
			PublicKey:  [2]string{spendingPublicKey[0].String(), spendingPublicKey[1].String()},
		},
		Viewing: ViewingKeyPair{
			PrivateKey: railcrypto.BytesToHex(privateKey, false),
			PublicKey:  railcrypto.BytesToHex(viewingPublicKey, false),
		},
		NullifyingKey: nullifyingKey.String(),
	}, nil
}

func hmacSHA512Node(key []byte, dataHex string) (KeyNode, error) {
	data, err := hex.DecodeString(railcrypto.Strip0x(dataHex))
	if err != nil {
		return KeyNode{}, err
	}
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	sum := railcrypto.BytesToHex(mac.Sum(nil), false)
	return KeyNode{
		ChainKey:  sum[:64],
		ChainCode: sum[64:],
	}, nil
}

func derive0xKey(mnemonic string, derivationIndex uint32) (*bip32.Key, error) {
	seed := bip39.NewSeed(mnemonic, "")
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	path := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 60,
		bip32.FirstHardenedChild,
		0,
		derivationIndex,
	}
	for _, child := range path {
		key, err = key.NewChildKey(child)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func privateKeyBytesFromBIP32(key *bip32.Key) ([]byte, error) {
	if key == nil || !key.IsPrivate {
		return nil, fmt.Errorf("private BIP32 key is required")
	}
	privateKey := key.Key
	if len(privateKey) == 33 && privateKey[0] == 0 {
		privateKey = privateKey[1:]
	}
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("expected 32-byte private key, got %d", len(privateKey))
	}
	return append([]byte(nil), privateKey...), nil
}

func mustDecimalBigInt(value string) *big.Int {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic(value)
	}
	return n
}
