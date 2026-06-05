package transaction

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

type EIP1559TxRequest struct {
	ChainID   *big.Int
	Nonce     uint64
	To        string
	Value     *big.Int
	GasLimit  uint64
	GasFeeCap *big.Int
	GasTipCap *big.Int
	Data      string
}

type SignedTransaction struct {
	Raw  string
	Hash string
	From string
}

func SignEIP1559Transaction(privateKeyHex string, request EIP1559TxRequest) (SignedTransaction, error) {
	if request.ChainID == nil || request.ChainID.Sign() <= 0 {
		return SignedTransaction{}, fmt.Errorf("chainID must be positive")
	}
	if !common.IsHexAddress(request.To) {
		return SignedTransaction{}, fmt.Errorf("invalid to address")
	}
	data, err := railcrypto.HexToBytes(request.Data)
	if err != nil {
		return SignedTransaction{}, fmt.Errorf("data: %w", err)
	}
	privateKey, err := ecdsaPrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return SignedTransaction{}, fmt.Errorf("private key: %w", err)
	}

	to := common.HexToAddress(request.To)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   cloneBigInt(request.ChainID),
		Nonce:     request.Nonce,
		GasTipCap: bigIntOrZero(request.GasTipCap),
		GasFeeCap: bigIntOrZero(request.GasFeeCap),
		Gas:       request.GasLimit,
		To:        &to,
		Value:     bigIntOrZero(request.Value),
		Data:      data,
	})
	signer := types.LatestSignerForChainID(request.ChainID)
	signed, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return SignedTransaction{}, err
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return SignedTransaction{}, err
	}
	from, err := types.Sender(signer, signed)
	if err != nil {
		return SignedTransaction{}, err
	}
	return SignedTransaction{
		Raw:  railcrypto.BytesToHex(raw, true),
		Hash: signed.Hash().Hex(),
		From: from.Hex(),
	}, nil
}

func AddressFromPrivateKey(privateKeyHex string) (string, error) {
	privateKey, err := ecdsaPrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	return ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex(), nil
}

func ecdsaPrivateKeyFromHex(privateKeyHex string) (*ecdsa.PrivateKey, error) {
	return ethcrypto.HexToECDSA(railcrypto.Strip0x(privateKeyHex))
}
