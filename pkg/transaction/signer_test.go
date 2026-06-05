package transaction

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestSignEIP1559TransactionRoundTrip(t *testing.T) {
	privateKey := "0000000000000000000000000000000000000000000000000000000000000001"
	request := EIP1559TxRequest{
		ChainID:   big.NewInt(31337),
		Nonce:     7,
		To:        "0x1111111111111111111111111111111111111111",
		Value:     big.NewInt(12345),
		GasLimit:  25000,
		GasFeeCap: big.NewInt(50_000_000_000),
		GasTipCap: big.NewInt(2_000_000_000),
		Data:      "0xabcdef",
	}

	signed, err := SignEIP1559Transaction(privateKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(signed.Raw, "0x02") {
		t.Fatalf("expected typed transaction raw bytes, got %s", signed.Raw[:4])
	}
	if signed.From != "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf" {
		t.Fatalf("expected signer address, got %s", signed.From)
	}

	raw, err := railcrypto.HexToBytes(signed.Raw)
	if err != nil {
		t.Fatal(err)
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if tx.Type() != types.DynamicFeeTxType {
		t.Fatalf("expected EIP-1559 transaction type, got %d", tx.Type())
	}
	if tx.Hash().Hex() != signed.Hash {
		t.Fatalf("expected hash %s, got %s", tx.Hash().Hex(), signed.Hash)
	}
	signer := types.LatestSignerForChainID(request.ChainID)
	from, err := types.Sender(signer, &tx)
	if err != nil {
		t.Fatal(err)
	}
	if from.Hex() != signed.From {
		t.Fatalf("expected recovered sender %s, got %s", signed.From, from.Hex())
	}
	if tx.Nonce() != request.Nonce {
		t.Fatalf("expected nonce %d, got %d", request.Nonce, tx.Nonce())
	}
	if tx.To() == nil || *tx.To() != common.HexToAddress(request.To) {
		t.Fatalf("expected to address %s, got %v", request.To, tx.To())
	}
	if tx.Value().Cmp(request.Value) != 0 {
		t.Fatalf("expected value %s, got %s", request.Value, tx.Value())
	}
	if tx.Gas() != request.GasLimit {
		t.Fatalf("expected gas limit %d, got %d", request.GasLimit, tx.Gas())
	}
	if tx.GasFeeCap().Cmp(request.GasFeeCap) != 0 {
		t.Fatalf("expected gas fee cap %s, got %s", request.GasFeeCap, tx.GasFeeCap())
	}
	if tx.GasTipCap().Cmp(request.GasTipCap) != 0 {
		t.Fatalf("expected gas tip cap %s, got %s", request.GasTipCap, tx.GasTipCap())
	}
	if !bytes.Equal(tx.Data(), []byte{0xab, 0xcd, 0xef}) {
		t.Fatalf("expected calldata abcdef, got %x", tx.Data())
	}
}

func TestSignEIP1559TransactionRejectsInvalidInputs(t *testing.T) {
	privateKey := "0000000000000000000000000000000000000000000000000000000000000001"
	_, err := SignEIP1559Transaction(privateKey, EIP1559TxRequest{
		ChainID: big.NewInt(1),
		To:      "not-an-address",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid to address") {
		t.Fatalf("expected invalid address error, got %v", err)
	}

	_, err = SignEIP1559Transaction(privateKey, EIP1559TxRequest{
		To: "0x1111111111111111111111111111111111111111",
	})
	if err == nil || !strings.Contains(err.Error(), "chainID") {
		t.Fatalf("expected chainID error, got %v", err)
	}
}
