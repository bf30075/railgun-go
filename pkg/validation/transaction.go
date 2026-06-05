package validation

import (
	"fmt"
	"math/big"
	"strings"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
	railtx "github.com/bf30075/railgun-go/pkg/transaction"
	"github.com/bf30075/railgun-go/pkg/txid"
)

type ContractTransactionRequest struct {
	To   string
	Data string
}

type ReceiverViewingData struct {
	MasterPublicKey   *big.Int
	ViewingPublicKey  []byte
	ViewingPrivateKey []byte
}

type ExtractedRailgunTransactionData struct {
	RailgunTxid                  string
	UTXOTreeIn                   *big.Int
	FirstCommitment              string
	FirstCommitmentNotePublicKey *big.Int
}

func ExtractRailgunTransactionDataFromTransactV2Calldata(
	request ContractTransactionRequest,
	contractAddress string,
	receiver ReceiverViewingData,
	tokenDataByHash map[string]railcrypto.TokenData,
) ([]ExtractedRailgunTransactionData, error) {
	if err := validateContractAddress(request.To, contractAddress); err != nil {
		return nil, err
	}
	txs, err := railtx.DecodeTransactV2Calldata(request.Data)
	if err != nil {
		return nil, err
	}
	return ExtractRailgunTransactionDataV2(txs, receiver, tokenDataByHash)
}

func ExtractRailgunTransactionDataFromRelayAdaptV2Calldata(
	request ContractTransactionRequest,
	contractAddress string,
	receiver ReceiverViewingData,
	tokenDataByHash map[string]railcrypto.TokenData,
) ([]ExtractedRailgunTransactionData, error) {
	if err := validateContractAddress(request.To, contractAddress); err != nil {
		return nil, err
	}
	txs, _, err := railtx.DecodeRelayAdaptV2Calldata(request.Data)
	if err != nil {
		return nil, err
	}
	return ExtractRailgunTransactionDataV2(txs, receiver, tokenDataByHash)
}

func ExtractRailgunTransactionDataFromExecuteV3Calldata(
	request ContractTransactionRequest,
	contractAddress string,
	receiver ReceiverViewingData,
	tokenDataByHash map[string]railcrypto.TokenData,
) ([]ExtractedRailgunTransactionData, error) {
	if err := validateContractAddress(request.To, contractAddress); err != nil {
		return nil, err
	}
	txs, _, err := railtx.DecodeExecuteV3TransactCalldata(request.Data)
	if err != nil {
		return nil, err
	}
	return ExtractRailgunTransactionDataV3(txs, receiver, tokenDataByHash)
}

func ExtractFirstNoteERC20AmountMapFromTransactV2Calldata(
	request ContractTransactionRequest,
	contractAddress string,
	receiver ReceiverViewingData,
	tokenDataByHash map[string]railcrypto.TokenData,
) (map[string]*big.Int, error) {
	if err := validateContractAddress(request.To, contractAddress); err != nil {
		return nil, err
	}
	txs, err := railtx.DecodeTransactV2Calldata(request.Data)
	if err != nil {
		return nil, err
	}
	return ExtractFirstNoteERC20AmountMapV2(txs, receiver, tokenDataByHash), nil
}

func ExtractFirstNoteERC20AmountMapFromRelayAdaptV2Calldata(
	request ContractTransactionRequest,
	contractAddress string,
	receiver ReceiverViewingData,
	tokenDataByHash map[string]railcrypto.TokenData,
) (map[string]*big.Int, error) {
	if err := validateContractAddress(request.To, contractAddress); err != nil {
		return nil, err
	}
	txs, _, err := railtx.DecodeRelayAdaptV2Calldata(request.Data)
	if err != nil {
		return nil, err
	}
	return ExtractFirstNoteERC20AmountMapV2(txs, receiver, tokenDataByHash), nil
}

func ExtractFirstNoteERC20AmountMapFromExecuteV3Calldata(
	request ContractTransactionRequest,
	contractAddress string,
	receiver ReceiverViewingData,
	tokenDataByHash map[string]railcrypto.TokenData,
) (map[string]*big.Int, error) {
	if err := validateContractAddress(request.To, contractAddress); err != nil {
		return nil, err
	}
	txs, _, err := railtx.DecodeExecuteV3TransactCalldata(request.Data)
	if err != nil {
		return nil, err
	}
	return ExtractFirstNoteERC20AmountMapV3(txs, receiver, tokenDataByHash), nil
}

func ExtractRailgunTransactionDataV2(txs []railtx.TransactionStructV2, receiver ReceiverViewingData, tokenDataByHash map[string]railcrypto.TokenData) ([]ExtractedRailgunTransactionData, error) {
	out := make([]ExtractedRailgunTransactionData, len(txs))
	for i, tx := range txs {
		boundParamsHash, err := railtx.HashBoundParamsV2Hex(tx.BoundParams, true)
		if err != nil {
			return nil, err
		}
		railgunTxid, err := txid.RailgunTransactionIDHex(tx.Nullifiers, tx.Commitments, boundParamsHash)
		if err != nil {
			return nil, err
		}
		firstCommitment, err := firstCommitment(tx.Commitments)
		if err != nil {
			return nil, err
		}
		var npk *big.Int
		if i == 0 {
			npk = extractNPKV2Safe(tx, receiver, tokenDataByHash)
		}
		out[i] = ExtractedRailgunTransactionData{
			RailgunTxid:                  railgunTxid,
			UTXOTreeIn:                   new(big.Int).SetUint64(uint64(tx.BoundParams.TreeNumber)),
			FirstCommitment:              firstCommitment,
			FirstCommitmentNotePublicKey: npk,
		}
	}
	return out, nil
}

func ExtractRailgunTransactionDataV3(txs []railtx.TransactionStructV3, receiver ReceiverViewingData, tokenDataByHash map[string]railcrypto.TokenData) ([]ExtractedRailgunTransactionData, error) {
	out := make([]ExtractedRailgunTransactionData, len(txs))
	for i, tx := range txs {
		boundParamsHash, err := railtx.HashBoundParamsV3Hex(tx.BoundParams, true)
		if err != nil {
			return nil, err
		}
		railgunTxid, err := txid.RailgunTransactionIDHex(tx.Nullifiers, tx.Commitments, boundParamsHash)
		if err != nil {
			return nil, err
		}
		firstCommitment, err := firstCommitment(tx.Commitments)
		if err != nil {
			return nil, err
		}
		var npk *big.Int
		if i == 0 {
			npk = extractNPKV3Safe(tx, receiver, tokenDataByHash)
		}
		out[i] = ExtractedRailgunTransactionData{
			RailgunTxid:                  railgunTxid,
			UTXOTreeIn:                   new(big.Int).SetUint64(uint64(tx.BoundParams.Local.TreeNumber)),
			FirstCommitment:              firstCommitment,
			FirstCommitmentNotePublicKey: npk,
		}
	}
	return out, nil
}

func ExtractFirstNoteERC20AmountMapV2(txs []railtx.TransactionStructV2, receiver ReceiverViewingData, tokenDataByHash map[string]railcrypto.TokenData) map[string]*big.Int {
	out := map[string]*big.Int{}
	for _, tx := range txs {
		note, err := decryptFirstNoteV2(tx, receiver, tokenDataByHash)
		if err != nil {
			continue
		}
		addERC20Amount(out, note, tx.Commitments[0], receiver)
	}
	return out
}

func ExtractFirstNoteERC20AmountMapV3(txs []railtx.TransactionStructV3, receiver ReceiverViewingData, tokenDataByHash map[string]railcrypto.TokenData) map[string]*big.Int {
	out := map[string]*big.Int{}
	for _, tx := range txs {
		note, err := decryptFirstNoteV3(tx, receiver, tokenDataByHash)
		if err != nil {
			continue
		}
		addERC20Amount(out, note, tx.Commitments[0], receiver)
	}
	return out
}

func extractNPKV2Safe(tx railtx.TransactionStructV2, receiver ReceiverViewingData, tokenDataByHash map[string]railcrypto.TokenData) *big.Int {
	note, err := decryptFirstNoteV2(tx, receiver, tokenDataByHash)
	if err != nil {
		return nil
	}
	return note.NotePublicKey
}

func extractNPKV3Safe(tx railtx.TransactionStructV3, receiver ReceiverViewingData, tokenDataByHash map[string]railcrypto.TokenData) *big.Int {
	note, err := decryptFirstNoteV3(tx, receiver, tokenDataByHash)
	if err != nil {
		return nil
	}
	return note.NotePublicKey
}

func decryptFirstNoteV2(tx railtx.TransactionStructV2, receiver ReceiverViewingData, tokenDataByHash map[string]railcrypto.TokenData) (railcrypto.DecryptedTransactNote, error) {
	if len(tx.BoundParams.CommitmentCiphertext) == 0 {
		return railcrypto.DecryptedTransactNote{}, fmt.Errorf("no ciphertext found for commitment at index 0")
	}
	ciphertext := tx.BoundParams.CommitmentCiphertext[0].Native()
	ivAndTag := railcrypto.Strip0x(ciphertext.Ciphertext[0])
	if len(ivAndTag) != 64 {
		return railcrypto.DecryptedTransactNote{}, fmt.Errorf("invalid V2 iv/tag length")
	}
	blindedSenderViewingKey, err := railcrypto.HexToBytes(ciphertext.BlindedSenderViewingKey)
	if err != nil {
		return railcrypto.DecryptedTransactNote{}, err
	}
	blindedReceiverViewingKey, err := railcrypto.HexToBytes(ciphertext.BlindedReceiverViewingKey)
	if err != nil {
		return railcrypto.DecryptedTransactNote{}, err
	}
	sharedKey, err := railcrypto.SharedSymmetricKey(receiver.ViewingPrivateKey, blindedSenderViewingKey)
	if err != nil {
		return railcrypto.DecryptedTransactNote{}, err
	}
	return railcrypto.DecryptTransactNoteV2(
		receiverAddressData(receiver),
		railcrypto.CiphertextGCM{
			IV:  ivAndTag[:32],
			Tag: ivAndTag[32:],
			Data: []string{
				ciphertext.Ciphertext[1],
				ciphertext.Ciphertext[2],
				ciphertext.Ciphertext[3],
			},
		},
		sharedKey,
		ciphertext.Memo,
		ciphertext.AnnotationData,
		receiver.ViewingPrivateKey,
		blindedReceiverViewingKey,
		blindedSenderViewingKey,
		false,
		false,
		tokenDataByHash,
		nil,
	)
}

func decryptFirstNoteV3(tx railtx.TransactionStructV3, receiver ReceiverViewingData, tokenDataByHash map[string]railcrypto.TokenData) (railcrypto.DecryptedTransactNote, error) {
	if len(tx.BoundParams.Local.CommitmentCiphertext) == 0 {
		return railcrypto.DecryptedTransactNote{}, fmt.Errorf("no ciphertext found for commitment at index 0")
	}
	ciphertext := tx.BoundParams.Local.CommitmentCiphertext[0].Native()
	combined := railcrypto.Strip0x(ciphertext.Ciphertext)
	if len(combined) < 32 {
		return railcrypto.DecryptedTransactNote{}, fmt.Errorf("invalid V3 ciphertext length")
	}
	blindedSenderViewingKey, err := railcrypto.HexToBytes(ciphertext.BlindedSenderViewingKey)
	if err != nil {
		return railcrypto.DecryptedTransactNote{}, err
	}
	blindedReceiverViewingKey, err := railcrypto.HexToBytes(ciphertext.BlindedReceiverViewingKey)
	if err != nil {
		return railcrypto.DecryptedTransactNote{}, err
	}
	sharedKey, err := railcrypto.SharedSymmetricKey(receiver.ViewingPrivateKey, blindedSenderViewingKey)
	if err != nil {
		return railcrypto.DecryptedTransactNote{}, err
	}
	return railcrypto.DecryptTransactNoteV3(
		receiverAddressData(receiver),
		railcrypto.CiphertextXChaCha{
			Algorithm: railcrypto.XChaChaPoly1305EncryptionAlgorithm,
			Nonce:     combined[:32],
			Bundle:    combined[32:],
		},
		sharedKey,
		"",
		receiver.ViewingPrivateKey,
		blindedReceiverViewingKey,
		blindedSenderViewingKey,
		false,
		false,
		tokenDataByHash,
		nil,
		0,
	)
}

func addERC20Amount(out map[string]*big.Int, note railcrypto.DecryptedTransactNote, commitmentHash string, receiver ReceiverViewingData) {
	if note.ReceiverAddressData.MasterPublicKey.Cmp(receiver.MasterPublicKey) != 0 {
		return
	}
	noteHash, err := railcrypto.BigIntToHex(note.Hash, 32, false)
	if err != nil {
		return
	}
	commitment, err := railcrypto.FormatHexToByteLength(commitmentHash, 32, false)
	if err != nil {
		return
	}
	if noteHash != commitment || note.TokenData.TokenType != railcrypto.TokenTypeERC20 {
		return
	}
	tokenAddress, err := railcrypto.FormatHexToByteLength(note.TokenData.TokenAddress, 20, true)
	if err != nil {
		return
	}
	tokenAddress = strings.ToLower(tokenAddress)
	if out[tokenAddress] == nil {
		out[tokenAddress] = big.NewInt(0)
	}
	out[tokenAddress].Add(out[tokenAddress], note.Value)
}

func receiverAddressData(receiver ReceiverViewingData) railcrypto.TransactNoteAddressData {
	return railcrypto.TransactNoteAddressData{
		MasterPublicKey:  new(big.Int).Set(receiver.MasterPublicKey),
		ViewingPublicKey: append([]byte(nil), receiver.ViewingPublicKey...),
	}
}

func firstCommitment(commitments []string) (string, error) {
	if len(commitments) == 0 {
		return "", fmt.Errorf("no commitment found at index 0")
	}
	return commitments[0], nil
}

func validateContractAddress(got string, expected string) error {
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("invalid contract address: got %s, expected %s", got, expected)
	}
	return nil
}
