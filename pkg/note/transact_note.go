package note

import (
	"fmt"
	"math/big"

	"github.com/bf30075/railgun-go/pkg/address"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

type TransactNote struct {
	ReceiverAddressData address.AddressData
	SenderAddressData   *address.AddressData
	TokenHash           string
	TokenData           railcrypto.TokenData
	Random              string
	Value               *big.Int
	NotePublicKey       *big.Int
	Hash                *big.Int
	OutputType          *int
	WalletSource        *string
	SenderRandom        *string
	MemoText            *string
	ShieldFee           *string
	BlockNumber         *uint64
}

type SerializedTransactNote struct {
	NPK              string  `json:"npk"`
	Value            string  `json:"value"`
	TokenHash        string  `json:"tokenHash"`
	Random           string  `json:"random"`
	RecipientAddress string  `json:"recipientAddress"`
	OutputType       *int    `json:"outputType,omitempty"`
	SenderRandom     *string `json:"senderRandom,omitempty"`
	WalletSource     *string `json:"walletSource,omitempty"`
	SenderAddress    *string `json:"senderAddress,omitempty"`
	MemoText         *string `json:"memoText,omitempty"`
	ShieldFee        *string `json:"shieldFee,omitempty"`
	BlockNumber      *uint64 `json:"blockNumber,omitempty"`
}

func NewTransactNote(
	receiverAddressData address.AddressData,
	senderAddressData *address.AddressData,
	random string,
	value *big.Int,
	tokenData railcrypto.TokenData,
	outputType *int,
	walletSource *string,
	senderRandom *string,
	memoText *string,
	shieldFee *string,
	blockNumber *uint64,
) (TransactNote, error) {
	if _, err := railcrypto.FormatHexToByteLength(random, 16, false); err != nil {
		return TransactNote{}, fmt.Errorf("random: %w", err)
	}
	if value == nil {
		return TransactNote{}, fmt.Errorf("value is required")
	}
	tokenHash, err := railcrypto.TokenDataHash(tokenData)
	if err != nil {
		return TransactNote{}, err
	}
	mpk, err := railcrypto.NumberishToBigInt(receiverAddressData.MasterPublicKey)
	if err != nil {
		return TransactNote{}, fmt.Errorf("receiver master public key: %w", err)
	}
	notePublicKey, err := railcrypto.NotePublicKey(mpk, random)
	if err != nil {
		return TransactNote{}, err
	}
	hash, err := railcrypto.NoteHash(notePublicKey, tokenHash, value)
	if err != nil {
		return TransactNote{}, err
	}
	return TransactNote{
		ReceiverAddressData: cloneAddressData(receiverAddressData),
		SenderAddressData:   cloneAddressDataPtr(senderAddressData),
		TokenHash:           tokenHash,
		TokenData:           tokenData,
		Random:              random,
		Value:               new(big.Int).Set(value),
		NotePublicKey:       notePublicKey,
		Hash:                hash,
		OutputType:          cloneIntPtr(outputType),
		WalletSource:        cloneStringPtr(walletSource),
		SenderRandom:        cloneStringPtr(senderRandom),
		MemoText:            cloneStringPtr(memoText),
		ShieldFee:           cloneStringPtr(shieldFee),
		BlockNumber:         cloneUint64Ptr(blockNumber),
	}, nil
}

func FromDecrypted(decrypted railcrypto.DecryptedTransactNote, chain *address.Chain) (TransactNote, error) {
	receiverAddressData, err := addressDataFromCrypto(decrypted.ReceiverAddressData, chain)
	if err != nil {
		return TransactNote{}, err
	}
	var senderAddressData *address.AddressData
	if decrypted.SenderAddressData != nil {
		sender, err := addressDataFromCrypto(*decrypted.SenderAddressData, chain)
		if err != nil {
			return TransactNote{}, err
		}
		senderAddressData = &sender
	}
	return NewTransactNote(
		receiverAddressData,
		senderAddressData,
		decrypted.Random,
		decrypted.Value,
		decrypted.TokenData,
		decrypted.OutputType,
		stringPtrIfNotEmpty(decrypted.WalletSource),
		stringPtrIfNotEmpty(decrypted.SenderRandom),
		stringPtrIfNotEmpty(decrypted.MemoText),
		nil,
		decrypted.BlockNumber,
	)
}

func Deserialize(serialized SerializedTransactNote, tokenDataByHash map[string]railcrypto.TokenData) (TransactNote, error) {
	receiverAddressData, err := address.Decode(serialized.RecipientAddress)
	if err != nil {
		return TransactNote{}, fmt.Errorf("recipient address: %w", err)
	}
	var senderAddressData *address.AddressData
	if serialized.SenderAddress != nil {
		sender, err := address.Decode(*serialized.SenderAddress)
		if err != nil {
			return TransactNote{}, fmt.Errorf("sender address: %w", err)
		}
		senderAddressData = &sender
	}
	tokenData, err := railcrypto.TokenDataFromHash(serialized.TokenHash, tokenDataByHash)
	if err != nil {
		return TransactNote{}, err
	}
	value, err := railcrypto.HexToBigInt(serialized.Value)
	if err != nil {
		return TransactNote{}, fmt.Errorf("value: %w", err)
	}
	return NewTransactNote(
		receiverAddressData,
		senderAddressData,
		serialized.Random,
		value,
		tokenData,
		serialized.OutputType,
		serialized.WalletSource,
		serialized.SenderRandom,
		serialized.MemoText,
		serialized.ShieldFee,
		serialized.BlockNumber,
	)
}

func (n TransactNote) Serialize(prefix bool) (SerializedTransactNote, error) {
	npk, err := railcrypto.BigIntToHex(n.NotePublicKey, 32, prefix)
	if err != nil {
		return SerializedTransactNote{}, err
	}
	value, err := railcrypto.BigIntToHex(n.Value, 16, prefix)
	if err != nil {
		return SerializedTransactNote{}, err
	}
	tokenHash, err := railcrypto.FormatHexToByteLength(n.TokenHash, 32, prefix)
	if err != nil {
		return SerializedTransactNote{}, err
	}
	random, err := railcrypto.FormatHexToByteLength(n.Random, 16, prefix)
	if err != nil {
		return SerializedTransactNote{}, err
	}
	recipientAddress, err := address.Encode(n.ReceiverAddressData)
	if err != nil {
		return SerializedTransactNote{}, fmt.Errorf("recipient address: %w", err)
	}
	var senderAddress *string
	if n.SenderAddressData != nil {
		encoded, err := address.Encode(*n.SenderAddressData)
		if err != nil {
			return SerializedTransactNote{}, fmt.Errorf("sender address: %w", err)
		}
		senderAddress = &encoded
	}
	return SerializedTransactNote{
		NPK:              npk,
		Value:            value,
		TokenHash:        tokenHash,
		Random:           random,
		RecipientAddress: recipientAddress,
		OutputType:       cloneIntPtr(n.OutputType),
		SenderRandom:     cloneStringPtr(n.SenderRandom),
		WalletSource:     cloneStringPtr(n.WalletSource),
		SenderAddress:    cloneStringPtr(senderAddress),
		MemoText:         cloneStringPtr(n.MemoText),
		ShieldFee:        cloneStringPtr(n.ShieldFee),
		BlockNumber:      cloneUint64Ptr(n.BlockNumber),
	}, nil
}

func addressDataFromCrypto(value railcrypto.TransactNoteAddressData, chain *address.Chain) (address.AddressData, error) {
	if value.MasterPublicKey == nil {
		return address.AddressData{}, fmt.Errorf("master public key is required")
	}
	viewingPublicKey, err := railcrypto.FormatHexToByteLength(railcrypto.BytesToHex(value.ViewingPublicKey, false), 32, false)
	if err != nil {
		return address.AddressData{}, fmt.Errorf("viewing public key: %w", err)
	}
	return address.AddressData{
		MasterPublicKey:  value.MasterPublicKey.String(),
		ViewingPublicKey: viewingPublicKey,
		Chain:            chain,
		Version:          address.AddressVersion,
	}, nil
}

func cloneAddressData(value address.AddressData) address.AddressData {
	cloned := value
	if value.Chain != nil {
		chain := *value.Chain
		cloned.Chain = &chain
	}
	return cloned
}

func cloneAddressDataPtr(value *address.AddressData) *address.AddressData {
	if value == nil {
		return nil
	}
	cloned := cloneAddressData(*value)
	return &cloned
}

func cloneStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func stringPtrIfNotEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func cloneIntPtr(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneUint64Ptr(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
