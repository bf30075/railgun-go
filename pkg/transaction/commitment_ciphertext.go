package transaction

import (
	"fmt"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func CreateCommitmentCiphertextV2(encrypted railcrypto.TransactNoteV2Encryption, blindedSenderViewingKey []byte, blindedReceiverViewingKey []byte) (CommitmentCiphertextV2, error) {
	if len(encrypted.NoteCiphertext.Data) != 3 {
		return CommitmentCiphertextV2{}, fmt.Errorf("V2 note ciphertext data must have length 3")
	}
	ciphertext := [4][32]byte{}
	var err error
	ciphertext[0], err = Bytes32FromHex(encrypted.NoteCiphertext.IV + encrypted.NoteCiphertext.Tag)
	if err != nil {
		return CommitmentCiphertextV2{}, fmt.Errorf("ciphertext[0]: %w", err)
	}
	for i, data := range encrypted.NoteCiphertext.Data {
		ciphertext[i+1], err = Bytes32FromHex(data)
		if err != nil {
			return CommitmentCiphertextV2{}, fmt.Errorf("ciphertext[%d]: %w", i+1, err)
		}
	}
	blindedSender, err := Bytes32FromHex(railcrypto.BytesToHex(blindedSenderViewingKey, false))
	if err != nil {
		return CommitmentCiphertextV2{}, fmt.Errorf("blinded sender viewing key: %w", err)
	}
	blindedReceiver, err := Bytes32FromHex(railcrypto.BytesToHex(blindedReceiverViewingKey, false))
	if err != nil {
		return CommitmentCiphertextV2{}, fmt.Errorf("blinded receiver viewing key: %w", err)
	}
	memo, err := DynamicBytesFromHex(encrypted.NoteMemo)
	if err != nil {
		return CommitmentCiphertextV2{}, fmt.Errorf("memo: %w", err)
	}
	annotationData, err := DynamicBytesFromHex(encrypted.AnnotationData)
	if err != nil {
		return CommitmentCiphertextV2{}, fmt.Errorf("annotation data: %w", err)
	}
	return CommitmentCiphertextV2{
		Ciphertext:                ciphertext,
		BlindedSenderViewingKey:   blindedSender,
		BlindedReceiverViewingKey: blindedReceiver,
		AnnotationData:            annotationData,
		Memo:                      memo,
	}, nil
}

func CreateCommitmentCiphertextV3(encrypted railcrypto.TransactNoteV3Encryption, blindedSenderViewingKey []byte, blindedReceiverViewingKey []byte) (CommitmentCiphertextV3, error) {
	ciphertext, err := DynamicBytesFromHex(encrypted.NoteCiphertext.Nonce + encrypted.NoteCiphertext.Bundle)
	if err != nil {
		return CommitmentCiphertextV3{}, fmt.Errorf("ciphertext: %w", err)
	}
	blindedSender, err := Bytes32FromHex(railcrypto.BytesToHex(blindedSenderViewingKey, false))
	if err != nil {
		return CommitmentCiphertextV3{}, fmt.Errorf("blinded sender viewing key: %w", err)
	}
	blindedReceiver, err := Bytes32FromHex(railcrypto.BytesToHex(blindedReceiverViewingKey, false))
	if err != nil {
		return CommitmentCiphertextV3{}, fmt.Errorf("blinded receiver viewing key: %w", err)
	}
	return CommitmentCiphertextV3{
		Ciphertext:                ciphertext,
		BlindedSenderViewingKey:   blindedSender,
		BlindedReceiverViewingKey: blindedReceiver,
	}, nil
}
