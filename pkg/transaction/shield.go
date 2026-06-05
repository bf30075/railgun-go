package transaction

import (
	"fmt"
	"math/big"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

type ShieldNoteInputs struct {
	MasterPublicKey          *big.Int
	Random                   string
	Value                    *big.Int
	TokenData                railcrypto.TokenData
	ShieldPrivateKey         []byte
	ReceiverViewingPublicKey []byte
	RandomGCMIV              string
	ReceiverCTRIV            string
}

func CreateShieldNoteRequest(inputs ShieldNoteInputs) (ShieldRequest, error) {
	if inputs.MasterPublicKey == nil {
		return ShieldRequest{}, fmt.Errorf("master public key is required")
	}
	if inputs.Value == nil {
		return ShieldRequest{}, fmt.Errorf("value is required")
	}
	random, err := railcrypto.FormatHexToByteLength(inputs.Random, 16, false)
	if err != nil {
		return ShieldRequest{}, fmt.Errorf("random: %w", err)
	}
	notePublicKey, err := railcrypto.NotePublicKey(inputs.MasterPublicKey, random)
	if err != nil {
		return ShieldRequest{}, err
	}
	sharedKey, err := railcrypto.SharedSymmetricKey(inputs.ShieldPrivateKey, inputs.ReceiverViewingPublicKey)
	if err != nil {
		return ShieldRequest{}, fmt.Errorf("shared symmetric key: %w", err)
	}
	encryptedRandom, err := railcrypto.AESGCMEncryptHex([]string{random}, railcrypto.BytesToHex(sharedKey, false), inputs.RandomGCMIV)
	if err != nil {
		return ShieldRequest{}, fmt.Errorf("encrypt random: %w", err)
	}
	receiverPlaintext := railcrypto.BytesToHex(inputs.ReceiverViewingPublicKey, false)
	encryptedReceiver, err := railcrypto.AESCTREncryptHex([]string{receiverPlaintext}, railcrypto.BytesToHex(inputs.ShieldPrivateKey, false), inputs.ReceiverCTRIV)
	if err != nil {
		return ShieldRequest{}, fmt.Errorf("encrypt receiver: %w", err)
	}
	shieldKey, err := railcrypto.PublicViewingKey(inputs.ShieldPrivateKey)
	if err != nil {
		return ShieldRequest{}, fmt.Errorf("shield key: %w", err)
	}
	notePublicKeyHex, err := railcrypto.BigIntToHex(notePublicKey, 32, true)
	if err != nil {
		return ShieldRequest{}, err
	}
	return ShieldRequest{
		Preimage: CommitmentPreimage{
			NPK:   notePublicKeyHex,
			Token: inputs.TokenData,
			Value: new(big.Int).Set(inputs.Value),
		},
		Ciphertext: ShieldCiphertext{
			EncryptedBundle: [3]string{
				railcrypto.Prefix0x(encryptedRandom.IV + encryptedRandom.Tag),
				railcrypto.Prefix0x(encryptedRandom.Data[0] + encryptedReceiver.IV),
				railcrypto.Prefix0x(encryptedReceiver.Data[0]),
			},
			ShieldKey: railcrypto.BytesToHex(shieldKey, true),
		},
	}, nil
}

func DecryptShieldRandom(encryptedBundle [3]string, sharedKey []byte) (string, error) {
	bundle0 := railcrypto.Strip0x(encryptedBundle[0])
	bundle1 := railcrypto.Strip0x(encryptedBundle[1])
	if len(bundle0) < 64 {
		return "", fmt.Errorf("encrypted bundle[0] must contain 16-byte IV and 16-byte tag")
	}
	if len(bundle1) < 32 {
		return "", fmt.Errorf("encrypted bundle[1] must contain encrypted random")
	}
	decrypted, err := railcrypto.AESGCMDecryptHex(
		railcrypto.CiphertextGCM{
			IV:   bundle0[:32],
			Tag:  bundle0[32:64],
			Data: []string{bundle1[:32]},
		},
		railcrypto.BytesToHex(sharedKey, false),
	)
	if err != nil {
		return "", err
	}
	if len(decrypted) != 1 {
		return "", fmt.Errorf("expected one decrypted random field, got %d", len(decrypted))
	}
	return decrypted[0], nil
}
