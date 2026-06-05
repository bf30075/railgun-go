package note

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestTransactNoteSerializeDeserializeMatchesTypeScript(t *testing.T) {
	fixture := loadTransactNoteFixtures(t)
	sharedKey, err := railcrypto.HexToBytes(fixture.Inputs.SharedKey)
	if err != nil {
		t.Fatal(err)
	}
	viewingPrivateKey, err := railcrypto.HexToBytes(fixture.Inputs.ViewingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	receiverViewingPublicKey, err := railcrypto.HexToBytes(fixture.Inputs.ReceiverViewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	senderViewingPublicKey, err := railcrypto.HexToBytes(fixture.Inputs.SenderViewingPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	blindedSenderViewingKey, err := railcrypto.HexToBytes(fixture.NoteBlinding.BlindedSenderViewingKey)
	if err != nil {
		t.Fatal(err)
	}
	blindedReceiverViewingKey, err := railcrypto.HexToBytes(fixture.NoteBlinding.BlindedReceiverViewingKey)
	if err != nil {
		t.Fatal(err)
	}
	receiverAddressData := railcrypto.TransactNoteAddressData{
		MasterPublicKey:  mustDec(t, fixture.Inputs.ReceiverMasterPublicKey),
		ViewingPublicKey: receiverViewingPublicKey,
	}
	senderAddressData := railcrypto.TransactNoteAddressData{
		MasterPublicKey:  mustDec(t, fixture.Inputs.SenderMasterPublicKey),
		ViewingPublicKey: senderViewingPublicKey,
	}

	tests := []struct {
		name     string
		decrypt  func() (railcrypto.DecryptedTransactNote, error)
		expected SerializedTransactNote
	}{
		{
			name: "v2 sent",
			decrypt: func() (railcrypto.DecryptedTransactNote, error) {
				return railcrypto.DecryptTransactNoteV2(
					senderAddressData,
					fixture.V2.NoteCiphertext,
					sharedKey,
					fixture.V2.NoteMemo,
					fixture.V2.AnnotationData,
					viewingPrivateKey,
					blindedReceiverViewingKey,
					blindedSenderViewingKey,
					true,
					false,
					nil,
					nil,
				)
			},
			expected: fixture.Decrypted.V2Sent.Serialized,
		},
		{
			name: "v2 received",
			decrypt: func() (railcrypto.DecryptedTransactNote, error) {
				return railcrypto.DecryptTransactNoteV2(
					receiverAddressData,
					fixture.V2.NoteCiphertext,
					sharedKey,
					fixture.V2.NoteMemo,
					fixture.V2.AnnotationData,
					viewingPrivateKey,
					blindedReceiverViewingKey,
					blindedSenderViewingKey,
					false,
					false,
					nil,
					nil,
				)
			},
			expected: fixture.Decrypted.V2Received.Serialized,
		},
		{
			name: "v3 sent",
			decrypt: func() (railcrypto.DecryptedTransactNote, error) {
				return railcrypto.DecryptTransactNoteV3(
					senderAddressData,
					fixture.V3.NoteCiphertext,
					sharedKey,
					fixture.V3.AnnotationData,
					viewingPrivateKey,
					blindedReceiverViewingKey,
					blindedSenderViewingKey,
					true,
					false,
					nil,
					nil,
					0,
				)
			},
			expected: fixture.Decrypted.V3Sent.Serialized,
		},
		{
			name: "v3 received",
			decrypt: func() (railcrypto.DecryptedTransactNote, error) {
				return railcrypto.DecryptTransactNoteV3(
					receiverAddressData,
					fixture.V3.NoteCiphertext,
					sharedKey,
					fixture.V3.AnnotationData,
					viewingPrivateKey,
					blindedReceiverViewingKey,
					blindedSenderViewingKey,
					false,
					false,
					nil,
					nil,
					0,
				)
			},
			expected: fixture.Decrypted.V3Received.Serialized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decrypted, err := test.decrypt()
			if err != nil {
				t.Fatal(err)
			}
			transactNote, err := FromDecrypted(decrypted, nil)
			if err != nil {
				t.Fatal(err)
			}
			serialized, err := transactNote.Serialize(false)
			if err != nil {
				t.Fatal(err)
			}
			if gotJSON, expectedJSON := mustJSON(t, serialized), mustJSON(t, test.expected); gotJSON != expectedJSON {
				t.Fatalf("expected serialized note %s, got %s", expectedJSON, gotJSON)
			}
			deserialized, err := Deserialize(serialized, nil)
			if err != nil {
				t.Fatal(err)
			}
			reserialized, err := deserialized.Serialize(false)
			if err != nil {
				t.Fatal(err)
			}
			if gotJSON, expectedJSON := mustJSON(t, reserialized), mustJSON(t, test.expected); gotJSON != expectedJSON {
				t.Fatalf("expected reserialized note %s, got %s", expectedJSON, gotJSON)
			}
		})
	}
}

func mustDec(t *testing.T, value string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid decimal %s", value)
	}
	return n
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

type exportedFixtures struct {
	TransactNoteFixtures transactNoteFixtureSet `json:"transactNoteFixtures"`
}

type transactNoteFixtureSet struct {
	Inputs       transactNoteInputsFixture           `json:"inputs"`
	V2           railcrypto.TransactNoteV2Encryption `json:"v2"`
	V3           railcrypto.TransactNoteV3Encryption `json:"v3"`
	NoteBlinding transactNoteBlindingFixture         `json:"noteBlinding"`
	Decrypted    transactNoteDecryptedFixtures       `json:"decrypted"`
}

type transactNoteInputsFixture struct {
	ReceiverMasterPublicKey  string               `json:"receiverMasterPublicKey"`
	SenderMasterPublicKey    string               `json:"senderMasterPublicKey"`
	ReceiverViewingPublicKey string               `json:"receiverViewingPublicKey"`
	SenderViewingPublicKey   string               `json:"senderViewingPublicKey"`
	TokenData                railcrypto.TokenData `json:"tokenData"`
	Random                   string               `json:"random"`
	Value                    string               `json:"value"`
	SenderRandom             string               `json:"senderRandom"`
	SharedKey                string               `json:"sharedKey"`
	ViewingPrivateKey        string               `json:"viewingPrivateKey"`
	OutputType               int                  `json:"outputType"`
	WalletSource             string               `json:"walletSource"`
	MemoText                 string               `json:"memoText"`
	NoteCiphertextV2IV       string               `json:"noteCiphertextV2IV"`
	AnnotationV2IV           string               `json:"annotationV2IV"`
	NoteCiphertextV3Nonce    string               `json:"noteCiphertextV3Nonce"`
	AnnotationV3Nonce        string               `json:"annotationV3Nonce"`
	OrderedOutputTypes       []int                `json:"orderedOutputTypes"`
}

type transactNoteBlindingFixture struct {
	BlindedSenderViewingKey   string `json:"blindedSenderViewingKey"`
	BlindedReceiverViewingKey string `json:"blindedReceiverViewingKey"`
}

type transactNoteDecryptedFixtures struct {
	V2Sent     decryptedTransactNoteFixture `json:"v2Sent"`
	V2Received decryptedTransactNoteFixture `json:"v2Received"`
	V3Sent     decryptedTransactNoteFixture `json:"v3Sent"`
	V3Received decryptedTransactNoteFixture `json:"v3Received"`
}

type decryptedTransactNoteFixture struct {
	Serialized SerializedTransactNote `json:"serialized"`
}

func loadTransactNoteFixtures(t *testing.T) transactNoteFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.TransactNoteFixtures
}
