package note

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestUnshieldNoteFixturesMatchTypeScript(t *testing.T) {
	fixtures := loadUnshieldNoteFixtures(t)
	for _, fixture := range fixtures.Notes {
		t.Run(fixture.Name, func(t *testing.T) {
			note := buildUnshieldNoteFromFixture(t, fixture)
			assertJSONEqual(t, nativeUnshieldNoteFrom(note), fixture.Note)
		})
	}
}

func TestAmountFeeFromValueMatchesTypeScript(t *testing.T) {
	fixtures := loadUnshieldNoteFixtures(t)
	for _, fixture := range fixtures.AmountFees {
		value := mustDec(t, fixture.Value)
		feeBasisPoints := mustDec(t, fixture.FeeBasisPoints)
		amount, fee := AmountFeeFromValue(value, feeBasisPoints)
		got := nativeAmountFee{
			Amount: amount.String(),
			Fee:    fee.String(),
		}
		assertJSONEqual(t, got, fixture.Output)
	}
}

func TestUnshieldNoteRejectsInvalidTokens(t *testing.T) {
	if _, err := NewUnshieldNote(
		"0x1111222233334444555566667777888899990000",
		big.NewInt(1),
		railcrypto.TokenData{
			TokenAddress: "0x1234",
			TokenType:    railcrypto.TokenTypeERC20,
			TokenSubID:   "0x00",
		},
		false,
	); err == nil {
		t.Fatal("expected invalid ERC20 token address to fail")
	}
	tokenData, err := railcrypto.TokenDataNFT(
		"0x1111111111111111111111111111111111111111",
		railcrypto.TokenTypeERC721,
		"12345",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewUnshieldNote(
		"0x1111222233334444555566667777888899990000",
		big.NewInt(2),
		tokenData,
		false,
	); err == nil {
		t.Fatal("expected ERC721 value other than 1 to fail")
	}
}

func buildUnshieldNoteFromFixture(t *testing.T, fixture unshieldNoteFixture) UnshieldNote {
	t.Helper()
	value := mustDec(t, fixture.Note.Value)
	switch fixture.Name {
	case "erc20":
		note, err := NewUnshieldNoteERC20(
			fixture.Note.ToAddress,
			value,
			fixture.Note.TokenData.TokenAddress,
			fixture.Note.AllowOverride,
		)
		if err != nil {
			t.Fatal(err)
		}
		return note
	case "erc721", "erc1155":
		note, err := NewUnshieldNoteNFT(
			fixture.Note.ToAddress,
			fixture.Note.TokenData,
			fixture.Note.AllowOverride,
		)
		if err != nil {
			t.Fatal(err)
		}
		return note
	case "empty-erc20":
		note, err := EmptyUnshieldNoteERC20()
		if err != nil {
			t.Fatal(err)
		}
		return note
	default:
		t.Fatalf("unknown fixture %q", fixture.Name)
		return UnshieldNote{}
	}
}

type unshieldExportedFixtures struct {
	UnshieldNoteFixtures unshieldNoteFixtureSet `json:"unshieldNoteFixtures"`
}

type unshieldNoteFixtureSet struct {
	Notes      []unshieldNoteFixture    `json:"notes"`
	AmountFees []unshieldAmountFeeInput `json:"amountFees"`
}

type unshieldNoteFixture struct {
	Name string             `json:"name"`
	Note nativeUnshieldNote `json:"note"`
}

type nativeUnshieldNote struct {
	ToAddress       string                     `json:"toAddress"`
	Value           string                     `json:"value"`
	TokenData       railcrypto.TokenData       `json:"tokenData"`
	Hash            string                     `json:"hash"`
	HashHex         string                     `json:"hashHex"`
	AllowOverride   bool                       `json:"allowOverride"`
	NPK             string                     `json:"npk"`
	NotePublicKey   string                     `json:"notePublicKey"`
	UnshieldData    nativeUnshieldData         `json:"unshieldData"`
	SerializeNoPref SerializedUnshieldPreimage `json:"serializeNoPrefix"`
	SerializePref   SerializedUnshieldPreimage `json:"serializePrefix"`
	PreImage        nativeUnshieldNotePreimage `json:"preImage"`
}

type nativeUnshieldData struct {
	ToAddress     string               `json:"toAddress"`
	Value         string               `json:"value"`
	TokenData     railcrypto.TokenData `json:"tokenData"`
	AllowOverride bool                 `json:"allowOverride"`
}

type nativeUnshieldNotePreimage struct {
	NPK   string               `json:"npk"`
	Token railcrypto.TokenData `json:"token"`
	Value string               `json:"value"`
}

type unshieldAmountFeeInput struct {
	Value          string          `json:"value"`
	FeeBasisPoints string          `json:"feeBasisPoints"`
	Output         nativeAmountFee `json:"output"`
}

type nativeAmountFee struct {
	Amount string `json:"amount"`
	Fee    string `json:"fee"`
}

func nativeUnshieldNoteFrom(note UnshieldNote) nativeUnshieldNote {
	hashHex, err := note.HashHex()
	if err != nil {
		panic(err)
	}
	notePublicKey, err := note.NotePublicKey()
	if err != nil {
		panic(err)
	}
	serializeNoPrefix, err := note.Serialize(false)
	if err != nil {
		panic(err)
	}
	serializePrefix, err := note.Serialize(true)
	if err != nil {
		panic(err)
	}
	unshieldData := note.UnshieldData()
	preImage := note.PreImage()
	return nativeUnshieldNote{
		ToAddress:     note.ToAddress,
		Value:         note.Value.String(),
		TokenData:     note.TokenData,
		Hash:          note.Hash.String(),
		HashHex:       hashHex,
		AllowOverride: note.AllowOverride,
		NPK:           note.NPK(),
		NotePublicKey: notePublicKey.String(),
		UnshieldData: nativeUnshieldData{
			ToAddress:     unshieldData.ToAddress,
			Value:         unshieldData.Value.String(),
			TokenData:     unshieldData.TokenData,
			AllowOverride: unshieldData.AllowOverride,
		},
		SerializeNoPref: serializeNoPrefix,
		SerializePref:   serializePrefix,
		PreImage: nativeUnshieldNotePreimage{
			NPK:   preImage.NPK,
			Token: preImage.Token,
			Value: preImage.Value.String(),
		},
	}
}

func loadUnshieldNoteFixtures(t *testing.T) unshieldNoteFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures unshieldExportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.UnshieldNoteFixtures
}

func assertJSONEqual(t *testing.T, got any, expected any) {
	t.Helper()
	gotJSON := mustJSON(t, got)
	expectedJSON := mustJSON(t, expected)
	if gotJSON != expectedJSON {
		t.Fatalf("expected %s, got %s", expectedJSON, gotJSON)
	}
}
