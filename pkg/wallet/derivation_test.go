package wallet

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type exportedFixtures struct {
	WalletFixtures walletFixtureSet `json:"walletFixtures"`
}

type walletFixtureSet struct {
	Mnemonic mnemonicFixtureSet `json:"mnemonic"`
	Derived  []derivedFixture   `json:"derived"`
	Indexed  IndexedWallet      `json:"indexed"`
}

type mnemonicFixtureSet struct {
	Valid   []mnemonicValidFixture   `json:"valid"`
	Invalid []mnemonicInvalidFixture `json:"invalid"`
	EVM     []mnemonicEVMFixture     `json:"evm"`
}

type mnemonicValidFixture struct {
	Mnemonic            string `json:"mnemonic"`
	Password            string `json:"password,omitempty"`
	Entropy             string `json:"entropy"`
	Seed                string `json:"seed"`
	EntropyFromMnemonic string `json:"entropyFromMnemonic"`
	MnemonicFromEntropy string `json:"mnemonicFromEntropy"`
	SeedFromMnemonic    string `json:"seedFromMnemonic"`
	Valid               bool   `json:"valid"`
}

type mnemonicInvalidFixture struct {
	Mnemonic string `json:"mnemonic"`
	Valid    bool   `json:"valid"`
}

type mnemonicEVMFixture struct {
	Name       string `json:"name"`
	Mnemonic   string `json:"mnemonic"`
	Index      uint32 `json:"index"`
	PrivateKey string `json:"privateKey"`
	Address    string `json:"address"`
}

type derivedFixture struct {
	Name            string          `json:"name"`
	Mnemonic        string          `json:"mnemonic"`
	Path            string          `json:"path"`
	SpendingKeyPair SpendingKeyPair `json:"spendingKeyPair"`
	ViewingKeyPair  ViewingKeyPair  `json:"viewingKeyPair"`
	NullifyingKey   string          `json:"nullifyingKey"`
}

func TestMnemonicFixturesMatchTypeScript(t *testing.T) {
	fixtures := loadWalletFixtures(t).Mnemonic
	for _, fixture := range fixtures.Valid {
		if !fixture.Valid {
			t.Fatalf("typescript fixture expected mnemonic to be valid: %q", fixture.Mnemonic)
		}
		if !ValidateMnemonic(fixture.Mnemonic) {
			t.Fatalf("expected mnemonic to validate: %q", fixture.Mnemonic)
		}
		entropy, err := MnemonicToEntropy(fixture.Mnemonic)
		if err != nil {
			t.Fatal(err)
		}
		if entropy != fixture.EntropyFromMnemonic || entropy != fixture.Entropy {
			t.Fatalf("expected entropy %s, got %s", fixture.Entropy, entropy)
		}
		mnemonic, err := MnemonicFromEntropy(fixture.Entropy)
		if err != nil {
			t.Fatal(err)
		}
		if mnemonic != fixture.MnemonicFromEntropy || mnemonic != fixture.Mnemonic {
			t.Fatalf("expected mnemonic %q, got %q", fixture.Mnemonic, mnemonic)
		}
		seed := MnemonicToSeed(fixture.Mnemonic, fixture.Password)
		if seed != fixture.SeedFromMnemonic || seed != fixture.Seed {
			t.Fatalf("expected seed %s, got %s", fixture.Seed, seed)
		}
	}
	for _, fixture := range fixtures.Invalid {
		if fixture.Valid {
			t.Fatalf("typescript fixture expected mnemonic to be invalid: %q", fixture.Mnemonic)
		}
		if ValidateMnemonic(fixture.Mnemonic) {
			t.Fatalf("expected mnemonic to be invalid: %q", fixture.Mnemonic)
		}
	}
	for _, fixture := range fixtures.EVM {
		t.Run(fixture.Name, func(t *testing.T) {
			privateKey, err := MnemonicTo0xPrivateKey(fixture.Mnemonic, fixture.Index)
			if err != nil {
				t.Fatal(err)
			}
			if privateKey != fixture.PrivateKey {
				t.Fatalf("expected 0x private key %s, got %s", fixture.PrivateKey, privateKey)
			}
			address, err := MnemonicTo0xAddress(fixture.Mnemonic, fixture.Index)
			if err != nil {
				t.Fatal(err)
			}
			if address != fixture.Address {
				t.Fatalf("expected 0x address %s, got %s", fixture.Address, address)
			}
		})
	}
}

func TestGenerateMnemonicShape(t *testing.T) {
	tests := []struct {
		strength int
		words    int
	}{
		{strength: 0, words: 12},
		{strength: 128, words: 12},
		{strength: 192, words: 18},
		{strength: 256, words: 24},
	}
	for _, test := range tests {
		mnemonic, err := GenerateMnemonic(test.strength)
		if err != nil {
			t.Fatal(err)
		}
		if !ValidateMnemonic(mnemonic) {
			t.Fatalf("generated mnemonic did not validate: %q", mnemonic)
		}
		if got := len(strings.Split(mnemonic, " ")); got != test.words {
			t.Fatalf("expected %d words, got %d", test.words, got)
		}
	}
	if _, err := GenerateMnemonic(160); err == nil {
		t.Fatal("expected unsupported strength to fail")
	}
}

func TestWalletDerivationMatchesTypeScript(t *testing.T) {
	fixtures := loadWalletFixtures(t)
	for _, fixture := range fixtures.Derived {
		t.Run(fixture.Name, func(t *testing.T) {
			derived, err := DeriveFromMnemonic(fixture.Mnemonic, fixture.Path)
			if err != nil {
				t.Fatal(err)
			}
			if derived.Spending != fixture.SpendingKeyPair {
				t.Fatalf("expected spending key pair %+v, got %+v", fixture.SpendingKeyPair, derived.Spending)
			}
			if derived.Viewing != fixture.ViewingKeyPair {
				t.Fatalf("expected viewing key pair %+v, got %+v", fixture.ViewingKeyPair, derived.Viewing)
			}
			if derived.NullifyingKey != fixture.NullifyingKey {
				t.Fatalf("expected nullifying key %s, got %s", fixture.NullifyingKey, derived.NullifyingKey)
			}
		})
	}
}

func TestIndexedWalletMatchesTypeScript(t *testing.T) {
	expected := loadWalletFixtures(t).Indexed
	indexed, err := DeriveIndexedWallet(expected.Mnemonic, expected.Index)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, indexed, expected)
}

func loadWalletFixtures(t *testing.T) walletFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.WalletFixtures
}

func assertJSONEqual(t *testing.T, got any, expected any) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(expectedJSON) {
		t.Fatalf("expected %s, got %s", expectedJSON, gotJSON)
	}
}
