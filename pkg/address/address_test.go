package address

import (
	"encoding/json"
	"os"
	"testing"
)

type exportedFixtures struct {
	AddressFixtures []addressFixture `json:"addressFixtures"`
}

type addressFixture struct {
	Name    string      `json:"name"`
	Encoded string      `json:"encoded"`
	Decoded AddressData `json:"decoded"`
}

func TestAddressFixturesMatchTypeScript(t *testing.T) {
	fixtures := loadAddressFixtures(t)
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			encoded, err := Encode(fixture.Decoded)
			if err != nil {
				t.Fatal(err)
			}
			if encoded != fixture.Encoded {
				t.Fatalf("expected address %s, got %s", fixture.Encoded, encoded)
			}
			decoded, err := Decode(fixture.Encoded)
			if err != nil {
				t.Fatal(err)
			}
			assertJSONEqual(t, decoded, fixture.Decoded)
		})
	}
}

func loadAddressFixtures(t *testing.T) []addressFixture {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.AddressFixtures
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
