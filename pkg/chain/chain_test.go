package chain

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

func TestFullNetworkIDMatchesTypeScript(t *testing.T) {
	fixtures := loadChainFixtures(t)
	for _, fixture := range fixtures.FullNetworkIDs {
		t.Run(fixture.Name, func(t *testing.T) {
			got, err := FullNetworkIDHex(fixture.Chain)
			if err != nil {
				t.Fatal(err)
			}
			if got != fixture.FullNetworkID {
				t.Fatalf("expected %s, got %s", fixture.FullNetworkID, got)
			}
			gotUint, err := FullNetworkIDUint64(fixture.Chain)
			if err != nil {
				t.Fatal(err)
			}
			if gotUint != mustUint64FromHex(t, fixture.FullNetworkID) {
				t.Fatalf("expected uint64 %d, got %d", mustUint64FromHex(t, fixture.FullNetworkID), gotUint)
			}
		})
	}
}

func TestSupportsV3MatchesTypeScript(t *testing.T) {
	fixture := loadChainFixtures(t).SupportsV3
	if got := SupportsV3(fixture.Supported); got != fixture.BeforeAdd {
		t.Fatalf("expected beforeAdd=%t, got %t", fixture.BeforeAdd, got)
	}
	if err := AssertSupportsV3(fixture.Unsupported); err == nil || err.Error() != fixture.AssertUnsupportedError {
		t.Fatalf("expected unsupported error %q, got %v", fixture.AssertUnsupportedError, err)
	}
	AddSupportsV3(fixture.Supported)
	if got := SupportsV3(fixture.Supported); got != fixture.AfterAdd {
		t.Fatalf("expected afterAdd=%t, got %t", fixture.AfterAdd, got)
	}
	if got := SupportsV3(fixture.Unsupported); got != fixture.UnsupportedAfterAdd {
		t.Fatalf("expected unsupportedAfterAdd=%t, got %t", fixture.UnsupportedAfterAdd, got)
	}
	if err := AssertSupportsV3(fixture.Supported); err != nil {
		t.Fatal(err)
	}
}

func TestAddSupportsV3IsIdempotent(t *testing.T) {
	chain := Chain{Type: 0, ID: 77770002}
	before := countSupportingV3Chain(chain)

	AddSupportsV3(chain)
	AddSupportsV3(chain)

	if got := countSupportingV3Chain(chain); got != before+1 {
		t.Fatalf("expected one registration, got %d before %d", got, before)
	}
}

func TestFullNetworkIDRejectsInvalidChain(t *testing.T) {
	if _, err := FullNetworkIDHex(Chain{Type: 256, ID: 1}); err == nil {
		t.Fatal("expected invalid chain type to fail")
	}
	if _, err := FullNetworkIDHex(Chain{Type: 1, ID: 1 << 56}); err == nil {
		t.Fatal("expected invalid chain id to fail")
	}
}

type exportedFixtures struct {
	ChainFixtures chainFixtureSet `json:"chainFixtures"`
}

type chainFixtureSet struct {
	FullNetworkIDs []chainFullNetworkIDFixture `json:"fullNetworkIDs"`
	SupportsV3     chainSupportsV3Fixture      `json:"supportsV3"`
}

type chainFullNetworkIDFixture struct {
	Name          string `json:"name"`
	Chain         Chain  `json:"chain"`
	FullNetworkID string `json:"fullNetworkID"`
}

type chainSupportsV3Fixture struct {
	Supported              Chain  `json:"supported"`
	Unsupported            Chain  `json:"unsupported"`
	BeforeAdd              bool   `json:"beforeAdd"`
	AfterAdd               bool   `json:"afterAdd"`
	UnsupportedAfterAdd    bool   `json:"unsupportedAfterAdd"`
	AssertUnsupportedError string `json:"assertUnsupportedError"`
}

func countSupportingV3Chain(chain Chain) int {
	count := 0
	for _, supportingChain := range chainsSupportingV3 {
		if supportingChain.Type == chain.Type && supportingChain.ID == chain.ID {
			count++
		}
	}
	return count
}

func loadChainFixtures(t *testing.T) chainFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.ChainFixtures
}

func mustUint64FromHex(t *testing.T, value string) uint64 {
	t.Helper()
	out, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
