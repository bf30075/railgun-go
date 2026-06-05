package events

import (
	"encoding/json"
	"os"
	"testing"
)

func TestV2EventParsingMatchesTypeScript(t *testing.T) {
	fixture := loadEventFixtures(t).V2
	shield, err := ParseV2ShieldLog(fixture.Shield.Log)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, shield, fixture.Shield.Formatted)

	transact, err := ParseV2TransactLog(fixture.Transact.Log)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, transact, fixture.Transact.Formatted)

	unshield, err := ParseV2UnshieldLog(fixture.Unshield.Log)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, unshield, fixture.Unshield.Formatted)

	nullifiers, err := ParseV2NullifiedLog(fixture.Nullified.Log)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, nullifiers, fixture.Nullified.Formatted)
}

func TestV2EventTopicsMatchTypeScript(t *testing.T) {
	topics := loadEventFixtures(t).V2.Topics
	tests := map[string]string{
		"Shield":    topics.Shield,
		"Transact":  topics.Transact,
		"Unshield":  topics.Unshield,
		"Nullified": topics.Nullified,
	}
	for eventName, expected := range tests {
		t.Run(eventName, func(t *testing.T) {
			got, err := V2EventTopic(eventName)
			if err != nil {
				t.Fatal(err)
			}
			if got != expected {
				t.Fatalf("expected topic %s, got %s", expected, got)
			}
		})
	}
}

func TestV3AccumulatorEventParsingMatchesTypeScript(t *testing.T) {
	fixture := loadEventFixtures(t).V3
	processed, err := ParseV3AccumulatorStateUpdateLog(fixture.Accumulator.Log)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, processed, fixture.Accumulator.Processed)
}

func TestV3EventTopicsMatchTypeScript(t *testing.T) {
	expected := loadEventFixtures(t).V3.Topics.AccumulatorStateUpdate
	got, err := V3AccumulatorStateUpdateTopic()
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Fatalf("expected topic %s, got %s", expected, got)
	}
}

func TestAccumulateV2LogsMatchesTypeScript(t *testing.T) {
	fixture := loadEventFixtures(t).V2
	got, err := AccumulateV2Logs([]ContractLog{
		unknownLog(),
		fixture.Shield.Log,
		fixture.Transact.Log,
		{},
		fixture.Unshield.Log,
		fixture.Nullified.Log,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := V2AccumulatedEvents{
		CommitmentEvents: []CommitmentEvent{
			fixture.Shield.Formatted,
			fixture.Transact.Formatted,
		},
		NullifierEvents: fixture.Nullified.Formatted,
		UnshieldEvents: []UnshieldStoredEvent{
			fixture.Unshield.Formatted,
		},
	}
	assertJSONEqual(t, got, expected)
}

func TestAccumulateV3LogsMatchesTypeScript(t *testing.T) {
	fixture := loadEventFixtures(t).V3
	got, err := AccumulateV3Logs([]ContractLog{
		unknownLog(),
		fixture.Accumulator.Log,
		{},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, got, fixture.Accumulator.Processed)
}

type exportedFixtures struct {
	EventFixtures eventFixtureSet `json:"eventFixtures"`
}

type eventFixtureSet struct {
	V2 v2EventFixtures `json:"v2"`
	V3 v3EventFixtures `json:"v3"`
}

type v2EventFixtures struct {
	Shield    commitmentEventFixture `json:"shield"`
	Transact  commitmentEventFixture `json:"transact"`
	Unshield  unshieldEventFixture   `json:"unshield"`
	Nullified nullifierEventFixture  `json:"nullified"`
	Topics    v2EventTopics          `json:"topics"`
}

type commitmentEventFixture struct {
	Log       ContractLog     `json:"log"`
	Formatted CommitmentEvent `json:"formatted"`
}

type unshieldEventFixture struct {
	Log       ContractLog         `json:"log"`
	Formatted UnshieldStoredEvent `json:"formatted"`
}

type nullifierEventFixture struct {
	Log       ContractLog `json:"log"`
	Formatted []Nullifier `json:"formatted"`
}

type v2EventTopics struct {
	Shield    string `json:"shield"`
	Transact  string `json:"transact"`
	Unshield  string `json:"unshield"`
	Nullified string `json:"nullified"`
}

type v3EventFixtures struct {
	Accumulator v3AccumulatorEventFixture `json:"accumulator"`
	Topics      v3EventTopics             `json:"topics"`
}

type v3AccumulatorEventFixture struct {
	Log       ContractLog         `json:"log"`
	Processed V3AccumulatorEvents `json:"processed"`
}

type v3EventTopics struct {
	AccumulatorStateUpdate string `json:"accumulatorStateUpdate"`
}

func loadEventFixtures(t *testing.T) eventFixtureSet {
	t.Helper()
	data, err := os.ReadFile("../../testdata/railgun/exported-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures exportedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures.EventFixtures
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
		gotPretty, _ := json.MarshalIndent(got, "", "  ")
		expectedPretty, _ := json.MarshalIndent(expected, "", "  ")
		t.Fatalf("mismatch\nexpected:\n%s\nactual:\n%s", expectedPretty, gotPretty)
	}
}

func unknownLog() ContractLog {
	return ContractLog{
		Topics: []string{"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		Data:   "0x",
	}
}
