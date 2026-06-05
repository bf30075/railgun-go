package events

import (
	"context"
	"reflect"
	"testing"
)

func TestScanV2EventsChunksAndAccumulates(t *testing.T) {
	fixture := loadEventFixtures(t).V2
	provider := &stubLogProvider{
		logs: [][]ContractLog{
			{fixture.Shield.Log, unknownLog()},
			{fixture.Transact.Log, fixture.Unshield.Log, fixture.Nullified.Log},
		},
	}
	got, err := ScanV2Events(context.Background(), provider, ScanRange{
		Addresses: []string{"0x1111111111111111111111111111111111111111"},
		FromBlock: 10,
		ToBlock:   13,
		ChunkSize: 2,
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

	if len(provider.calls) != 2 {
		t.Fatalf("expected 2 provider calls, got %d", len(provider.calls))
	}
	assertFilter(t, provider.calls[0], 10, 11, []string{"0x1111111111111111111111111111111111111111"}, []string{
		fixture.Topics.Shield,
		fixture.Topics.Transact,
		fixture.Topics.Unshield,
		fixture.Topics.Nullified,
	})
	assertFilter(t, provider.calls[1], 12, 13, []string{"0x1111111111111111111111111111111111111111"}, []string{
		fixture.Topics.Shield,
		fixture.Topics.Transact,
		fixture.Topics.Unshield,
		fixture.Topics.Nullified,
	})
}

func TestScanV3EventsAccumulates(t *testing.T) {
	fixture := loadEventFixtures(t).V3
	provider := &stubLogProvider{
		logs: [][]ContractLog{
			{unknownLog(), fixture.Accumulator.Log},
		},
	}
	got, err := ScanV3Events(context.Background(), provider, ScanRange{
		FromBlock: 20,
		ToBlock:   22,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, got, fixture.Accumulator.Processed)

	if len(provider.calls) != 1 {
		t.Fatalf("expected 1 provider call, got %d", len(provider.calls))
	}
	assertFilter(t, provider.calls[0], 20, 22, nil, []string{fixture.Topics.AccumulatorStateUpdate})
}

type stubLogProvider struct {
	calls  []LogFilter
	logs   [][]ContractLog
	latest uint64
}

func (provider *stubLogProvider) FilterLogs(_ context.Context, filter LogFilter) ([]ContractLog, error) {
	provider.calls = append(provider.calls, filter)
	if len(provider.logs) == 0 {
		return nil, nil
	}
	logs := provider.logs[0]
	provider.logs = provider.logs[1:]
	return logs, nil
}

func (provider *stubLogProvider) BlockNumber(_ context.Context) (uint64, error) {
	return provider.latest, nil
}

func assertFilter(t *testing.T, got LogFilter, fromBlock uint64, toBlock uint64, addresses []string, firstTopicGroup []string) {
	t.Helper()
	if got.FromBlock != fromBlock || got.ToBlock != toBlock {
		t.Fatalf("expected block range %d-%d, got %d-%d", fromBlock, toBlock, got.FromBlock, got.ToBlock)
	}
	if !reflect.DeepEqual(got.Addresses, addresses) {
		t.Fatalf("expected addresses %v, got %v", addresses, got.Addresses)
	}
	if len(got.Topics) != 1 {
		t.Fatalf("expected 1 topic group, got %d", len(got.Topics))
	}
	if !reflect.DeepEqual(got.Topics[0], firstTopicGroup) {
		t.Fatalf("expected first topic group %v, got %v", firstTopicGroup, got.Topics[0])
	}
}
