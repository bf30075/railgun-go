package events

import (
	"context"
	"fmt"
)

type LogFilter struct {
	Addresses []string   `json:"addresses,omitempty"`
	FromBlock uint64     `json:"fromBlock"`
	ToBlock   uint64     `json:"toBlock"`
	Topics    [][]string `json:"topics,omitempty"`
}

type LogProvider interface {
	FilterLogs(ctx context.Context, filter LogFilter) ([]ContractLog, error)
}

type ScanRange struct {
	Addresses []string
	FromBlock uint64
	ToBlock   uint64
	ChunkSize uint64
}

type ScannedLogChunk struct {
	FromBlock uint64
	ToBlock   uint64
	Logs      int
}

func ScanV2Events(ctx context.Context, provider LogProvider, scan ScanRange) (V2AccumulatedEvents, error) {
	out := emptyV2AccumulatedEvents()
	err := ScanV2EventChunks(ctx, provider, scan, func(events V2AccumulatedEvents, _ ScannedLogChunk) error {
		appendV2AccumulatedEvents(&out, events)
		return nil
	})
	if err != nil {
		return V2AccumulatedEvents{}, err
	}
	return out, nil
}

func ScanV2EventChunks(ctx context.Context, provider LogProvider, scan ScanRange, handle func(V2AccumulatedEvents, ScannedLogChunk) error) error {
	topics, err := v2FilterTopics()
	if err != nil {
		return err
	}
	return scanLogChunks(ctx, provider, scan, [][]string{topics}, func(logs []ContractLog, chunk ScannedLogChunk) error {
		events, err := AccumulateV2Logs(logs)
		if err != nil {
			return err
		}
		return handle(events, chunk)
	})
}

func ScanV3Events(ctx context.Context, provider LogProvider, scan ScanRange) (V3AccumulatorEvents, error) {
	out := emptyV3AccumulatorEvents()
	err := ScanV3EventChunks(ctx, provider, scan, func(events V3AccumulatorEvents, _ ScannedLogChunk) error {
		appendV3AccumulatorEvents(&out, events)
		return nil
	})
	if err != nil {
		return V3AccumulatorEvents{}, err
	}
	return out, nil
}

func ScanV3EventChunks(ctx context.Context, provider LogProvider, scan ScanRange, handle func(V3AccumulatorEvents, ScannedLogChunk) error) error {
	topic, err := V3AccumulatorStateUpdateTopic()
	if err != nil {
		return err
	}
	return scanLogChunks(ctx, provider, scan, [][]string{{topic}}, func(logs []ContractLog, chunk ScannedLogChunk) error {
		events, err := AccumulateV3Logs(logs)
		if err != nil {
			return err
		}
		return handle(events, chunk)
	})
}

func v2FilterTopics() ([]string, error) {
	topics, err := loadV2EventTopics()
	if err != nil {
		return nil, err
	}
	return []string{
		topics.Shield,
		topics.Transact,
		topics.Unshield,
		topics.Nullified,
	}, nil
}

func scanLogChunks(ctx context.Context, provider LogProvider, scan ScanRange, topics [][]string, handle func([]ContractLog, ScannedLogChunk) error) error {
	if provider == nil {
		return fmt.Errorf("log provider is required")
	}
	if scan.ToBlock < scan.FromBlock {
		return fmt.Errorf("toBlock must be greater than or equal to fromBlock")
	}
	for from := scan.FromBlock; ; {
		to := scan.ToBlock
		if scan.ChunkSize > 0 {
			chunkTo := from + scan.ChunkSize - 1
			if chunkTo < from || chunkTo > scan.ToBlock {
				chunkTo = scan.ToBlock
			}
			to = chunkTo
		}
		logs, err := provider.FilterLogs(ctx, LogFilter{
			Addresses: append([]string(nil), scan.Addresses...),
			FromBlock: from,
			ToBlock:   to,
			Topics:    cloneTopics(topics),
		})
		if err != nil {
			return fmt.Errorf("filter logs %d-%d: %w", from, to, err)
		}
		chunk := ScannedLogChunk{FromBlock: from, ToBlock: to, Logs: len(logs)}
		if err := handle(logs, chunk); err != nil {
			return fmt.Errorf("handle logs %d-%d: %w", from, to, err)
		}
		if to == scan.ToBlock {
			return nil
		}
		from = to + 1
	}
}

func emptyV2AccumulatedEvents() V2AccumulatedEvents {
	return V2AccumulatedEvents{
		CommitmentEvents: []CommitmentEvent{},
		NullifierEvents:  []Nullifier{},
		UnshieldEvents:   []UnshieldStoredEvent{},
	}
}

func emptyV3AccumulatorEvents() V3AccumulatorEvents {
	return V3AccumulatorEvents{
		CommitmentEvents:         []V3CommitmentEvent{},
		NullifierEvents:          []Nullifier{},
		UnshieldEvents:           []UnshieldStoredEvent{},
		RailgunTransactionEvents: []RailgunTransactionV3{},
	}
}

func appendV2AccumulatedEvents(dst *V2AccumulatedEvents, src V2AccumulatedEvents) {
	dst.CommitmentEvents = append(dst.CommitmentEvents, src.CommitmentEvents...)
	dst.NullifierEvents = append(dst.NullifierEvents, src.NullifierEvents...)
	dst.UnshieldEvents = append(dst.UnshieldEvents, src.UnshieldEvents...)
}

func appendV3AccumulatorEvents(dst *V3AccumulatorEvents, src V3AccumulatorEvents) {
	dst.CommitmentEvents = append(dst.CommitmentEvents, src.CommitmentEvents...)
	dst.NullifierEvents = append(dst.NullifierEvents, src.NullifierEvents...)
	dst.UnshieldEvents = append(dst.UnshieldEvents, src.UnshieldEvents...)
	dst.RailgunTransactionEvents = append(dst.RailgunTransactionEvents, src.RailgunTransactionEvents...)
}

func cloneTopics(topics [][]string) [][]string {
	out := make([][]string, len(topics))
	for i, group := range topics {
		out[i] = append([]string(nil), group...)
	}
	return out
}
