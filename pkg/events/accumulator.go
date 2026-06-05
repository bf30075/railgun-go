package events

import (
	"fmt"
	"strings"
)

type V2AccumulatedEvents struct {
	CommitmentEvents []CommitmentEvent     `json:"commitmentEvents"`
	NullifierEvents  []Nullifier           `json:"nullifierEvents"`
	UnshieldEvents   []UnshieldStoredEvent `json:"unshieldEvents"`
}

func AccumulateV2Logs(logs []ContractLog) (V2AccumulatedEvents, error) {
	out := V2AccumulatedEvents{
		CommitmentEvents: []CommitmentEvent{},
		NullifierEvents:  []Nullifier{},
		UnshieldEvents:   []UnshieldStoredEvent{},
	}
	topics, err := loadV2EventTopics()
	if err != nil {
		return V2AccumulatedEvents{}, err
	}
	for i, log := range logs {
		topic := firstTopic(log)
		switch {
		case topic == "":
			continue
		case strings.EqualFold(topic, topics.Shield):
			event, err := ParseV2ShieldLog(log)
			if err != nil {
				return V2AccumulatedEvents{}, fmt.Errorf("v2 shield log[%d]: %w", i, err)
			}
			out.CommitmentEvents = append(out.CommitmentEvents, event)
		case strings.EqualFold(topic, topics.Transact):
			event, err := ParseV2TransactLog(log)
			if err != nil {
				return V2AccumulatedEvents{}, fmt.Errorf("v2 transact log[%d]: %w", i, err)
			}
			out.CommitmentEvents = append(out.CommitmentEvents, event)
		case strings.EqualFold(topic, topics.Unshield):
			event, err := ParseV2UnshieldLog(log)
			if err != nil {
				return V2AccumulatedEvents{}, fmt.Errorf("v2 unshield log[%d]: %w", i, err)
			}
			out.UnshieldEvents = append(out.UnshieldEvents, event)
		case strings.EqualFold(topic, topics.Nullified):
			events, err := ParseV2NullifiedLog(log)
			if err != nil {
				return V2AccumulatedEvents{}, fmt.Errorf("v2 nullified log[%d]: %w", i, err)
			}
			out.NullifierEvents = append(out.NullifierEvents, events...)
		}
	}
	return out, nil
}

func AccumulateV3Logs(logs []ContractLog) (V3AccumulatorEvents, error) {
	out := V3AccumulatorEvents{
		CommitmentEvents:         []V3CommitmentEvent{},
		NullifierEvents:          []Nullifier{},
		UnshieldEvents:           []UnshieldStoredEvent{},
		RailgunTransactionEvents: []RailgunTransactionV3{},
	}
	accumulatorTopic, err := V3AccumulatorStateUpdateTopic()
	if err != nil {
		return V3AccumulatorEvents{}, err
	}
	for i, log := range logs {
		topic := firstTopic(log)
		if topic == "" || !strings.EqualFold(topic, accumulatorTopic) {
			continue
		}
		events, err := ParseV3AccumulatorStateUpdateLog(log)
		if err != nil {
			return V3AccumulatorEvents{}, fmt.Errorf("v3 accumulator log[%d]: %w", i, err)
		}
		out.CommitmentEvents = append(out.CommitmentEvents, events.CommitmentEvents...)
		out.NullifierEvents = append(out.NullifierEvents, events.NullifierEvents...)
		out.UnshieldEvents = append(out.UnshieldEvents, events.UnshieldEvents...)
		out.RailgunTransactionEvents = append(out.RailgunTransactionEvents, events.RailgunTransactionEvents...)
	}
	return out, nil
}

type v2Topics struct {
	Shield    string
	Transact  string
	Unshield  string
	Nullified string
}

func loadV2EventTopics() (v2Topics, error) {
	shield, err := V2EventTopic("Shield")
	if err != nil {
		return v2Topics{}, err
	}
	transact, err := V2EventTopic("Transact")
	if err != nil {
		return v2Topics{}, err
	}
	unshield, err := V2EventTopic("Unshield")
	if err != nil {
		return v2Topics{}, err
	}
	nullified, err := V2EventTopic("Nullified")
	if err != nil {
		return v2Topics{}, err
	}
	return v2Topics{
		Shield:    shield,
		Transact:  transact,
		Unshield:  unshield,
		Nullified: nullified,
	}, nil
}

func firstTopic(log ContractLog) string {
	if len(log.Topics) == 0 {
		return ""
	}
	return log.Topics[0]
}
