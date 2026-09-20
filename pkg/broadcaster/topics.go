package broadcaster

import (
	"fmt"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
)

// Content topic helpers mirror packages/common/src/waku/waku-topics.ts.
func ContentTopicDefault() string {
	return "/railgun/v2/default/json"
}

func ContentTopicFees(chain railchain.Chain) string {
	return fmt.Sprintf("/railgun/v2/%d-%d-fees/json", chain.Type, chain.ID)
}

func ContentTopicTransact(chain railchain.Chain) string {
	return fmt.Sprintf("/railgun/v2/%d-%d-transact/json", chain.Type, chain.ID)
}

func ContentTopicTransactResponse(chain railchain.Chain) string {
	return fmt.Sprintf("/railgun/v2/%d-%d-transact-response/json", chain.Type, chain.ID)
}

func ContentTopicMetrics() string {
	return "/railgun/v2/metrics/json"
}

func ContentTopicEncrypted(topic string) string {
	return fmt.Sprintf("/railgun/v2/encrypted-%s/json", topic)
}
