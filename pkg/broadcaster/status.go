package broadcaster

import (
	"time"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
)

func connectionStatus(chain railchain.Chain, transport Transport, cache *FeeCache, filter *AddressFilter, cfg *Config) ConnectionStatus {
	if transport == nil || transport.HasError() {
		return StatusError
	}
	if !transport.Started() {
		return StatusDisconnected
	}
	now := time.Now().UnixMilli()
	last := cache.LastSubscribedAt()
	if last > 0 && now-last > int64(cfg.FeeExpirationTimeoutMS) {
		cache.TouchSubscribed(now + 5000)
		return StatusDisconnected
	}
	fees := cache.FeesForChain(chain)
	if fees == nil || len(fees) == 0 {
		return StatusSearching
	}
	allExpired := true
	anyAvailable := false
	for _, byBroadcaster := range fees {
		addresses := make([]string, 0, len(byBroadcaster))
		for addr := range byBroadcaster {
			addresses = append(addresses, addr)
		}
		for _, addr := range filter.Filter(addresses) {
			for _, fee := range byBroadcaster[addr] {
				if !cachedFeeExpired(fee.Expiration, now) {
					allExpired = false
					if fee.AvailableWallets > 0 {
						anyAvailable = true
					}
				}
			}
		}
	}
	if allExpired {
		return StatusDisconnected
	}
	if !anyAvailable {
		return StatusAllUnavailable
	}
	return StatusConnected
}
