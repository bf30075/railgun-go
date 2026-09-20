package broadcaster

import (
	"strings"
	"sync"
	"time"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
)

type feeCacheState struct {
	// networkKey -> token -> broadcaster -> identifier -> fee
	forNetwork map[string]map[string]map[string]map[string]CachedTokenFee
}

// FeeCache mirrors BroadcasterFeeCache.
type FeeCache struct {
	mu                                 sync.RWMutex
	state                              feeCacheState
	authorizedFees                     map[string]map[string]CachedTokenFee // signer -> token -> fee
	poiActiveListKeys                  []string
	lastSubscribedFeeMessageReceivedAt int64
}

func NewFeeCache(poiActiveListKeys []string) *FeeCache {
	now := time.Now().UnixMilli()
	return &FeeCache{
		state:                              feeCacheState{forNetwork: map[string]map[string]map[string]map[string]CachedTokenFee{}},
		authorizedFees:                     map[string]map[string]CachedTokenFee{},
		poiActiveListKeys:                  append([]string{}, poiActiveListKeys...),
		lastSubscribedFeeMessageReceivedAt: now,
	}
}

func (c *FeeCache) LastSubscribedAt() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSubscribedFeeMessageReceivedAt
}

func (c *FeeCache) TouchSubscribed(nowMS int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSubscribedFeeMessageReceivedAt = nowMS
}

func (c *FeeCache) Reset(chain railchain.Chain) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.state.forNetwork, networkKey(chain))
}

func (c *FeeCache) AddAuthorizedFees(signerAddress string, tokenFeeMap map[string]CachedTokenFee) {
	c.mu.Lock()
	defer c.mu.Unlock()
	signer := strings.ToLower(signerAddress)
	if c.authorizedFees[signer] == nil {
		c.authorizedFees[signer] = map[string]CachedTokenFee{}
	}
	for token, fee := range tokenFeeMap {
		token = strings.ToLower(token)
		existing, ok := c.authorizedFees[signer][token]
		if ok && existing.Expiration >= fee.Expiration {
			continue
		}
		c.authorizedFees[signer][token] = fee
	}
}

func (c *FeeCache) GetAuthorizedFee(tokenAddress string) (CachedTokenFee, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	token := strings.ToLower(tokenAddress)
	var best CachedTokenFee
	found := false
	for _, byToken := range c.authorizedFees {
		fee, ok := byToken[token]
		if !ok {
			continue
		}
		if !found || fee.Expiration > best.Expiration {
			best = fee
			found = true
		}
	}
	return best, found
}

func (c *FeeCache) AddTokenFees(
	chain railchain.Chain,
	railgunAddress string,
	feeExpiration int64,
	tokenFeeMap map[string]CachedTokenFee,
	identifier string,
	version string,
	requiredPOIListKeys []string,
	cfg *Config,
	dbg Debugger,
) {
	if dbg == nil {
		dbg = nopDebugger{}
	}
	for _, listKey := range requiredPOIListKeys {
		allowed := false
		for _, active := range c.poiActiveListKeys {
			if active == listKey {
				allowed = true
				break
			}
		}
		if !allowed {
			dbg.Log("[Fees] Broadcaster " + railgunAddress + " requires POI list key " + listKey + ", which is not active.")
			return
		}
	}
	if invalidBroadcasterVersion(version, cfg.MinimumBroadcasterVersion, cfg.MaximumBroadcasterVersion) {
		dbg.Log("[Fees] Broadcaster version " + version + " invalid: " + railgunAddress)
		return
	}
	now := time.Now().UnixMilli()
	if cachedFeeExpired(feeExpiration, now) {
		dbg.Log("[Fees] Fees expired for " + railgunAddress)
		return
	}
	if identifier == "" {
		identifier = DefaultBroadcasterIdentifier
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	netKey := networkKey(chain)
	if c.state.forNetwork[netKey] == nil {
		c.state.forNetwork[netKey] = map[string]map[string]map[string]CachedTokenFee{}
	}
	for token, fee := range tokenFeeMap {
		token = strings.ToLower(token)
		if c.state.forNetwork[netKey][token] == nil {
			c.state.forNetwork[netKey][token] = map[string]map[string]CachedTokenFee{}
		}
		if c.state.forNetwork[netKey][token][railgunAddress] == nil {
			c.state.forNetwork[netKey][token][railgunAddress] = map[string]CachedTokenFee{}
		}
		c.state.forNetwork[netKey][token][railgunAddress][identifier] = fee
	}
	c.lastSubscribedFeeMessageReceivedAt = now
}

func (c *FeeCache) FeesForToken(chain railchain.Chain, tokenAddress string) map[string]map[string]CachedTokenFee {
	c.mu.RLock()
	defer c.mu.RUnlock()
	net := c.state.forNetwork[networkKey(chain)]
	if net == nil {
		return nil
	}
	src := net[strings.ToLower(tokenAddress)]
	if src == nil {
		return nil
	}
	out := make(map[string]map[string]CachedTokenFee, len(src))
	for broadcaster, byID := range src {
		cloned := make(map[string]CachedTokenFee, len(byID))
		for id, fee := range byID {
			cloned[id] = fee
		}
		out[broadcaster] = cloned
	}
	return out
}

func (c *FeeCache) FeesForChain(chain railchain.Chain) map[string]map[string]map[string]CachedTokenFee {
	c.mu.RLock()
	defer c.mu.RUnlock()
	src := c.state.forNetwork[networkKey(chain)]
	if src == nil {
		return nil
	}
	out := make(map[string]map[string]map[string]CachedTokenFee, len(src))
	for token, byBroadcaster := range src {
		out[token] = make(map[string]map[string]CachedTokenFee, len(byBroadcaster))
		for broadcaster, byID := range byBroadcaster {
			out[token][broadcaster] = make(map[string]CachedTokenFee, len(byID))
			for id, fee := range byID {
				out[token][broadcaster][id] = fee
			}
		}
	}
	return out
}

func (c *FeeCache) SupportsToken(chain railchain.Chain, tokenAddress string, useRelayAdapt bool, cfg *Config, filter *AddressFilter) bool {
	return len(FindBroadcastersForToken(c, filter, cfg, chain, tokenAddress, useRelayAdapt, false)) > 0
}

func networkKey(chain railchain.Chain) string {
	return chainKey(chain.Type, chain.ID)
}
