package broadcaster

import (
	"math/big"
	"math/rand"
	"strings"
	"time"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
)

func cachedFeeUnavailableOrExpired(fee CachedTokenFee, chain railchain.Chain, useRelayAdapt bool, cfg *Config, nowMS int64) bool {
	if useRelayAdapt {
		history := cfg.RelayAdaptHistoryFor(chain.Type, chain.ID)
		if !relayAdaptAllowed(history, fee.RelayAdapt) {
			return true
		}
	}
	if fee.AvailableWallets == 0 {
		return true
	}
	return cachedFeeExpired(fee.Expiration, nowMS)
}

// FindBroadcastersForToken mirrors BroadcasterSearch.findBroadcastersForToken.
func FindBroadcastersForToken(
	cache *FeeCache,
	filter *AddressFilter,
	cfg *Config,
	chain railchain.Chain,
	tokenAddress string,
	useRelayAdapt bool,
	ignoreMissingAuthorizedFee bool,
) []SelectedBroadcaster {
	now := time.Now().UnixMilli()
	token := strings.ToLower(tokenAddress)
	byBroadcaster := cache.FeesForToken(chain, token)
	if byBroadcaster == nil {
		return nil
	}
	unfiltered := make([]string, 0, len(byBroadcaster))
	for addr := range byBroadcaster {
		unfiltered = append(unfiltered, addr)
	}
	addresses := filter.Filter(unfiltered)

	var minFee, maxFee *big.Int
	if cfg.HasTrustedSigner() {
		authorized, ok := cache.GetAuthorizedFee(token)
		if ok {
			authorizedAmount, ok := new(big.Int).SetString(authorized.FeePerUnitGas, 10)
			if ok {
				lower := new(big.Int).Mul(authorizedAmount, big.NewInt(int64(cfg.AuthorizedFeeVarianceLowerPct*100)))
				lower.Div(lower, big.NewInt(100))
				upper := new(big.Int).Mul(authorizedAmount, big.NewInt(int64(cfg.AuthorizedFeeVarianceUpperPct*100)))
				upper.Div(upper, big.NewInt(100))
				minFee = new(big.Int).Sub(authorizedAmount, lower)
				maxFee = new(big.Int).Add(authorizedAmount, upper)
			}
		} else if !ignoreMissingAuthorizedFee {
			return []SelectedBroadcaster{}
		}
	}

	selected := make([]SelectedBroadcaster, 0)
	for _, addr := range addresses {
		for _, fee := range byBroadcaster[addr] {
			if cachedFeeUnavailableOrExpired(fee, chain, useRelayAdapt, cfg, now) {
				continue
			}
			if minFee != nil && maxFee != nil {
				amount, ok := new(big.Int).SetString(fee.FeePerUnitGas, 10)
				if !ok || amount.Cmp(minFee) < 0 || amount.Cmp(maxFee) > 0 {
					continue
				}
			}
			selected = append(selected, SelectedBroadcaster{
				RailgunAddress: addr,
				TokenAddress:   tokenAddress,
				TokenFee:       fee,
			})
		}
	}
	sortByReliabilityDesc(selected)
	return selected
}

// FindBestBroadcaster returns the lowest-fee broadcaster (reliability tie-break).
func FindBestBroadcaster(
	cache *FeeCache,
	filter *AddressFilter,
	cfg *Config,
	chain railchain.Chain,
	tokenAddress string,
	useRelayAdapt bool,
) (SelectedBroadcaster, bool) {
	selected := FindBroadcastersForToken(cache, filter, cfg, chain, tokenAddress, useRelayAdapt, false)
	if len(selected) == 0 {
		return SelectedBroadcaster{}, false
	}
	sortByAscendingFee(selected)
	return selected[0], true
}

// FindRandomBroadcasterForToken picks among fees within percentageThreshold of the minimum.
func FindRandomBroadcasterForToken(
	cache *FeeCache,
	filter *AddressFilter,
	cfg *Config,
	chain railchain.Chain,
	tokenAddress string,
	useRelayAdapt bool,
	percentageThreshold int,
) (SelectedBroadcaster, bool) {
	if percentageThreshold <= 0 {
		percentageThreshold = defaultRandomFeeThresholdPct
	}
	selected := FindBroadcastersForToken(cache, filter, cfg, chain, tokenAddress, useRelayAdapt, false)
	if len(selected) == 0 {
		return SelectedBroadcaster{}, false
	}
	sortByAscendingFee(selected)
	minFee, ok := new(big.Int).SetString(selected[0].TokenFee.FeePerUnitGas, 10)
	if !ok {
		return SelectedBroadcaster{}, false
	}
	threshold := new(big.Int).Mul(minFee, big.NewInt(int64(100+percentageThreshold)))
	threshold.Div(threshold, big.NewInt(100))
	eligible := make([]SelectedBroadcaster, 0, len(selected))
	for _, item := range selected {
		fee, ok := new(big.Int).SetString(item.TokenFee.FeePerUnitGas, 10)
		if !ok || fee.Cmp(threshold) > 0 {
			continue
		}
		eligible = append(eligible, item)
	}
	if len(eligible) == 0 {
		return SelectedBroadcaster{}, false
	}
	return eligible[rand.Intn(len(eligible))], true
}

// FindAllBroadcastersForChain returns every available quote on the chain.
func FindAllBroadcastersForChain(
	cache *FeeCache,
	filter *AddressFilter,
	cfg *Config,
	chain railchain.Chain,
	useRelayAdapt bool,
) []SelectedBroadcaster {
	fees := cache.FeesForChain(chain)
	if fees == nil {
		return nil
	}
	out := make([]SelectedBroadcaster, 0)
	for token := range fees {
		out = append(out, FindBroadcastersForToken(cache, filter, cfg, chain, token, useRelayAdapt, false)...)
	}
	sortByAscendingFee(out)
	return out
}

func sortByReliabilityDesc(items []SelectedBroadcaster) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].TokenFee.Reliability > items[i].TokenFee.Reliability {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}

func sortByAscendingFee(items []SelectedBroadcaster) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			ai, _ := new(big.Int).SetString(items[i].TokenFee.FeePerUnitGas, 10)
			aj, _ := new(big.Int).SetString(items[j].TokenFee.FeePerUnitGas, 10)
			if ai == nil {
				ai = big.NewInt(0)
			}
			if aj == nil {
				aj = big.NewInt(0)
			}
			cmp := ai.Cmp(aj)
			if cmp > 0 || (cmp == 0 && items[j].TokenFee.Reliability > items[i].TokenFee.Reliability) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}
