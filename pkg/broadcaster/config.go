package broadcaster

import (
	"fmt"
	"strings"
	"sync"
)

// CustomDNSConfig mirrors upstream CustomDNSConfig.
type CustomDNSConfig struct {
	OnlyCustom   bool
	ENRTreePeers []string
}

// Options mirrors BroadcasterOptions from the TS client.
type Options struct {
	TrustedFeeSigner      []string
	POIActiveListKeys     []string
	EnableHealthcheckLogs bool
	PubSubTopic           string
	ClusterID             uint16
	ShardID               uint16
	DNSDiscoveryURLs      []string
	AdditionalPeers       []string
	StorePeers            []string
	AdditionalDirectPeers []string
	PeerDiscoveryTimeoutMS int
	FeeExpirationTimeoutMS int
	HistoricalLookBackMS   int
	UseCustomDNS           *CustomDNSConfig
	MinBroadcasterVersion  string
	MaxBroadcasterVersion  string
	RelayAdaptHistory      map[string][]string // key: "type:id"
	IsDev                  bool
	Debugger               Debugger
	NullifierLookup        NullifierTxidLookup
	// Transport overrides the live Waku node (tests inject MemoryTransport).
	Transport Transport
}

// Config holds mutable runtime settings applied from Options.
type Config struct {
	mu sync.RWMutex

	TrustedFeeSigner               []string
	POIActiveListKeys              []string
	EnableHealthcheckLogs          bool
	IsDev                          bool
	FeeExpirationTimeoutMS         int
	HistoricalLookBackMS           int
	PeerDiscoveryTimeoutMS         int
	AuthorizedFeeVarianceLowerPct  float64
	AuthorizedFeeVarianceUpperPct  float64
	MinimumBroadcasterVersion      string
	MaximumBroadcasterVersion      string
	UseDNSDiscovery                bool
	CustomDNS                      CustomDNSConfig
	AdditionalDirectPeers          []string
	StorePeers                     []string
	ClusterID                      uint16
	ShardID                        uint16
	PubSubTopic                    string
	RelayAdaptHistory              map[string][]string
}

func newConfig(opts Options) *Config {
	cfg := &Config{
		TrustedFeeSigner:              append([]string{}, opts.TrustedFeeSigner...),
		POIActiveListKeys:             append([]string{}, opts.POIActiveListKeys...),
		EnableHealthcheckLogs:         opts.EnableHealthcheckLogs,
		IsDev:                         opts.IsDev,
		FeeExpirationTimeoutMS:        DefaultFeeExpirationTimeoutMS,
		HistoricalLookBackMS:          DefaultHistoricalLookBackMS,
		PeerDiscoveryTimeoutMS:        DefaultPeerDiscoveryTimeoutMS,
		AuthorizedFeeVarianceLowerPct: authorizedFeeVarianceLowerPct,
		AuthorizedFeeVarianceUpperPct: authorizedFeeVarianceUpperPct,
		MinimumBroadcasterVersion:     DefaultMinimumBroadcasterVersion,
		MaximumBroadcasterVersion:     DefaultMaximumBroadcasterVersion,
		UseDNSDiscovery:               true,
		ClusterID:                     DefaultClusterID,
		ShardID:                       DefaultShardID,
		PubSubTopic:                   FormatRelayShardTopic(DefaultClusterID, DefaultShardID),
		RelayAdaptHistory:             DefaultRelayAdaptHistory(),
	}
	if opts.FeeExpirationTimeoutMS > 0 {
		cfg.FeeExpirationTimeoutMS = opts.FeeExpirationTimeoutMS
	}
	if opts.HistoricalLookBackMS > 0 {
		cfg.HistoricalLookBackMS = opts.HistoricalLookBackMS
	}
	if opts.PeerDiscoveryTimeoutMS > 0 {
		cfg.PeerDiscoveryTimeoutMS = opts.PeerDiscoveryTimeoutMS
	}
	if opts.MinBroadcasterVersion != "" {
		cfg.MinimumBroadcasterVersion = opts.MinBroadcasterVersion
	}
	if opts.MaxBroadcasterVersion != "" {
		cfg.MaximumBroadcasterVersion = opts.MaxBroadcasterVersion
	}
	cfg.configureNetwork(opts.ClusterID, opts.ShardID, opts.PubSubTopic)
	cfg.configurePeers(opts)
	if opts.RelayAdaptHistory != nil {
		cfg.RelayAdaptHistory = cloneStringSliceMap(opts.RelayAdaptHistory)
	}
	return cfg
}

func (c *Config) configureNetwork(clusterID, shardID uint16, pubSubTopic string) {
	hasCluster := clusterID != 0
	hasShard := shardID != 0
	cID := c.ClusterID
	sID := c.ShardID
	if hasCluster {
		cID = clusterID
	}
	if hasShard {
		sID = shardID
	}
	if !hasCluster && !hasShard && pubSubTopic != "" {
		if parsedC, parsedS, ok := ParseRelayShardTopic(pubSubTopic); ok {
			cID, sID = parsedC, parsedS
		}
	}
	c.ClusterID = cID
	c.ShardID = sID
	if hasCluster || hasShard || pubSubTopic == "" {
		c.PubSubTopic = FormatRelayShardTopic(cID, sID)
	} else {
		c.PubSubTopic = pubSubTopic
	}
}

func (c *Config) configurePeers(opts Options) {
	dnsURLs := normalizeStrings(opts.DNSDiscoveryURLs)
	direct := normalizeStrings(opts.AdditionalDirectPeers)
	additional := normalizeStrings(opts.AdditionalPeers)
	store := normalizeStrings(opts.StorePeers)
	c.StorePeers = store
	merged := append([]string{}, direct...)
	merged = append(merged, additional...)
	merged = append(merged, store...)
	c.AdditionalDirectPeers = uniqueStrings(merged)

	if len(dnsURLs) > 0 {
		c.UseDNSDiscovery = true
		c.CustomDNS = CustomDNSConfig{OnlyCustom: true, ENRTreePeers: dnsURLs}
		return
	}
	c.UseDNSDiscovery = true
	if opts.UseCustomDNS != nil {
		c.CustomDNS = CustomDNSConfig{
			OnlyCustom:   opts.UseCustomDNS.OnlyCustom,
			ENRTreePeers: normalizeStrings(opts.UseCustomDNS.ENRTreePeers),
		}
		return
	}
	c.CustomDNS = CustomDNSConfig{
		OnlyCustom:   true,
		ENRTreePeers: []string{DefaultENRTreeURL},
	}
}

func (c *Config) DNSDiscoveryURLs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string{}, c.CustomDNS.ENRTreePeers...)
}

func (c *Config) BootstrapPeers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.AdditionalDirectPeers) > 0 {
		return append([]string{}, c.AdditionalDirectPeers...)
	}
	return append([]string{}, DefaultPeers...)
}

func (c *Config) IsTrustedSigner(railgunAddress string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	addr := strings.ToLower(railgunAddress)
	for _, trusted := range c.TrustedFeeSigner {
		if strings.ToLower(trusted) == addr {
			return true
		}
	}
	return false
}

func (c *Config) HasTrustedSigner() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.TrustedFeeSigner) > 0
}

func (c *Config) RelayAdaptHistoryFor(chainType int, chainID uint64) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := chainKey(chainType, chainID)
	return append([]string{}, c.RelayAdaptHistory[key]...)
}

func chainKey(chainType int, chainID uint64) string {
	return fmt.Sprintf("%d:%d", chainType, chainID)
}

func normalizeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return uniqueStrings(out)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string{}, v...)
	}
	return out
}
