package broadcaster

import "fmt"

const (
	DefaultClusterID = 5
	DefaultShardID   = 1

	DefaultENRTreeURL = "enrtree://APMYHUVNQWHJNPI5L2KQ765EMCKUAMRWPUH3U2QIKPK6XEV3OW442@discovery.rootedinprivacy.com"

	DefaultMinimumBroadcasterVersion = "8.0.0"
	DefaultMaximumBroadcasterVersion = "8.999.0"

	DefaultBroadcasterIdentifier = "default"

	DefaultFeeExpirationTimeoutMS  = 120_000
	DefaultHistoricalLookBackMS    = 60_000
	DefaultPeerDiscoveryTimeoutMS  = 60_000
	feeExpirationMinimumMS         = 40_000
	authorizedFeeVarianceLowerPct  = 0.10
	authorizedFeeVarianceUpperPct  = 0.30
	defaultRandomFeeThresholdPct   = 5
)

// DefaultPeers are TCP/WSS bootstrap multiaddrs used by the upstream web client.
var DefaultPeers = []string{
	"/dns4/relay-a.rootedinprivacy.com/tcp/8000/wss/p2p/16Uiu2HAmFbD2ZvAFi2j9jjDo6g4HFbQAhfjDfnTTrbyRGQRmtG7x",
	"/dns4/relay-b.rootedinprivacy.com/tcp/8000/wss/p2p/16Uiu2HAmPtEAoPPok7VLrpNNC6t92ZQFqLndHvkdx6Fk3CxA4MaG",
	"/dns4/client-edge.rootedinprivacy.com/tcp/8000/wss/p2p/16Uiu2HAmQdCGG5qREQCq96kucmpUVupmvLwrTRjMazPAaMTNP97A",
}

func FormatRelayShardTopic(clusterID, shardID uint16) string {
	return fmt.Sprintf("/waku/2/rs/%d/%d", clusterID, shardID)
}

func ParseRelayShardTopic(topic string) (clusterID, shardID uint16, ok bool) {
	var c, s int
	n, err := fmt.Sscanf(topic, "/waku/2/rs/%d/%d", &c, &s)
	if err != nil || n != 2 || c < 0 || s < 0 || c > 65535 || s > 65535 {
		return 0, 0, false
	}
	return uint16(c), uint16(s), true
}
