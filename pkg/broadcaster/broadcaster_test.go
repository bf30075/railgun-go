package broadcaster

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

func TestTopics(t *testing.T) {
	chain := railchain.Chain{Type: 0, ID: 56}
	if got := ContentTopicFees(chain); got != "/railgun/v2/0-56-fees/json" {
		t.Fatalf("fees topic %s", got)
	}
	if got := ContentTopicTransact(chain); got != "/railgun/v2/0-56-transact/json" {
		t.Fatalf("transact topic %s", got)
	}
	if FormatRelayShardTopic(5, 1) != "/waku/2/rs/5/1" {
		t.Fatal("shard topic")
	}
}

func TestX25519SharedSecretMatchesNoble(t *testing.T) {
	priv, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	randPriv, _ := hex.DecodeString("0202020202020202020202020202020202020202020202020202020202020202")
	pub, err := railcrypto.PublicViewingKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := X25519SharedSecret(randPriv, pub)
	if err != nil {
		t.Fatal(err)
	}
	want := "4181d7302557342bdb6d061c4b1eebea828ecb625c3368b7111680793307220b"
	if hex.EncodeToString(shared) != want {
		t.Fatalf("got %s want %s", hex.EncodeToString(shared), want)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pub, err := railcrypto.PublicViewingKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"test": "123", "value": float64(678)}
	encrypted, err := EncryptDataWithSharedKey(payload, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted.RandomPubKey) != 64 {
		t.Fatalf("random pubkey len %d", len(encrypted.RandomPubKey))
	}
	shared, err := X25519SharedSecret(seed, mustHex(encrypted.RandomPubKey))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, ok := DecryptAESGCM256(encrypted.EncryptedData, shared)
	if !ok {
		t.Fatal("decrypt failed")
	}
	if decrypted["test"] != "123" {
		t.Fatalf("unexpected %#v", decrypted)
	}
}

func TestFeeCacheAndBestBroadcaster(t *testing.T) {
	cfg := newConfig(Options{TrustedFeeSigner: []string{"0zk1trusted"}})
	cache := NewFeeCache(nil)
	filter := NewAddressFilter()
	chain := railchain.Chain{Type: 0, ID: 56}
	now := time.Now().UnixMilli()
	cache.AddAuthorizedFees("0zk1trusted", map[string]CachedTokenFee{
		"0xtoken": {
			FeePerUnitGas:    "1000",
			Expiration:       now + 120_000,
			FeesID:           "fee-1",
			AvailableWallets: 2,
			RelayAdapt:       "0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd",
			Reliability:      0.9,
		},
	})
	cache.AddTokenFees(chain, "0zk1broadcaster", now+120_000, map[string]CachedTokenFee{
		"0xtoken": {
			FeePerUnitGas:    "1100",
			Expiration:       now + 120_000,
			FeesID:           "fee-2",
			AvailableWallets: 1,
			RelayAdapt:       "0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd",
			Reliability:      0.8,
		},
	}, "default", "8.1.0", nil, cfg, nopDebugger{})

	best, ok := FindBestBroadcaster(cache, filter, cfg, chain, "0xtoken", true)
	if !ok {
		t.Fatal("expected broadcaster")
	}
	if best.TokenFee.FeesID != "fee-2" {
		t.Fatalf("got %#v", best)
	}
}

func TestClientMemoryTransportFlow(t *testing.T) {
	transport := NewMemoryTransport()
	client, err := NewClient(Options{
		TrustedFeeSigner: []string{"0zk1trusted"},
		Transport:        transport,
		IsDev:            true,
	})
	if err != nil {
		t.Fatal(err)
	}
	chain := railchain.Chain{Type: 0, ID: 56}
	ctx := context.Background()
	if err := client.Start(ctx, chain, nil); err != nil {
		t.Fatal(err)
	}
	defer client.Stop(ctx)

	// Inject fees directly for selection path.
	now := time.Now().UnixMilli()
	client.FeeCache().AddAuthorizedFees("0zk1trusted", map[string]CachedTokenFee{
		"0x55d398326f99059ff775485246999027b3197955": {
			FeePerUnitGas: "1000", Expiration: now + 120_000, FeesID: "a", AvailableWallets: 1,
			RelayAdapt: "0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd", Reliability: 1,
		},
	})
	client.FeeCache().AddTokenFees(chain, "0zk1broadcaster", now+120_000, map[string]CachedTokenFee{
		"0x55d398326f99059ff775485246999027b3197955": {
			FeePerUnitGas: "1000", Expiration: now + 120_000, FeesID: "b", AvailableWallets: 1,
			RelayAdapt: "0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd", Reliability: 1,
		},
	}, "default", "8.1.0", nil, client.cfg, nopDebugger{})

	best, ok := client.FindBestBroadcaster(chain, "0x55d398326f99059ff775485246999027b3197955", true)
	if !ok {
		t.Fatal("expected best broadcaster")
	}
	if best.TokenFee.FeesID != "b" {
		t.Fatalf("unexpected %#v", best)
	}

	// Publish a fake encrypted response and ensure store decrypt path works.
	shared := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i)
	}
	client.responses.SetSharedKey(shared)
	enc, err := EncryptJSONDataWithSharedKey(map[string]any{"id": "1", "txHash": "0xabc"}, shared)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"result": enc})
	_ = transport.Publish(ctx, ContentTopicTransactResponse(chain), payload)
	resp, ok := client.responses.Get()
	if !ok || resp.TxHash != "0xabc" {
		t.Fatalf("response %#v ok=%v", resp, ok)
	}
}

func mustHex(value string) []byte {
	out, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return out
}
