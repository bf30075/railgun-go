# Public Broadcaster (Waku)

Go port of [`@railgun-community/waku-broadcaster-client`](https://github.com/Railgun-Community/waku-broadcaster-client).
Package: `pkg/broadcaster`.

## What it covers

| Upstream (TS) | Go |
| --- | --- |
| Content topics (`fees` / `transact` / `transact-response`) | `ContentTopic*` |
| Fee message parse + ED25519 verify | `HandleFeesMessage` / `VerifyBroadcasterSignature` |
| Fee cache + trusted signer variance | `FeeCache` |
| Best / random / all selection | `FindBestBroadcaster` … |
| `encryptDataWithSharedKey` (noble X25519 + AES-GCM) | `EncryptDataWithSharedKey` |
| `BroadcasterTransaction.create/send` | `Client.CreateTransaction` / `Transaction.Send` |
| Light node (filter + lightpush + store + DNS) | `NewWakuTransport` via go-waku |

Self-broadcast via JSON-RPC (`SendEIP1559*`) remains available as an opt-out.

## SDK default (unshield)

`Runtime.UnshieldBaseTokenV2` / `UnshieldERC20V2` default to Waku:

1. Connect (or reuse) a broadcaster client
2. Pick a **random** in-threshold fee quote for the unshield token
3. Add a `BroadcasterFee` private output and prove
4. Submit encrypted calldata over Waku

Opt out with either:

```go
sdk.RuntimeOptions{
    Network: config,
    Broadcaster: &sdk.BroadcasterOptions{SelfBroadcast: true},
}
// or per request:
self := true
runtime.UnshieldBaseTokenV2(ctx, sdk.UnshieldBaseTokenV2Request{SelfBroadcast: &self, ...})
```

Shield stays self-broadcast (public deposit needs the wallet EVM key).

## Low-level client usage

```go
client, err := broadcaster.NewClient(broadcaster.Options{
    // empty TrustedFeeSigner uses Railway community defaults
})
if err != nil {
    return err
}
chain := railchain.Chain{Type: 0, ID: 56} // BSC
if err := client.Start(ctx, chain, func(_ railchain.Chain, status broadcaster.ConnectionStatus) {
    log.Println("broadcaster:", status)
}); err != nil {
    return err
}
defer client.Stop(ctx)

selected, ok := client.FindRandomBroadcasterForToken(chain, tokenAddress, true, 5)
if !ok {
    return fmt.Errorf("no broadcaster for token")
}

tx, err := client.CreateTransaction(
    "V2_PoseidonMerkle",
    to,
    data,
    selected.RailgunAddress,
    selected.TokenFee.FeesID,
    chain,
    nullifiers,
    minGasPrice,
    true,
    preTransactionPOIs,
)
if err != nil {
    return err
}
txHash, err := tx.Send(ctx)
```

For unit tests, inject `Options{Transport: broadcaster.NewMemoryTransport()}`.

## Network defaults

- PubSub shard: `/waku/2/rs/5/1`
- ENR tree: `discovery.rootedinprivacy.com`
- Bootstrap WSS peers: `relay-a/b` + `client-edge` under `rootedinprivacy.com`
- `go.mod` replace: `github.com/libp2p/go-libp2p-pubsub` → `github.com/waku-org/go-libp2p-pubsub v0.13.1-gowaku` (required by go-waku)
