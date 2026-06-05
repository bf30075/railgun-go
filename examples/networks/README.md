# Network Configs

Drop-in `NetworkConfig` JSON for the three mainnet chains the upstream Railgun
engine ships defaults for. Load with `sdk.LoadNetworkConfig("examples/networks/bsc.json")`.

| File | Chain ID | V2 QuickSync | V3 |
| --- | --- | --- | --- |
| `bsc.json` | 56 | yes (via `sdk.BSCV2QuickSyncStrategy{}`) | not enabled upstream |
| `ethereum.json` | 1 | RPC only | not enabled upstream |
| `polygon.json` | 137 | RPC only | not enabled upstream |

## Replace before use

- `rpcEndpoint` — the bundled URLs are best-effort public endpoints; for real
  workloads, point at your own node or a paid provider.
- `defaultChunkSize` / `defaultConfirmations` — defaults are conservative.
  Tune them based on your provider's log-range limits and the chain's
  finality model.

## Source

Addresses, deployment blocks, and POI launch blocks come from
[`@railgun-community/shared-models`](https://github.com/Railgun-Community/shared-models/blob/main/src/models/network-config.ts).
When upstream rotates a contract (e.g. RelayAdapt upgrade), refresh these
files from that source.
