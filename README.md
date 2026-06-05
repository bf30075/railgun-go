# railgun-go

[中文](README.zh-CN.md) · [Architecture](docs/architecture.md) · [Quickstart](docs/quickstart.md) · [Network configs](examples/networks/) · [rapidsnark Setup](docs/rapidsnark-setup.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

`railgun-go` is a Go implementation of the Railgun protocol engine. The code is split along engine boundaries — cryptographic core, wallet state, network providers, sync strategies, and transaction execution — so each layer is testable without a CLI or UI.

**100% Go ZK proving.** The upstream Node engine's Groth16 proving path — artifact resolution, witness generation, public-signal formatting, and local verification — is fully reimplemented in Go. No Node.js runtime, no JavaScript shims; `rapidsnark` is invoked only as an optional external prover binary.

## Install

```bash
go get github.com/bf30075/railgun-go/pkg/sdk
```

Requires Go 1.26+. Default builds and tests do not need any external binary.

## Quickstart

```go
import "github.com/bf30075/railgun-go/pkg/sdk"

config, _ := sdk.LoadNetworkConfig("network.json")
runtime, _ := sdk.NewMemoryRuntimeFromMnemonic(
    sdk.RuntimeOptions{Network: config},
    mnemonic,
    0,
)
runtime.Sync(ctx, "wallet")
balances, _ := runtime.Balances(ctx, nil)
```

Full walk-through (file-backed runtime, shield, unshield) is in [docs/quickstart.md](docs/quickstart.md).

## What's in `pkg/sdk`

`Runtime` is the session facade. It owns wallet state, the active TXID versions for the chain, the provider, proof config, and optional secret material. Engine-level operations live behind it: `Sync`, `Balances`, `History`, `POIStatus`, `Rollback`, and the private flows `ShieldBaseToken` / `ShieldERC20` / `UnshieldBaseTokenV2` / `UnshieldERC20V2`.

Private execution requires both a `WalletSecret` and a provider that supports EIP-1559 sending, receipts, and contract calls. Check `runtime.ProviderCapabilities()` and fail closed when capabilities are missing.

For the package map and dependency direction, see [docs/architecture.md](docs/architecture.md). For native proving with `rapidsnark`, see [docs/rapidsnark-setup.md](docs/rapidsnark-setup.md).

## Verification

```bash
make check        # go test ./pkg/... + git diff --check
go vet ./pkg/...
```

Native proving is opt-in (requires the `prover` binary):

```bash
go test -tags "rapidsnark witnesscalc" ./...
```

## Status

`railgun-go` has not published a public release yet. Before the first tag: configure a real private security contact and decide the public Go module path.

## License

MIT — see [LICENSE](LICENSE). This module is a Go reimplementation of the MIT-licensed [@railgun-community/engine](https://github.com/Railgun-Community/engine).
