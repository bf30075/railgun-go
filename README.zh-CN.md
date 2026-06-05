# railgun-go

[English](README.md) · [架构](docs/architecture.md) · [Quickstart](docs/quickstart.md) · [rapidsnark 安装](docs/rapidsnark-setup.md) · [Changelog](CHANGELOG.md) · [贡献](CONTRIBUTING.md) · [安全](SECURITY.md)

`railgun-go` 是 Railgun 协议引擎的 Go 实现。代码按引擎边界拆分 —— 加密核心、钱包状态、网络 provider、同步策略、交易执行 —— 每一层都可以脱离 CLI/UI 单独测试。

**100% Go ZK 证明。** 上游 Node 引擎的 Groth16 proving 路径 —— artifact 解析、witness 生成、public signal 格式化、本地验证 —— 已全部用 Go 重新实现。不需要 Node.js runtime,也没有 JavaScript shim;`rapidsnark` 只作为可选的外部 prover 二进制被调用。

## 安装

```bash
go get github.com/bf30075/railgun-go/pkg/sdk
```

需要 Go 1.26+。默认构建和测试不依赖任何外部二进制。

## 快速上手

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

完整流程(文件存储 runtime、shield、unshield)见 [docs/quickstart.md](docs/quickstart.md)。

## `pkg/sdk` 概览

`Runtime` 是会话级 facade,持有钱包状态、当前链的 active TXID version、provider、proof 配置和可选 secret 材料。引擎能力都通过它暴露:`Sync`、`Balances`、`History`、`POIStatus`、`Rollback`,以及私有流程 `ShieldBaseToken` / `ShieldERC20` / `UnshieldBaseTokenV2` / `UnshieldERC20V2`。

私有交易执行需要 `WalletSecret`,并且 provider 必须支持 EIP-1559 发送、receipt 读取和合约调用。先用 `runtime.ProviderCapabilities()` 判断,缺能力时直接拒绝开放对应工作流。

包结构和依赖方向见 [docs/architecture.md](docs/architecture.md)。原生 proving (rapidsnark) 见 [docs/rapidsnark-setup.md](docs/rapidsnark-setup.md)。

## 验证

```bash
make check        # go test ./pkg/... + git diff --check
go vet ./pkg/...
```

原生 proving 为可选(需要 `prover` 二进制):

```bash
go test -tags "rapidsnark witnesscalc" ./...
```

## 状态

`railgun-go` 还未发布公开版本。第一次 tag 前需要:配置真实的私有安全联系方式,并决定公开 Go module path。

## License

MIT — 见 [LICENSE](LICENSE)。本模块是 MIT 协议的 [@railgun-community/engine](https://github.com/Railgun-Community/engine) 的 Go 重新实现。
