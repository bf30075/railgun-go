# rapidsnark Setup

Default `railgun-go` engine tests do not need rapidsnark. The external `prover`
binary is required only for:

- real native proving via `pkg/proof/rapidsnark`;
- `Runtime.UnshieldBaseTokenV2` and `Runtime.UnshieldERC20V2`;
- tests built with the `rapidsnark` build tag.

The SDK rapidsnark backend resolves the prover in this order:

1. `ProofConfig.RapidsnarkProverBinary` when explicitly set;
2. an executable named `prover` discovered on `PATH`.

The upstream [iden3/rapidsnark](https://github.com/iden3/rapidsnark) build
instructions are the source of truth. After compilation the standalone prover
is usually at `package/bin/prover` inside the rapidsnark repository.

## macOS

Install Go and the rapidsnark build dependencies:

```bash
brew install go git cmake gmp libsodium nasm
```

Build the prover. On Apple Silicon use `macos_arm64`:

```bash
git clone https://github.com/iden3/rapidsnark.git
cd rapidsnark
git submodule update --init --recursive
./build_gmp.sh macos_arm64
make macos_arm64
mkdir -p ~/.local/bin
cp package/bin/prover ~/.local/bin/prover
chmod +x ~/.local/bin/prover
```

On Intel Mac use `host`:

```bash
git clone https://github.com/iden3/rapidsnark.git
cd rapidsnark
git submodule update --init --recursive
./build_gmp.sh host
make host
mkdir -p ~/.local/bin
cp package/bin/prover ~/.local/bin/prover
chmod +x ~/.local/bin/prover
```

Confirm the shell can find the prover:

```bash
export PATH="$HOME/.local/bin:$PATH"
command -v prover
```

If you do not want to change `PATH`, set `ProofConfig.RapidsnarkProverBinary`
to an absolute path such as `/Users/<you>/.local/bin/prover`.

## Windows

Use WSL2 + Ubuntu for building and running. The upstream rapidsnark README
does not provide native Windows build steps; WSL2 can use the Ubuntu/Linux
toolchain directly. Install WSL by following the
[Microsoft WSL documentation](https://learn.microsoft.com/en-us/windows/wsl/install).

Install Ubuntu from an administrator PowerShell:

```powershell
wsl --install -d Ubuntu
```

After rebooting, enter the Ubuntu shell, install dependencies, and build the
Linux prover:

```bash
sudo apt update
sudo apt install -y build-essential cmake libgmp-dev libsodium-dev nasm curl m4 git
git clone https://github.com/iden3/rapidsnark.git
cd rapidsnark
git submodule update --init --recursive
./build_gmp.sh host
make host
mkdir -p ~/.local/bin
cp package/bin/prover ~/.local/bin/prover
chmod +x ~/.local/bin/prover
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
command -v prover
```

Keep the runtime environment consistent on Windows. If the prover was built
inside WSL, `railgun-go` should run inside the same WSL environment. A native
Windows Go process cannot directly execute the Linux `prover` from WSL. If
native Windows execution is required, provide a working `prover.exe`, place it
in the Windows `PATH`, or set `ProofConfig.RapidsnarkProverBinary` to its
absolute path.

## Verify the Integration

Default tests still run without tags:

```bash
make test
```

Enable tags only when verifying witness calculator or rapidsnark integration:

```bash
go test -tags witnesscalc ./pkg/proof/witness
go test -tags "rapidsnark witnesscalc" ./...
```

`rapidsnark` tests require a working `prover`. Some tests also require
`RAPIDSNARK_PROVER`, `RAPIDSNARK_ZKEY`, and `RAPIDSNARK_WTNS` to point to one
matching set of test circuit artifacts.

## Configuring `railgun-go`

Pass the prover binary path through `RuntimeOptions.Proof`:

```go
runtime, err := sdk.NewFileRuntimeFromKeystore(
    ".railgun-go/wallet-1",
    ".railgun-go/wallet-1.vault.json",
    password,
    sdk.RuntimeOptions{
        Network: config,
        Proof: &sdk.ProofConfig{
            RapidsnarkProverBinary: "/Users/<you>/.local/bin/prover",
            ArtifactCacheDir:       ".railgun-go/artifacts",
        },
    },
)
```

`ArtifactCacheDir` is the directory where compiled `.zkey` / `.wasm` circuit
artifacts are cached. The first call that needs an artifact downloads and
verifies it; subsequent calls reuse the cached file.

For per-request overrides, set `Proof` and/or `ArtifactCacheDir` on the
individual `UnshieldBaseTokenV2Request` or `UnshieldERC20V2Request`.
