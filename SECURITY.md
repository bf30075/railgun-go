# Security

`railgun-go` handles wallet state, proof inputs, and transaction construction. Treat wallet material and generated artifacts as sensitive.

## Reporting

This repository does not yet define a public security contact. Until one is added, do not disclose wallet secrets, private keys, mnemonics, RPC credentials, or private transaction data in public issues.

Before the first public release, configure a private reporting channel and
replace this section with the real contact path.

## Local Handling

- Never commit mnemonics, private keys, keystores, `.vault.json` files, or local wallet state.
- Keep rapidsnark artifacts and temporary prover outputs outside version control unless they are intentional test fixtures.
- Prefer injected providers and local test fixtures over live RPC credentials in tests.
- When changing private execution, verify both success and failure paths. Reverted receipts, missing proofs, mismatched secrets, and insufficient ERC20 allowance should fail explicitly.

## Supported Checks

Default checks:

```bash
make check
```

Native proving checks are opt-in because they require external binaries and artifacts:

```bash
go test -tags witnesscalc ./pkg/proof/witness
go test -tags "rapidsnark witnesscalc" ./...
```

## Public Release Blockers

Before tagging a first public release, configure a real private security
contact, decide the public Go module path, and complete a secrets review of
the working tree.
