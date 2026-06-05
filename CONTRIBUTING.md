# Contributing

`railgun-go` is a protocol engine repository. Keep changes small, verifiable, and close to the layer they affect.

## Development Loop

Run the default checks before sending a change:

```bash
make check
```

For a tighter loop while editing one package:

```bash
go test ./pkg/<package>
```

For proof witness changes:

```bash
go test -tags witnesscalc ./pkg/proof/witness
```

The full rapidsnark path needs an external `prover` binary and matching artifacts. Do not make ordinary tests depend on native proving.

## Boundaries

- Put deterministic cryptography, proof formatting, and transaction encoding in `pkg/crypto`, `pkg/proof`, and `pkg/transaction`.
- Put provider and log scanning changes in `pkg/events`.
- Put wallet state import, balances, history, POI status, and local rescans in `pkg/wallet`.
- Put historical bootstrap integrations in `pkg/quicksync` behind a `SyncStrategy`.
- Put application orchestration outside this repository, or behind `pkg/sdk` facades when it is engine-level behavior.

## Tests

New behavior should land with tests at the same layer as the change. A runtime behavior change usually belongs in `pkg/sdk`; a parser or pagination bug belongs beside the parser or fetcher.

Do not commit generated scratch directories, local wallet state, private keys, keystores, or prover artifacts.
