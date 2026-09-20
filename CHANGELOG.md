# Changelog

All notable changes to `railgun-go` should be recorded here.

This project has not published a public release yet. Keep entries under
`Unreleased` until the first tag is cut.

## Unreleased

- Wired `Runtime` unshield to default to Waku: randomly select a public broadcaster, pay its fee from the private balance, and submit over lightpush. Opt out with `BroadcasterOptions.SelfBroadcast` or per-request `SelfBroadcast`.
- Added `pkg/broadcaster`: Go port of the Railgun public broadcaster client (Waku topics, fee cache/selection, X25519+AES encrypt, lightpush submit) using go-waku.
- Moved the Railgun protocol engine into the standalone `railgun-go` module.
- Reimplemented the upstream Node engine's Groth16 proving path end-to-end in Go; `rapidsnark` is now only an optional external prover binary.
- Adopted MIT license to match upstream `@railgun-community/engine`.

## Release Notes Policy

- Use semantic versioning once public tags exist.
- Call out changes to proof formats, wallet persistence, transaction calldata,
  provider requirements, or supported chains explicitly.
- Mention whether native proving requires a rapidsnark upgrade.
- Do not publish a release until the public release checklist is complete.
