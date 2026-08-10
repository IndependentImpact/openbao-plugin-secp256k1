# openbao-plugin-secp256k1

An OpenBao secrets-engine plugin that holds **non-exportable secp256k1 keys** and signs caller-supplied **32-byte digests**, returning 65-byte `r||s||v` signatures verifiable by the EVM `ecrecover` precompile.

It exists because stock OpenBao transit has no secp256k1 key type and will not accept one ([openbao/openbao#2618](https://github.com/openbao/openbao/issues/2618), closed wontfix). Independent Impact uses it to serve the platform-wide **bounty attestation key** (role `bounty`) in the dedicated security domain **`DOM-B`**, per [ADR-0018](https://github.com/IndependentImpact/ii-backend/blob/develop/docs/adrs/adr-0018-secrets-management.md) and [TS-0016](https://github.com/IndependentImpact/ii-backend/blob/develop/docs/tech-specs/ts-0016-key-custody-and-signing.md). This is a **prototyping-stage arrangement**, to be revisited at MVE.

## Security properties

- **Non-exportable by construction.** There is no export, backup, or restore endpoint. Reads return public material only. Enforced by tests (`TestNoPrivateMaterialExposed`).
- **Digests only.** The engine never hashes for the caller; `prehashed=true` is mandatory and inputs must be exactly 32 bytes (the underlying library would otherwise silently truncate or pad). Keccak-256 and EIP-712 encoding are the caller's job.
- **Deterministic, canonical signatures.** RFC6979 nonces, low-S (EIP-2), `v ∈ {27, 28}` — via [`decred/dcrd/dcrec/secp256k1/v4`](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4), the same pure-Go implementation go-ethereum uses without cgo. Byte conventions are pinned against go-ethereum test vectors.
- **Seal-wrapped storage.** Key material under `keys/` is declared for seal wrapping (extra encryption under a capable seal).
- **Gated deletion.** `deletion_allowed` defaults to false, set per key via `keys/<name>/config`.

## API

| Path | Op | Purpose |
|---|---|---|
| `keys/<name>` | `POST` | Create (fails if the key exists) |
| `keys/<name>` | `GET` | Public keys (compressed + uncompressed SEC1), EVM address, per version |
| `keys/<name>` | `DELETE` | Delete — only if `deletion_allowed` |
| `keys/<name>/config` | `POST` | `deletion_allowed=<bool>` |
| `keys/<name>/rotate` | `POST` | New key version; old versions remain requestable explicitly |
| `keys/` | `LIST` | Key names |
| `sign/<name>` | `POST` | `input` (base64 32-byte digest), `prehashed=true`, optional `key_version` (0 = latest) |

`sign` response: `signature` (0x-hex, 65-byte `r||s||v`, v = 27/28), `key_version`, `public_key_compressed`, `public_key_uncompressed`, `evm_address` — the public key is returned on every signature so callers can enforce a registry match (TS-0016).

## Build

```sh
CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/IndependentImpact/openbao-plugin-secp256k1.pluginVersion=v0.1.0" -o openbao-plugin-secp256k1 ./cmd
```

## Register and mount

```hcl
# server config
plugin_directory = "/opt/openbao/plugins"
```

```sh
bao plugin register -sha256=$(sha256sum openbao-plugin-secp256k1 | cut -d' ' -f1) -version=v0.1.0 secret secp256k1
bao secrets enable -path=secp256k1 secp256k1
bao write secp256k1/keys/bounty
bao write secp256k1/sign/bounty input=$(echo -n "<32-byte-digest>" | base64) prehashed=true
```

Dev-mode smoke test:

```sh
bao server -dev -dev-plugin-dir=$(pwd)
```

## Deployment constraints (II-specific)

- Deploy **only** on the `DOM-B` cluster. The plugin must not be loaded into any other security domain (TS-0016).
- Only the bounty handler receives a `DOM-B` credential; its policy grants `update` on `sign/bounty` and nothing else.
- Deployment assertions (TS-0016 acceptance criterion 8): enumerate mounted paths and assert no export/backup endpoints; the check in `TestNoPrivateMaterialExposed` is the reference implementation.
- Before upgrading the pinned OpenBao release, re-check whether native secp256k1 has landed upstream; if it has, retire this plugin.

## License

MPL-2.0.
