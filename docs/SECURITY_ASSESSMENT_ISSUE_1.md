# Security assessment — issue #1

**Repository:** `IndependentImpact/openbao-plugin-secp256k1`  
**Reviewed revision:** `c6e023c` (`main`)  
**Review date:** 2026-08-12  
**Target:** v0.1.0 on OpenBao 2.6.1  
**Reviewer:** independent Codex review session, not the authoring session

## Decision

**Do not approve for production-like custody use yet.**

The core cryptographic design is narrow and sound: the plugin has no
private-key export route, enforces 32-byte prehashed inputs, and correctly
converts dcrd compact signatures to EVM `r||s||v`. However, the resolved
runtime graph contains reachable known vulnerabilities and private-key byte
copies are retained in the Go heap after use. The audit and capable-seal
claims are architecturally plausible but not yet proven by an OpenBao
integration test.

Resolve SEC-001 and SEC-002, then add the integration evidence in SEC-004
before production-like use.

## Scope and method

This assessment covers the entire initial implementation, commit `c6e023c`,
against [GitHub issue #1](https://github.com/IndependentImpact/openbao-plugin-secp256k1/issues/1):
input validation, storage/no-export hygiene, EVM conversion, dependencies,
audit semantics, and OpenBao compatibility.

Checks performed:

- Static source and dependency inspection.
- `go test -race ./...`, `go vet ./...`, `go build ./...`, `go mod verify`,
  and `govulncheck ./...`.
- Local OpenBao 2.6.1 plugin registration, mount, key creation, signing,
  public-key read, and an `export/test-key` negative probe. The probe returned
  `unsupported path`.

The temporary local OpenBao server was stopped after testing. No pre-existing
repository code was changed by this review.

## Confirmed controls

| Area | Result | Evidence |
| --- | --- | --- |
| Input validation | Pass | `prehashed=true` is mandatory; standard base64 decoding and exactly 32 decoded bytes are required before signing. [path_sign.go](../path_sign.go:45) |
| EVM signature conversion | Pass | dcrd compact `v||r||s` is converted to `r||s||v`; only recovery codes 27/28 are accepted. [path_sign.go](../path_sign.go:106) |
| EVM interoperability | Pass | Known-answer, recovery, address, deterministic RFC6979, and low-S tests pass. [evm_vectors_test.go](../evm_vectors_test.go:34) |
| No-export surface | Pass, caveat below | No export/backup/restore route exists; live OpenBao 2.6.1 `export/test-key` returned 404. Key reads and signing expose public material only. [backend.go](../backend.go:41) |
| Seal-wrap declaration | Pass | `keys/` is prefix-scoped under `SealWrapStorage`. [backend.go](../backend.go:46) |
| Audit architecture | Pass by inspection | The plugin uses normal framework paths and does not opt out of OpenBao core audit brokerage. Runtime evidence remains required; see SEC-004. |
| Handler logging/response hygiene | Pass by inspection | Handlers do not log or return `PrivateKey`; errors reveal names, lengths, recovery codes, or decode errors only. [key.go](../key.go:66), [path_sign.go](../path_sign.go:45) |

## Findings

### SEC-001 — High: reachable known vulnerabilities in the runtime graph

**Evidence.** [go.mod](../go.mod:3) uses Go 1.25.0 and pins OpenBao API/SDK
2.5.1, although the stated review target is OpenBao 2.6.1. The resolved
dependency graph includes gRPC 1.78.0 and go-jose 4.1.3.
`govulncheck ./...` reported **25 reachable vulnerabilities**, including:

- GO-2026-6061 in gRPC 1.78.0 (fixed in 1.82.1), reachable through the
  plugin's gRPC serving path;
- GO-2026-4945 in go-jose 4.1.3 (fixed in 4.1.4); and
- multiple reachable Go 1.25 standard-library TLS, HTTP/2, URL, X.509, and
  encoding vulnerabilities fixed in later Go 1.25 patch releases.

This is material in a custody boundary because the plugin exposes a gRPC/TLS
server to the OpenBao process. dcrd secp256k1 v4.4.1 itself produced no finding.
[CI](../.github/workflows/ci.yml:12) has no vulnerability gate.

**Required remediation.** Upgrade to an OpenBao SDK/API version compatible
with OpenBao 2.6.1 or later, use a current patched Go 1.25 release, refresh
`go.sum`, and make a clean reachable-vulnerability scan a release gate.

**Suggested issue:** `security: update OpenBao/Go baseline and gate reachable
vulnerabilities`.

### SEC-002 — Medium: private-key byte copies are not wiped after storage use

**Evidence.** `getKey` decodes private scalars into heap-backed
`keyVersion.PrivateKey` slices ([key.go](../key.go:31)). The plugin correctly
zeros temporary dcrd `PrivateKey` values
([path_sign.go](../path_sign.go:86), [key.go](../key.go:72)), but not the
decoded scalar bytes. `putKey` serializes key material into a JSON buffer
without wiping it ([key.go](../key.go:46)). These copies remain after create,
read, configuration, rotation, signing, and delete operations until garbage
collection.

This is not an API export route, but it materially weakens process-memory/core
dump resistance and fails the issue's requested `PrivateKey.Zero()` hygiene
review.

**Required remediation.** Centralize entry cleanup and overwrite decoded and
serialized private-scalar buffers on all return paths. Avoid loading private
material on public-only paths where possible. Document unavoidable Go-runtime
limitations, and enforce deployment controls for core dumps and swap.

**Suggested issue:** `security: wipe decoded and serialized private scalar
buffers`.

### SEC-003 — Low: invalid persisted private scalars do not fail closed

**Evidence.** The plugin only checks stored private-key length before calling
`secp256k1.PrivKeyFromBytes` ([key.go](../key.go:69),
[path_sign.go](../path_sign.go:82)). dcrd documents that callers must validate
the scalar range `[1,N-1]`; conversion reduces invalid values. A corrupted
zero or out-of-range value can therefore be accepted instead of rejected.

Barrier integrity makes hostile mutation difficult, so this is not an external
key-extraction path.

**Recommended remediation.** Validate non-zero/non-overflow scalar values
before deriving a public key or signing. Add persistence-corruption tests.

### SEC-004 — Medium: audit and capable-seal claims lack integration evidence

**Evidence.** Tests call `Backend.HandleRequest` directly with
`logical.InmemStorage` ([backend_test.go](../backend_test.go:18)), bypassing
OpenBao core's audit broker and a capable seal. The `SealWrapStorage`
declaration is correct, and source inspection of OpenBao 2.6.1 confirms core
audits mounted external-plugin requests and responses around dispatch, like
stock transit. Still, issue #1 requires confirmation equivalent to stock
transit, and the repository has no repeatable OpenBao 2.6.1 test that checks
an audit record, audit redaction, or actual seal wrapping.

The local live-mount test proves basic OpenBao 2.6.1 protocol compatibility but
does not prove audit-device or seal behaviour.

**Required remediation.** Add a disposable OpenBao 2.6.1 integration job that
registers/mounts the built plugin, configures an audit device, signs a digest,
and asserts request/response audit events without private material. In a
capable-seal environment, assert the stored `keys/` item is seal-wrapped.
Add negative `export`, `backup`, and `restore` probes.

### SEC-005 — Low: no-export test misses nested response values

**Evidence.** `TestNoPrivateMaterialExposed`
([backend_test.go](../backend_test.go:225)) inspects route names and top-level
string values only. Key reads hold their version data under the nested
`versions` map ([path_keys.go](../path_keys.go:134)), so a nested future leak
would evade the test. Manual review found no current response or log leak.

**Recommended remediation.** Recursively inspect response maps/slices (or
serialize whole responses) and reject both hex and base64 forms of the test
private scalar across create, read, rotate, config, sign, and error responses.

## Dependency and upstream review

The direct curve dependency, dcrd secp256k1 v4.4.1, is appropriate: generation
uses `crypto/rand`, dcrd supplies deterministic compact signing, and the
plugin uses `PrivateKey.Zero()` for temporary dcrd objects. The surrounding
OpenBao/toolchain graph, not the curve library, is the dependency blocker.

OpenBao 2.6.1 was checked for native transit secp256k1 support during this
review. No native replacement was found; the upstream request cited by this
repository remains closed. Re-check this retirement condition on each OpenBao
upgrade.

## Release gate

1. Resolve SEC-001 and SEC-002; address or explicitly accept SEC-003 and
   SEC-005.
2. Add and pass the OpenBao 2.6.1 integration coverage required by SEC-004.
3. Repeat this checklist against the exact release binary, OpenBao version,
   Go patch version, and `go.sum`.
4. Restrict deployment to a dedicated security domain, grant the signing
   workload only `update` on its `sign/<name>` path, configure audit devices
   declaratively, and prohibit core dumps and swap exposure.

## Verification record

| Check | Result |
| --- | --- |
| `go test -race ./...` | Pass |
| `go vet ./...` | Pass |
| `go build ./...` | Pass |
| `go mod verify` | Pass |
| `govulncheck ./...` | Fail: 25 reachable vulnerabilities (SEC-001) |
| OpenBao 2.6.1 register/mount/create/sign/read | Pass |
| Live `secp256k1/export/test-key` probe | Pass: unsupported path |
| Actual audit-device/capable-seal assertion | Not demonstrated (SEC-004) |
