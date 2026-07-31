# interpose-sdk-go

[![govulncheck](https://github.com/interposed/interpose-sdk-go/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/interposed/interpose-sdk-go/actions/workflows/govulncheck.yml)

Cooperative-agent client for the [interpose](https://github.com/interposed/interpose) daemon. Agents call `RequestPermission` (or one of the typed helpers) before performing a gated action; the daemon either auto-allows under policy, prompts the user for hardware-backed approval (passkey / YubiKey), or denies.

This is the SDK an AI agent (or any process acting on behalf of a user) imports to participate in the cooperative path. Even without the SDK, the interpose kernel enforcer (LSM-BPF on Linux, EndpointSecurity on macOS soon) still blocks unauthorized actions — but cooperative agents get a much nicer UX because they ask first rather than getting `EPERM` after the fact.

---

## Install

Go 1.25 or later.

```bash
go get github.com/interposed/interpose-sdk-go
```

> **Note:** The SDK currently imports AAuth primitives from `interposed/interpose`, which is still a private repo. External users will not be able to `go build` until those primitives are relocated into this SDK (planned). For local development against both repos, clone them as siblings — the SDK's `go.mod` has a `replace` directive that picks up your local `interpose` checkout automatically.

---

## Quick start

```go
package main

import (
    "context"
    "log"

    interpose "github.com/interposed/interpose-sdk-go"
)

func main() {
    c, err := interpose.New("my-agent")
    if err != nil { log.Fatal(err) }

    ctx := context.Background()
    if err := c.RequestFileWrite(ctx, "/tmp/output.txt"); err != nil {
        log.Fatalf("permission: %v", err)
    }
    // approved — proceed with the write
}
```

Assumes a local `interpose serve` daemon on `127.0.0.1:7421`. Override with `INTERPOSE_ADDR` env var or the `WithAddr` option.

---

## API

### Primitive

```go
func (c *Client) RequestPermission(ctx context.Context, scope, target string) error
```

The underlying request. `scope` is any string the broker policy understands; `target` is the resource the action operates on. Returns `nil` on approval, `ErrDenied` on denial, or a transport error.

### Typed helpers

Sugar over the primitive with scope strings baked in. Use these for discoverability and to avoid typos.

| Helper | Scope | Target |
|---|---|---|
| `RequestFileWrite(ctx, path)` | `file.write` | path |
| `RequestFileRead(ctx, path)` | `file.read` | path |
| `RequestFileDelete(ctx, path)` | `file.delete` | path |
| `RequestExec(ctx, binary)` | `exec` | absolute path |
| `RequestConnect(ctx, host, port)` | `net.connect` | `host:port` |

For custom scopes (or any scope your broker policy is configured for that isn't in the table), call `RequestPermission` directly.

### Errors

All match with `errors.Is`:

- `ErrDenied` — broker refused (user denied, policy auto-deny, prompt timeout)
- `ErrDaemonUnreachable` — couldn't reach broker; check `interpose serve` is running
- `ErrUnauthorized` — broker rejected the agent token (clock skew or protocol mismatch)
- `ErrInvalidRequest` — broker rejected the request shape; programmer error

### Options

```go
interpose.New("my-agent",
    interpose.WithAddr("10.0.0.5:7421"),
    interpose.WithTimeout(30*time.Second),
    interpose.WithHTTPClient(custom),
)
```

---

## How auth works under the hood

The SDK implements the agent side of [AAuth](https://github.com/dickhardt/aauth) — Dick Hardt's draft OAuth extension for AI agents. On every request:

1. The SDK mints an `aa-agent+jwt` token with the agent's ephemeral Ed25519 keypair (generated per-process — agent identities are instance-scoped, never persisted). The agent's public key travels inside the token's `cnf.jwk` claim so the broker can verify the signature without any prior key exchange.
2. The SDK POSTs to `<addr>/permission` with `Authorization: AAuth <token>`.
3. The broker (interpose's Person Server) evaluates the request against its policy. Outcomes:
   - Auto-allow / auto-deny per policy rule.
   - Prompt the user via a registered hardware authenticator (passkey, YubiKey, Touch ID).
4. On approval the broker returns an `aa-auth+jwt` (not exposed to the agent — the SDK uses HTTP 200 vs 403 as the verdict signal) AND installs a kernel-side pre-authorization in the LSM enforcer so subsequent syscalls from the agent's process tree pass through.

You don't have to think about any of this. The SDK API is `RequestPermission(scope, target) → error`.

---

## When to call the SDK

Call **before** the action, not after. The kernel enforcer denies un-pre-authorized actions even from a process that intends to ask later — the cooperative path exists so agents get a real human-mediated approval rather than a bare `EPERM`.

```go
// Good:
if err := c.RequestFileWrite(ctx, path); err != nil { return err }
return os.WriteFile(path, data, 0o644)

// Bad — kernel will deny the write before your error handler runs:
err := os.WriteFile(path, data, 0o644)
if errors.Is(err, syscall.EPERM) {
    c.RequestFileWrite(ctx, path)  // too late
}
```

Approvals have a default TTL (60 s in v0.8). For long-running operations, ask once with a wider mission scope rather than per-syscall.

---

## See also

- [interpose](https://github.com/interposed/interpose) — the daemon this SDK talks to
- [`docs/security.md`](https://github.com/interposed/interpose/blob/main/docs/security.md) — what the kernel enforcer actually blocks
- [AAuth draft](https://github.com/dickhardt/aauth) — the protocol the SDK implements

---

## License

Apache 2.0. See [LICENSE](LICENSE).
