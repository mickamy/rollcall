# rollcall

Policy-enforcing database proxy that records which AI agent touched whose data.

[![CI](https://github.com/mickamy/rollcall/actions/workflows/ci.yaml/badge.svg)](https://github.com/mickamy/rollcall/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/mickamy/rollcall)](https://github.com/mickamy/rollcall/releases/latest)

## Installation

```sh
go install github.com/mickamy/rollcall@latest
```

With Homebrew:

```sh
brew install --cask mickamy/tap/rollcall
```

Prebuilt binaries are on the [releases page](https://github.com/mickamy/rollcall/releases).

## Status

Early development. `rollcall proxy` speaks the PostgreSQL protocol: it relays authentication untouched, sees every statement on both the simple and the extended query protocol, and refuses one before it reaches the server. A policy file maps each database role to an agent and can make it read-only; without `-policy`, every statement is allowed. The access ledger is next.

The proxy speaks plaintext on both sides and answers `SSLRequest` with `N`, so `sslmode=prefer` clients fall back to plaintext. Keep the listener on loopback or a pod-local network until TLS lands.

## Usage

Start the proxy in front of a database and point your agent's connection at it:

```sh
rollcall proxy -upstream 127.0.0.1:5432            # listens on 127.0.0.1:6432
PGHOST=127.0.0.1 PGPORT=6432 psql -U agent_claude_ops prod
```

Enforce a read-only role with a policy file:

```yaml
# policy.yaml
fail: closed
roles:
  agent_ops:
    agent: claude-ops
    purpose: incident-investigation
    read_only: true
```

```sh
rollcall proxy -upstream 127.0.0.1:5432 -policy policy.yaml
```

```sh
rollcall proxy -h
rollcall help
rollcall version
```

## Development

```sh
make test   # go test -race ./...
make lint   # builds bin/custom-gcl from .custom-gcl.yml, then runs it
make build  # bin/rollcall
```

## License

[MIT](./LICENSE)
