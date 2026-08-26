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

Early development. `rollcall proxy` currently relays PostgreSQL connections unchanged; policy enforcement and the access ledger are being built on top of it.

## Usage

Start the proxy in front of a database and point your agent's connection at it:

```sh
rollcall proxy -upstream 127.0.0.1:5432            # listens on 127.0.0.1:6432
PGHOST=127.0.0.1 PGPORT=6432 psql -U agent_claude_ops prod
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
