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

## Usage

```sh
rollcall hello -name Go
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
