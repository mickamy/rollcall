.PHONY: build install test lint clean

GOLANGCI_LINT := bin/custom-gcl

build:
	go build -trimpath -ldflags "-s -w" -o bin/rollcall .

install:
	go install .

test:
	go test -race ./...

$(GOLANGCI_LINT): .custom-gcl.yml
	golangci-lint custom

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

clean:
	rm -rf bin
