.PHONY: build test vet lint clean install snapshot

BIN      := hookguard
PKG      := ./cmd/hookguard
VERSION  ?= dev
LDFLAGS  := -s -w -X main.Version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BIN) $(PKG)

install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

clean:
	rm -rf bin dist

snapshot:
	goreleaser release --snapshot --clean
