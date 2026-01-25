GO := /usr/local/go/bin/go
BINARY := timeseal
CMD_DIR := ./cmd/timeseal

.PHONY: all build test clean install

all: build

build:
	$(GO) build -o $(BINARY) $(CMD_DIR)

test:
	$(GO) test -v ./...

clean:
	rm -f $(BINARY)
	rm -f *.tsl *.payload

install:
	$(GO) install $(CMD_DIR)

.PHONY: fmt lint
fmt:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...
