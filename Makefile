VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/axionpanel ./cmd/panel
	go build -ldflags "$(LDFLAGS)" -o bin/axionpanel-agent ./cmd/agent

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin
