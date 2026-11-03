VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build web test vet clean

# The panel binary embeds web/dist. Run `make web` first for a usable UI;
# without it the panel still builds and serves a 503 at /.
build:
	go build -ldflags "$(LDFLAGS)" -o bin/axionpanel ./cmd/panel
	go build -ldflags "$(LDFLAGS)" -o bin/axionpanel-agent ./cmd/agent

web:
	cd web && npm ci --no-audit --no-fund && npm run build
	touch web/dist/.gitkeep

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin
