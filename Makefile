BIN := ./bin/xytherion

.PHONY: build dev clean tidy ui test

build:
	go build -ldflags="-s -w" -o $(BIN) ./cmd/xytherion

dev:
	go run ./cmd/xytherion

tidy:
	go mod tidy

clean:
	rm -rf ./bin

# Rebuild the embedded dashboard from the site repo (needs Node.js), then
# commit internal/ui/dist so plain `go build` keeps working without Node.
SITE ?= ../xytherion
ui:
	cd $(SITE) && npm run build:agent-ui

test:
	go vet ./...
	go test ./...
