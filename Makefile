.PHONY: fmt lint test build verify

BINARY := clawscanner
OUT_DIR := dist

fmt:
	gofmt -w ./cmd ./internal

lint:
	go vet ./...

test:
	go test ./...

build:
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(OUT_DIR)/$(BINARY)-linux-amd64 ./cmd/clawscanner
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(OUT_DIR)/$(BINARY)-linux-arm64 ./cmd/clawscanner
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(OUT_DIR)/$(BINARY)-macos-amd64 ./cmd/clawscanner
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(OUT_DIR)/$(BINARY)-macos-arm64 ./cmd/clawscanner

verify: fmt lint test build
