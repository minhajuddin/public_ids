GOBIN := $(shell go env GOPATH)/bin
PROTO_FILES := $(wildcard *.proto)

.PHONY: all build test proto tidy clean tools

all: build

build: proto
	go build ./...

test:
	go test ./...

# Regenerate Go code from the .proto files.
proto: tools
	PATH="$(PATH):$(GOBIN)" protoc \
		--go_out=. --go_opt=module=github.com/minhajuddin/public_ids \
		$(PROTO_FILES)

# Install codegen tooling.
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

tidy:
	go mod tidy

clean:
	go clean ./...
