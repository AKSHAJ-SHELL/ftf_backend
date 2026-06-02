SHELL := /usr/bin/env bash
BIN := bin/server

.PHONY: build run vet lint test sqlc migrate clean

build:
	mkdir -p bin
	go build -o $(BIN) ./cmd/server

run:
	go run ./cmd/server

vet:
	go vet ./...

lint:
	golangci-lint run

test:
	go test ./... -count=1

sqlc:
	sqlc generate

migrate:
	goose -dir migrations postgres "$(DATABASE_URL)" up

clean:
	rm -rf bin tmp coverage.out
