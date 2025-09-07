GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=dns-capture

.PHONY: all build clean test deps generate

all: deps generate build

build:
	$(GOBUILD) -o $(BINARY_NAME) .

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f dnscapture*_bpfe?.go
	rm -f dnscapture*_bpfe?.o

test:
	$(GOTEST) -v ./...

deps:
	$(GOMOD) download
	$(GOMOD) tidy

generate:
	$(GOCMD) generate ./...

install-deps:
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(shell uname -r)
