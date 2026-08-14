PLUGIN  := openbao-plugin-secp256k1
VERSION ?= v0.0.0-dev
LDFLAGS := -s -w -X github.com/IndependentImpact/openbao-plugin-secp256k1.pluginVersion=$(VERSION)

.PHONY: build test vet vulncheck integration checksum clean

build:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o bin/$(PLUGIN) ./cmd

test:
	go test -race ./...

vet:
	go vet ./...

vulncheck:
	govulncheck ./...

integration:
	./scripts/integration-openbao.sh

checksum: build
	cd bin && shasum -a 256 $(PLUGIN) > checksums.txt && cat checksums.txt

clean:
	rm -rf bin
