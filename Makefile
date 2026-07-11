# mailrelay build & release
#
# `make release` produces dist/: one tar.gz per target plus SHA256SUMS —
# exactly the artifact set the installer (install.sh) and the get.mailnite.com
# manifest (mailnite-get/release.sh) consume. Upload dist/* to the GitHub
# release for VERSION, then stamp the channel with mailnite-get/release.sh.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS  = -s -w -X main.Version=$(VERSION) -X main.Build=$(BUILD)

# The relay targets Linux VDS machines; amd64 + arm64 cover them.
TARGETS = linux_amd64 linux_arm64

build:
	go build -ldflags '$(LDFLAGS)' -o mailrelay .

test:
	go build ./... && go test ./... -race

release: clean
	@mkdir -p dist
	@for t in $(TARGETS); do \
		os=$${t%_*}; arch=$${t#*_}; \
		echo "building $$t"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/mailrelay . || exit 1; \
		tar -czf dist/mailrelay_$$t.tar.gz -C dist mailrelay; \
		rm dist/mailrelay; \
	done
	@cd dist && sha256sum *.tar.gz > SHA256SUMS
	@echo "release $(VERSION):" && cat dist/SHA256SUMS

clean:
	rm -rf dist mailrelay

.PHONY: build test release clean
