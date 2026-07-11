# mailrelay build & release
#
# `make release` produces dist/: one archive per target (tar.gz, zip on
# windows) plus SHA256SUMS — exactly the artifact set the installer
# (install.sh) and the get.mailnite.com manifest (mailnite-get/release.sh)
# consume. CI attaches dist/* to the GitHub release on a tag; `make crosscheck`
# is the artifact-less compile check CI runs on every commit to main.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS  = -s -w -X main.Version=$(VERSION) -X main.Build=$(BUILD)

# Two architectures on the three operating systems that matter. The relay
# itself targets a Linux VDS; the darwin/windows builds are for running the
# workstation-side tooling (gen-ca, gen-certs, deploy) natively.
TARGETS = linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64

build:
	go build -ldflags '$(LDFLAGS)' -o mailrelay .

test:
	go vet ./... && go test ./... -race

# Behavioral test of install.sh (install/reinstall/autoupdate handover) against
# stubbed systemctl/curl — no root, no network, no systemd needed.
test-install:
	bash test/install_test.sh

# Compile every target without keeping artifacts — the fast per-commit gate.
# `go build ./...` (a package list) type-checks and links but writes nothing.
crosscheck:
	@for t in $(TARGETS); do \
		os=$${t%_*}; arch=$${t#*_}; \
		echo "compile $$t"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build ./... || exit 1; \
	done

release: clean
	@mkdir -p dist
	@for t in $(TARGETS); do \
		os=$${t%_*}; arch=$${t#*_}; \
		bin=mailrelay; if [ "$$os" = "windows" ]; then bin=mailrelay.exe; fi; \
		echo "building $$t"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/$$bin . || exit 1; \
		if [ "$$os" = "windows" ]; then \
			(cd dist && zip -q mailrelay_$$t.zip $$bin) || exit 1; \
		else \
			tar -czf dist/mailrelay_$$t.tar.gz -C dist $$bin || exit 1; \
		fi; \
		rm dist/$$bin; \
	done
	@cd dist && sha256sum *.tar.gz *.zip > SHA256SUMS
	@echo "release $(VERSION):" && cat dist/SHA256SUMS

clean:
	rm -rf dist mailrelay

.PHONY: build test test-install crosscheck release clean
