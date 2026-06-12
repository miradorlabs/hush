PREFIX ?= $(HOME)/.local
BIN := .build/release/hush

build:
	swift build -c release
	codesign -s - -f -o runtime $(BIN)

install: build
	mkdir -p $(PREFIX)/bin
	install $(BIN) $(PREFIX)/bin/hush

test:
	swift test

exploit: install
	@chmod +x tests/exploits.sh
	@PATH="$(PREFIX)/bin:$$PATH" tests/exploits.sh

demo: install
	@chmod +x examples/web-app/test.sh
	@examples/web-app/test.sh

# Reproducible build artifact + checksum. Signing/notarization: see RELEASING.md
dist: build
	@mkdir -p dist
	@cp $(BIN) dist/hush
	@cd dist && shasum -a 256 hush > hush.sha256
	@echo "dist/hush + dist/hush.sha256"
	@cat dist/hush.sha256

clean:
	swift package clean
	rm -rf dist

.PHONY: build install test exploit demo dist clean
