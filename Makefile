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

demo: install
	@chmod +x examples/web-app/test.sh
	@examples/web-app/test.sh

clean:
	swift package clean

.PHONY: build install test demo clean
