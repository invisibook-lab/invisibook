.PHONY: build-desktop build-cli clean

build: build-desktop build-cli

build-desktop:
	cd app/desktop && cargo build --release

build-cli:
	cd cli && cargo build --release
	cp cli/target/release/invisibook-cli ./invisibook

clean:
	rm -f invisibook
