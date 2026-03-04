.PHONY: build-cli clean

build-cli:
	cd cli && cargo build --release
	cp cli/target/release/invisibook-cli ./invisibook

clean:
	rm -f invisibook
