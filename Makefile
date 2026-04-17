.PHONY: build-desktop build-cli build-chain run-chain clean

build: build-desktop build-cli build-chain

build-desktop:
	cd app/desktop && cargo build --release

build-cli:
	cd cli && cargo build --release
	cp cli/target/release/invisibook-cli ./invisibook

build-chain:
	cd chain && go build -o invisibook .

run-desktop:
	cd app/desktop && cargo run --release

run-chain:
	cd chain && go run .

clean:
	rm -f invisibook

reset-chain:
	cd chain && rm -rf data
