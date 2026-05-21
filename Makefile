.PHONY: build-desktop build-cli build-chain run-chain clean reset reset-chain reset-cash

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

reset: reset-chain reset-cash

reset-chain:
	cd chain && rm -rf data

reset-cash:
	mkdir -p ~/.invisibook
	cp chain/cfg/tests/alice_cash.json ~/.invisibook/cash.json
