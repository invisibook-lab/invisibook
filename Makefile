.PHONY: build build-desktop build-chain run-chain run-test clean reset reset-chain reset-test

build: build-desktop build-chain

build-desktop:
	cd app/desktop && cargo build --release

build-chain:
	cd chain && go build -o invisibook .

run-desktop:
	cd app/desktop && cargo run --release

run-chain:
	cd chain && go run .

# Launch Alice + Bob dual desktop for testing (resets cash each time).
run-test:
	@./scripts/dev-dual.sh clean
	@./scripts/dev-dual.sh

clean:
	rm -f invisibook

reset: reset-chain reset-test

reset-chain:
	cd chain && rm -rf data

reset-test:
	./scripts/dev-dual.sh clean
