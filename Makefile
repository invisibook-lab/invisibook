.PHONY: build build-desktop build-chain build-chain-lite build-cozk2p-lib build-settle2p build-chain-cozk2p smoke-chain dump-cozk2p-fixture dump-settlepair2p-fixture dump-pool-fixture test-e2e-pool test-e2e-cozk2p run-chain run-test clean reset reset-chain reset-test

# The settle2p_session prover ships alongside the desktop app.
COZK2P_SETTLE2P_BIN := $(PWD)/cozk2p/target/release/settle2p_session

build: build-desktop build-settle2p build-chain

build-desktop:
	cd app/desktop && cargo build --release

# The DEFAULT chain build carries the cozk2p PLONK verifier (staticlib +
# `-tags cozk2p`): a production config sets settle_cozk2p_vk_path, and a
# binary without the verifier refuses to boot on it. Requires Rust.
build-chain: build-chain-cozk2p

# Pure-Go build WITHOUT the collaborative-settlement verifier. Dev only:
# the resulting binary refuses to boot on any config that sets
# settle_cozk2p_vk_path, so it cannot silently become a production node.
build-chain-lite:
	cd chain && go build -o invisibook .

# ── 2-party collaborative settlement (cozk2p) ──
# The PLONK verifier lives in the cozk2p Rust staticlib, linked into the
# chain via cgo behind the `cozk2p` build tag (docs/cozk2p_design.md §4).

build-cozk2p-lib:
	cd cozk2p && cargo build --release --lib
	mkdir -p chain/lib
	cp cozk2p/target/release/libcozk2p.a chain/lib/

# The desktop app's settlement runs the collaborative proof in this
# subprocess (the cozk2p workspace pins an older toolchain and cannot be
# linked into the app). Point the app at it with INVISIBOOK_SETTLE2P_BIN.
build-settle2p:
	cd cozk2p && cargo build --release --bin settle2p_session

build-chain-cozk2p: build-cozk2p-lib
	cd chain && go build -tags cozk2p -o invisibook .

# Smoke: the default chain binary must link the REAL PLONK verifier (and
# the stub build must refuse a PLONK-configured node).
smoke-chain: build-chain
	cd chain && go test -tags cozk2p ./core/ -run TestPlonkVerifierLinked -count=1
	cd chain && go test ./core/ -run TestStubBinaryRefusesPlonkConfiguredNode -count=1

# Regenerates chain/vk/settle_cozk2p_vk.bin and the Go-test fixture (runs an
# in-process 2-party collaborative prove; ~30 s).
dump-cozk2p-fixture:
	cd cozk2p && cargo run --release --bin dump_settle2p_fixture -- \
		--vk-out ../chain/vk/settle_cozk2p_vk.bin \
		--fixture-out /tmp/settle_cozk2p_fixture.json

# Regenerates chain/vk/settle_pair_cozk2p_vk.bin (the MERGED statement) and
# its Go-test fixture (in-process 2-party collaborative prove; ~2 min).
dump-settlepair2p-fixture:
	cd cozk2p && cargo run --release --bin dump_settlepair2p_fixture -- \
		--vk-out ../chain/vk/settle_pair_cozk2p_vk.bin \
		--fixture-out /tmp/settle_pair_cozk2p_fixture.json

# Shielded-pool fixture + VKs (note_deposit / spend_withdraw), consumed by
# chain/core pool tests and chain/test/pool_e2e_test.go.
dump-pool-fixture:
	cd lib && cargo run -p invisibook-lib --example dump_pool_fixture -- \
		/tmp/pool_fixture.json --copy-vk

test-e2e-pool: build-chain dump-pool-fixture
	cd chain && go test ./test/ -run TestShieldedPoolLifecycle -timeout 600s -v

# Full-depth 2-party e2e: real collaborative proof verified on a running
# chain (plus the core-level accept/reject fixture tests).
test-e2e-cozk2p: build-chain-cozk2p dump-cozk2p-fixture dump-settlepair2p-fixture
	cd chain && go test -tags cozk2p ./core/ -run 'CoZk2p|Settle2p|SettlePair2p' -v
	cd chain && go test -tags cozk2p ./test/ -run 'CoZk2p' -v -timeout 600s

run-desktop: build-settle2p
	cd app/desktop && INVISIBOOK_SETTLE2P_BIN=$(COZK2P_SETTLE2P_BIN) cargo run --release

run-chain:
	cd chain && go run .

# Launch Alice + Bob dual desktop for testing (resets note ledgers each time).
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
