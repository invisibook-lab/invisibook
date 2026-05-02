# SHA-256 Commitment Verification + Comparison (2PC)

Two-party computation protocol using emp-ag2pc (malicious-secure garbled circuits).

Two parties each prove knowledge of a value behind a SHA-256 commitment, then privately compare their values.

## Circuit

Both parties input both commitments C1 and C2 for malicious security (prevents tampering).

```
Inputs:
  Alice (1024 bits): padded_msg1[512] || C1[256] || C2[256]
  Bob   (1024 bits): padded_msg2[512] || C1[256] || C2[256]

Logic:
  1. Verify C1_alice == C1_bob AND C2_alice == C2_bob  (consistency)
  2. h1 = SHA-256(padded_msg1), h2 = SHA-256(padded_msg2)
  3. valid = (h1 == C1) AND (h2 == C2) AND consistency
  4. cmp = v1 > v2  (unsigned 64-bit)

Outputs (2 bits):
  output[0] = valid
  output[1] = v1 > v2
```

~236K gates, ~46K AND gates (~1.4 MB garbled table).

## Prerequisites

- CMake >= 3.12
- C++14 compiler (g++ or clang++)
- OpenSSL development headers
- Python 3 (for circuit composition)

### macOS

```bash
brew install cmake openssl pkg-config
```

### Ubuntu/Debian

```bash
sudo apt-get install build-essential cmake libssl-dev git pkg-config
```

## Build

```bash
# 1. Install emp-toolkit dependencies
bash scripts/install_deps.sh

# 2. Generate the composed Bristol Format circuit
python3 scripts/compose_circuit.py

# 3. Build the executable
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Run

Each party provides their own secret value and randomness, plus both public commitments.

- `C1 = SHA-256(v1 || r1)` — Alice's commitment
- `C2 = SHA-256(v2 || r2)` — Bob's commitment

Terminal 1 (Alice):
```bash
./build/sha256_compare 1 12345 \
  --v 100 \
  --r <64-hex-chars-randomness> \
  --c1 <64-hex-chars-C1> \
  --c2 <64-hex-chars-C2> \
  --circuit circuits/sha256_compare.txt
```

Terminal 2 (Bob):
```bash
./build/sha256_compare 2 12345 127.0.0.1 \
  --v 50 \
  --r <64-hex-chars-randomness> \
  --c1 <64-hex-chars-C1> \
  --c2 <64-hex-chars-C2> \
  --circuit circuits/sha256_compare.txt
```

### Arguments

| Arg | Description |
|-----|-------------|
| `<party>` | 1 (Alice/garbler) or 2 (Bob/evaluator) |
| `<port>` | TCP port for connection |
| `[host]` | Host address (required for Bob) |
| `--v` | Secret uint64 value |
| `--r` | 256-bit randomness as 64 hex characters |
| `--c1` | Commitment C1 = SHA-256(v1\|\|r1), 64 hex chars |
| `--c2` | Commitment C2 = SHA-256(v2\|\|r2), 64 hex chars |
| `--circuit` | Path to composed Bristol circuit file |

### Expected Results

- **Valid commitments, v1 > v2**: `Result: v1 > v2`
- **Valid commitments, v1 <= v2**: `Result: v1 <= v2`
- **Invalid commitment**: `ABORT: commitment verification failed`

## SHA-256 Padding

The host program pads the 320-bit message (v[64] || r[256]) to 512 bits per SHA-256 spec:

```
v[64] | r[256] | 1 | 0*127 | 0x0000000000000140[64]
```

This is handled automatically by the `sha256_pad_message()` function.
