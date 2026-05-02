#!/usr/bin/env python3
"""
Compose a Bristol Format circuit for SHA-256 commitment verification + comparison.

Circuit logic:
  1. Verify C1_alice == C1_bob AND C2_alice == C2_bob (commitment consistency)
  2. Compute h1 = SHA-256(padded_msg1), h2 = SHA-256(padded_msg2)
  3. Check h1 == C1 AND h2 == C2 (commitment verification)
  4. If all valid, output v1 > v2 (unsigned 64-bit comparison)

Input wire layout (big-endian bit encoding):
  Alice (n1=1024): padded_msg1[512] || C1[256] || C2[256]
  Bob   (n2=1024): padded_msg2[512] || C1[256] || C2[256]

  padded_msg = v[64] || r[256] || 1 || 0*127 || 0x0000000000000140[64]

Output (2 bits):
  output[0] = valid (consistency + commitment checks all passed)
  output[1] = v1 > v2
"""

import os
import sys
import urllib.request


SHA256_URL = (
    "https://raw.githubusercontent.com/emp-toolkit/emp-tool/"
    "master/emp-tool/circuits/files/bristol_format/sha-256.txt"
)


def parse_bristol(filepath):
    """Parse a Bristol Format circuit file. Returns (num_gates, num_wires, n1, n2, n3, gates)."""
    with open(filepath, "r") as f:
        lines = f.readlines()

    num_gates, num_wires = map(int, lines[0].split())
    n1, n2, n3 = map(int, lines[1].split())

    # Skip blank lines after header
    idx = 2
    while idx < len(lines) and lines[idx].strip() == "":
        idx += 1

    gates = []
    for line in lines[idx:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        nin = int(parts[0])
        nout = int(parts[1])
        if nin == 2:
            gates.append((nin, nout, int(parts[2]), int(parts[3]), int(parts[4]), parts[5]))
        elif nin == 1:
            gates.append((nin, nout, int(parts[2]), -1, int(parts[3]), parts[4]))
        else:
            raise ValueError(f"Unsupported gate with {nin} inputs: {line}")

    assert len(gates) == num_gates, f"Parsed {len(gates)} gates, expected {num_gates}"
    return num_gates, num_wires, n1, n2, n3, gates


def compose_circuit(sha256_path, output_path):
    sha_ngates, sha_nwires, sha_n1, sha_n2, sha_n3, sha_gates = parse_bristol(sha256_path)

    assert sha_n1 == 512, f"Expected SHA-256 n1=512, got {sha_n1}"
    assert sha_n3 == 256, f"Expected SHA-256 n3=256, got {sha_n3}"

    SHA_INPUT = sha_n1       # 512
    SHA_OUTPUT = sha_n3      # 256

    # Our composed circuit parameters
    #   Alice (n1=1024): padded_msg1[512] || C1[256] || C2[256]
    #   Bob   (n2=1024): padded_msg2[512] || C1[256] || C2[256]
    N1 = 1024  # Alice
    N2 = 1024  # Bob
    N3 = 2     # output: [valid, v1>v2]
    TOTAL_INPUT = N1 + N2    # 2048

    # Alice wire ranges
    ALICE_MSG   = (0, 512)       # 0..511
    ALICE_C1    = (512, 768)     # 512..767
    ALICE_C2    = (768, 1024)    # 768..1023
    # Bob wire ranges
    BOB_MSG     = (N1, N1+512)           # 1024..1535
    BOB_C1      = (N1+512, N1+768)       # 1536..1791
    BOB_C2      = (N1+768, N1+1024)      # 1792..2047

    all_gates = []
    next_wire = TOTAL_INPUT

    # ── Constant-zero wire ──────────────────────────────────────────────
    const_0 = next_wire
    all_gates.append(f"2 1 0 0 {const_0} XOR")
    next_wire += 1

    # ── SHA-256 Instance 1 (Alice message → wires 0..511) ──────────────
    offset1 = next_wire - SHA_INPUT
    for g in sha_gates:
        nin, nout, in1, in2, out, gtype = g
        r_in1 = in1 if in1 < SHA_INPUT else in1 + offset1
        r_out = out + offset1   # out >= SHA_INPUT always for gate outputs
        if nin == 2:
            r_in2 = in2 if in2 < SHA_INPUT else in2 + offset1
            all_gates.append(f"2 1 {r_in1} {r_in2} {r_out} {gtype}")
        else:
            all_gates.append(f"1 1 {r_in1} {r_out} {gtype}")
    next_wire = (sha_nwires - 1) + offset1 + 1
    sha1_out_start = (sha_nwires - SHA_OUTPUT) + offset1

    # ── SHA-256 Instance 2 (Bob message → wires 1024..1535) ────────────
    offset2 = next_wire - SHA_INPUT
    for g in sha_gates:
        nin, nout, in1, in2, out, gtype = g
        r_in1 = (in1 + N1) if in1 < SHA_INPUT else (in1 + offset2)
        r_out = out + offset2
        if nin == 2:
            r_in2 = (in2 + N1) if in2 < SHA_INPUT else (in2 + offset2)
            all_gates.append(f"2 1 {r_in1} {r_in2} {r_out} {gtype}")
        else:
            all_gates.append(f"1 1 {r_in1} {r_out} {gtype}")
    next_wire = (sha_nwires - 1) + offset2 + 1
    sha2_out_start = (sha_nwires - SHA_OUTPUT) + offset2

    # ── Helper: 256-bit equality check ─────────────────────────────────
    def eq_check_256(a_start, b_start):
        """Emit gates for 256-bit equality. Returns the result wire."""
        nonlocal next_wire
        bits = []
        for i in range(256):
            xor_w = next_wire
            all_gates.append(f"2 1 {a_start + i} {b_start + i} {xor_w} XOR")
            next_wire += 1
            inv_w = next_wire
            all_gates.append(f"1 1 {xor_w} {inv_w} INV")
            next_wire += 1
            bits.append(inv_w)
        acc = bits[0]
        for i in range(1, 256):
            and_w = next_wire
            all_gates.append(f"2 1 {acc} {bits[i]} {and_w} AND")
            next_wire += 1
            acc = and_w
        return acc

    # ── Commitment consistency: C1_alice == C1_bob ─────────────────────
    c1_match = eq_check_256(ALICE_C1[0], BOB_C1[0])

    # ── Commitment consistency: C2_alice == C2_bob ─────────────────────
    c2_match = eq_check_256(ALICE_C2[0], BOB_C2[0])

    # ── Hash check 1: SHA-256(msg1) == C1 ──────────────────────────────
    eq1_wire = eq_check_256(sha1_out_start, ALICE_C1[0])

    # ── Hash check 2: SHA-256(msg2) == C2 ──────────────────────────────
    eq2_wire = eq_check_256(sha2_out_start, ALICE_C2[0])

    # ── Validity: AND(c1_match, c2_match, eq1, eq2) ───────────────────
    and1 = next_wire
    all_gates.append(f"2 1 {c1_match} {c2_match} {and1} AND")
    next_wire += 1
    and2 = next_wire
    all_gates.append(f"2 1 {eq1_wire} {eq2_wire} {and2} AND")
    next_wire += 1
    valid_wire = next_wire
    all_gates.append(f"2 1 {and1} {and2} {valid_wire} AND")
    next_wire += 1

    # ── 64-bit Unsigned Comparator: v1 > v2 ────────────────────────────
    # v1 = wires 0..63 (big-endian, index 0 = MSB)
    # v2 = wires 1024..1087
    V1 = 0
    V2 = N1   # 1024

    # MSB (bit index 0): result = v1[0] AND NOT(v2[0])
    not_v2_0 = next_wire
    all_gates.append(f"1 1 {V2} {not_v2_0} INV")
    next_wire += 1
    result = next_wire
    all_gates.append(f"2 1 {V1} {not_v2_0} {result} AND")
    next_wire += 1

    # Bits 1..63: MUX chain (from MSB to LSB)
    # If bits differ: result = v1[i]  (v1 has 1 → v1 > v2)
    # If bits same:   result = previous result
    for i in range(1, 64):
        v1_i = V1 + i
        v2_i = V2 + i

        sel = next_wire     # XOR(v1[i], v2[i]) — 1 if bits differ
        all_gates.append(f"2 1 {v1_i} {v2_i} {sel} XOR")
        next_wire += 1

        diff = next_wire    # XOR(prev_result, v1[i])
        all_gates.append(f"2 1 {result} {v1_i} {diff} XOR")
        next_wire += 1

        masked = next_wire  # AND(sel, diff)
        all_gates.append(f"2 1 {sel} {diff} {masked} AND")
        next_wire += 1

        new_result = next_wire  # XOR(prev_result, masked) = MUX output
        all_gates.append(f"2 1 {result} {masked} {new_result} XOR")
        next_wire += 1

        result = new_result

    cmp_wire = result

    # ── Output wires (must be the last N3 wires) ──────────────────────
    out_valid = next_wire
    all_gates.append(f"2 1 {valid_wire} {const_0} {out_valid} XOR")
    next_wire += 1

    out_cmp = next_wire
    all_gates.append(f"2 1 {cmp_wire} {const_0} {out_cmp} XOR")
    next_wire += 1

    # ── Write Bristol Format output ───────────────────────────────────
    total_gates = len(all_gates)
    total_wires = next_wire

    assert total_wires == TOTAL_INPUT + total_gates, (
        f"Wire count mismatch: {total_wires} != {TOTAL_INPUT} + {total_gates}"
    )

    with open(output_path, "w") as f:
        f.write(f"{total_gates} {total_wires}\n")
        f.write(f"{N1} {N2} {N3}\n")
        f.write("\n")
        for gate in all_gates:
            f.write(gate + "\n")

    print(f"Circuit written to {output_path}")
    print(f"  Total gates:  {total_gates}")
    print(f"  Total wires:  {total_wires}")
    print(f"  Inputs:       Alice={N1}, Bob={N2}")
    print(f"  Outputs:      {N3}")
    print(f"  SHA-256 gates (per instance): {sha_ngates}")

    # Gate breakdown
    sha_and = sum(1 for g in sha_gates if g[5] == "AND")
    sha_xor = sum(1 for g in sha_gates if g[5] == "XOR")
    sha_inv = sum(1 for g in sha_gates if g[5] == "INV")
    print(f"\n  Gate breakdown:")
    print(f"    SHA-256 x2:         {sha_ngates*2} (AND={sha_and*2}, XOR={sha_xor*2}, INV={sha_inv*2})")
    print(f"    Consistency x2:     {767*2}  (C1_alice==C1_bob, C2_alice==C2_bob)")
    print(f"    Hash eq checks x2:  {767*2}  (hash1==C1, hash2==C2)")
    print(f"    Validity AND:       3")
    print(f"    Comparator:         {2 + 63*4}")
    print(f"    Const+Output:       3")


def find_sha256_circuit():
    """Locate sha-256.txt from emp-tool source or download it."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    emp_dir = os.path.dirname(script_dir)

    search_paths = [
        os.path.join(emp_dir, "third_party", "src", "emp-tool",
                     "emp-tool", "circuits", "files", "bristol_format", "sha-256.txt"),
        os.path.join(emp_dir, "third_party", "install", "share",
                     "emp-tool", "circuits", "files", "bristol_format", "sha-256.txt"),
    ]

    for p in search_paths:
        if os.path.exists(p):
            return p

    # Try command-line argument
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        return sys.argv[1]

    # Auto-download into circuits/
    cached = os.path.join(emp_dir, "circuits", "sha-256.txt")
    if os.path.exists(cached):
        return cached

    print(f"sha-256.txt not found locally. Downloading from emp-toolkit...")
    os.makedirs(os.path.dirname(cached), exist_ok=True)
    urllib.request.urlretrieve(SHA256_URL, cached)
    print(f"  Saved to {cached}")
    return cached


def main():
    sha256_path = find_sha256_circuit()
    print(f"Using SHA-256 circuit: {sha256_path}")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    emp_dir = os.path.dirname(script_dir)
    output_path = os.path.join(emp_dir, "circuits", "sha256_compare.txt")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    compose_circuit(sha256_path, output_path)


if __name__ == "__main__":
    main()
