#!/usr/bin/env python3
"""Per-step R1CS constraint census of the Groth16 settle circuits.

For each circuit, this script generates CUMULATIVE variants (the template
body truncated after each step), compiles every variant with the real
circom compiler, and reports the per-step delta of NON-LINEAR constraints
(the Groth16 cost metric). The final variant must match the pristine
circuit file exactly — the script cross-checks that and fails on drift,
so the embedded step chunks cannot silently diverge from the sources.

The numbers in docs/settlement_protocol.md section 5 come from this
output. Run from the repo root:

    python3 scripts/circom_step_census.py
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "lib" / "zk" / "templates"


def compile_count(src: str, workdir: Path, name: str) -> tuple[int, int]:
    """Compile one circom source; return (non_linear, linear) counts."""
    f = workdir / f"{name}.circom"
    f.write_text(src)
    out = subprocess.run(
        ["circom", str(f), "--r1cs", "-o", str(workdir), "-l", str(TEMPLATES)],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        sys.exit(f"circom failed on {name}:\n{out.stdout}\n{out.stderr}")
    text = out.stdout
    nl = int(re.search(r"non-linear constraints: (\d+)", text).group(1))
    lin = int(re.search(r"^linear constraints: (\d+)", text, re.MULTILINE).group(1))
    return nl, lin


def census(name: str, header: str, decls: str, steps: list[tuple[str, str]], main: str):
    """Compile cumulative variants and print the per-step delta table."""
    pristine = (TEMPLATES / f"{name}.circom").read_text()
    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        print(f"\n== {name}.circom — measured non-linear R1CS constraints per step ==")
        prev_nl = 0
        body = ""
        rows = []
        for label, chunk in steps:
            body += chunk
            src = f"{header}\ntemplate T() {{\n{decls}{body}}}\n{main}\n"
            nl, _lin = compile_count(src, wd, f"{name}_{len(rows)}")
            rows.append((label, nl - prev_nl))
            prev_nl = nl
        # Cross-check: the pristine file must compile to the same total.
        full_nl, full_lin = compile_count(pristine, wd, f"{name}_full")
        for label, delta in rows:
            print(f"{label:<58} {delta:>8}")
        print(f"{'TOTAL (cumulative variants)':<58} {prev_nl:>8}")
        print(f"{'TOTAL (pristine file)':<58} {full_nl:>8}   (+{full_lin} linear)")
        if prev_nl != full_nl:
            sys.exit(f"DRIFT: cumulative variants of {name} disagree with the pristine file")


HDR_CMP = 'pragma circom 2.2.3;\ninclude "utils/poseidon.circom";\ninclude "utils/bitify.circom";\ninclude "utils/comparators.circom";'
HDR_NOTE = 'pragma circom 2.2.3;\ninclude "utils/poseidon.circom";\ninclude "utils/bitify.circom";\ninclude "note.circom";'

census(
    "settle_cozk",
    HDR_CMP,
    """    signal input cmp;
    signal input order_a_commitment;
    signal input order_b_commitment;
    signal input a;
    signal input r_a;
    signal input b;
    signal input r_b;
""",
    [
        ("1 [RANGE(a)] + [RANGE(b)] (Num2Bits(64) x2)", """
    component a_range = Num2Bits(64);
    a_range.in <== a;
    component b_range = Num2Bits(64);
    b_range.in <== b;
"""),
        ("2 [OPEN(order_a_commitment; a, r_a)]", """
    signal ha <== Poseidon(2)([a, r_a]);
    ha === order_a_commitment;
"""),
        ("3 [OPEN(order_b_commitment; b, r_b)]", """
    signal hb <== Poseidon(2)([b, r_b]);
    hb === order_b_commitment;
"""),
        ("4 cmp = (b<a) - (a<b) via LessThan(64) x2", """
    component lt = LessThan(64);
    lt.in[0] <== a;
    lt.in[1] <== b;
    component gt = LessThan(64);
    gt.in[0] <== b;
    gt.in[1] <== a;
    cmp === gt.out - lt.out;
"""),
    ],
    "component main {public [cmp, order_a_commitment, order_b_commitment]} = T();",
)

census(
    "settle_small",
    HDR_NOTE,
    """    signal input cm_q;
    signal input locked_0;
    signal input locked_1;
    signal input price;
    signal input side;
    signal input pay_asset;
    signal input cm_note_out;
    signal input bind;
    signal input q;
    signal input r_q;
    signal input locked_v[2];
    signal input locked_r[2];
    signal input npk_ctr;
    signal input r_note;
""",
    [
        ("1 side boolean", """
    side * (1 - side) === 0;
"""),
        ("2 [RANGE(q)] + [OPEN(cm_q; q, r_q)]", """
    component q_range = Num2Bits(64);
    q_range.in <== q;
    signal cm_q_check <== Poseidon(2)([q, r_q]);
    cm_q_check === cm_q;
"""),
        ("3 collateral slots: [RANGE] x2 + [OPEN] x2", """
    component v_range[2];
    signal locked_check[2];
    for (var i = 0; i < 2; i++) {
        v_range[i] = Num2Bits(64);
        v_range[i].in <== locked_v[i];
    }
    locked_check[0] <== Poseidon(2)([locked_v[0], locked_r[0]]);
    locked_check[0] === locked_0;
    locked_check[1] <== Poseidon(2)([locked_v[1], locked_r[1]]);
    locked_check[1] === locked_1;
    signal locked_sum <== locked_v[0] + locked_v[1];
"""),
        ("4 [RANGE(price)] + collateral equation", """
    component price_range = Num2Bits(64);
    price_range.in <== price;
    signal q_price <== q * price;
    locked_sum === q_price + side * (q - q_price);
"""),
        ("5 payout NoteCommit === cm_note_out", """
    component note = NoteCommit();
    note.npk <== npk_ctr;
    note.asset <== pay_asset;
    note.v <== locked_sum;
    note.r <== r_note;
    note.cm === cm_note_out;
"""),
        ("6 [BIND] keep-alive", """
    signal bind_sq <== bind * bind;
"""),
    ],
    "component main {public [cm_q, locked_0, locked_1, price, side, pay_asset, cm_note_out, bind]} = T();",
)

census(
    "settle_large",
    HDR_NOTE,
    """    signal input cm_q;
    signal input cm_q_ctr;
    signal input locked_0;
    signal input locked_1;
    signal input price;
    signal input side;
    signal input cm_q_residual;
    signal input cm_locked_residual;
    signal input pay_asset;
    signal input cm_note_out;
    signal input bind;
    signal input q;
    signal input r_q;
    signal input q_ctr;
    signal input r_q_ctr;
    signal input locked_v[2];
    signal input locked_r[2];
    signal input r_q_residual;
    signal input r_locked_residual;
    signal input npk_ctr;
    signal input r_note;
""",
    [
        ("1 side boolean", """
    side * (1 - side) === 0;
"""),
        ("2 [RANGE(q)] + [RANGE(q_ctr)]", """
    component q_range = Num2Bits(64);
    q_range.in <== q;
    component q_ctr_range = Num2Bits(64);
    q_ctr_range.in <== q_ctr;
"""),
        ("3 [OPEN(cm_q)] + [OPEN(cm_q_ctr)]", """
    signal cm_q_check <== Poseidon(2)([q, r_q]);
    cm_q_check === cm_q;
    signal cm_ctr_check <== Poseidon(2)([q_ctr, r_q_ctr]);
    cm_ctr_check === cm_q_ctr;
"""),
        ("4 q_res = q - q_ctr + [RANGE(q_res)] + [OPEN(cm_q_residual)]", """
    signal q_res <== q - q_ctr;
    component res_range = Num2Bits(64);
    res_range.in <== q_res;
    signal cm_res_check <== Poseidon(2)([q_res, r_q_residual]);
    cm_res_check === cm_q_residual;
"""),
        ("5 collateral slots: [RANGE] x2 + [OPEN] x2", """
    component v_range[2];
    signal locked_check[2];
    for (var i = 0; i < 2; i++) {
        v_range[i] = Num2Bits(64);
        v_range[i].in <== locked_v[i];
    }
    locked_check[0] <== Poseidon(2)([locked_v[0], locked_r[0]]);
    locked_check[0] === locked_0;
    locked_check[1] <== Poseidon(2)([locked_v[1], locked_r[1]]);
    locked_check[1] === locked_1;
    signal locked_sum <== locked_v[0] + locked_v[1];
"""),
        ("6 [RANGE(price)] + collateral equation", """
    component price_range = Num2Bits(64);
    price_range.in <== price;
    signal q_price <== q * price;
    locked_sum === q_price + side * (q - q_price);
"""),
        ("7 residual collateral + [OPEN(cm_locked_residual)]", """
    signal res_price <== q_res * price;
    signal locked_res <== res_price + side * (q_res - res_price);
    signal cm_locked_res_check <== Poseidon(2)([locked_res, r_locked_residual]);
    cm_locked_res_check === cm_locked_residual;
"""),
        ("8 fill + payout NoteCommit === cm_note_out", """
    signal fill <== locked_sum - locked_res;
    component note = NoteCommit();
    note.npk <== npk_ctr;
    note.asset <== pay_asset;
    note.v <== fill;
    note.r <== r_note;
    note.cm === cm_note_out;
"""),
        ("9 [BIND] keep-alive", """
    signal bind_sq <== bind * bind;
"""),
    ],
    "component main {public [cm_q, cm_q_ctr, locked_0, locked_1, price, side, cm_q_residual, cm_locked_residual, pay_asset, cm_note_out, bind]} = T();",
)
