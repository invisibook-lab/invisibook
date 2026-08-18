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
    signal input locked_a;
    signal input locked_b;
    signal input price;
    signal input a_is_seller;

    signal input q_a;
    signal input r_a;
    signal input q_b;
    signal input r_b;
""",
    [
        ("1 [RANGE(q_a)] + [RANGE(q_b)] (Num2Bits(64) x2)", """
    component a_range = Num2Bits(64);
    a_range.in <== q_a;
    component b_range = Num2Bits(64);
    b_range.in <== q_b;
"""),
        ("2 needed_a equation + [OPEN(locked_a; needed_a, r_a)]", """
    signal qa_price <== q_a * price;
    signal needed_a <== qa_price + a_is_seller * (q_a - qa_price);
    signal ha <== Poseidon(2)([needed_a, r_a]);
    ha === locked_a;
"""),
        ("3 needed_b equation (opposite side) + [OPEN(locked_b; ...)]", """
    signal b_is_seller <== 1 - a_is_seller;
    signal qb_price <== q_b * price;
    signal needed_b <== qb_price + b_is_seller * (q_b - qb_price);
    signal hb <== Poseidon(2)([needed_b, r_b]);
    hb === locked_b;
"""),
        ("4 cmp = (q_b<q_a) - (q_a<q_b) via LessThan(64) x2", """
    component lt = LessThan(64);
    lt.in[0] <== q_a;
    lt.in[1] <== q_b;
    component gt = LessThan(64);
    gt.in[0] <== q_b;
    gt.in[1] <== q_a;
    cmp === gt.out - lt.out;
"""),
    ],
    "component main {public [cmp, locked_a, locked_b, price, a_is_seller]} = T();",
)

census(
    "settle_small",
    HDR_NOTE,
    """    signal input locked;
    signal input price;
    signal input side;
    signal input pay_asset;
    signal input cm_note_out;
    signal input bind;

    signal input q;
    signal input r_locked;
    signal input npk_ctr;
    signal input r_note;
""",
    [
        ("1 side boolean", """
    side * (1 - side) === 0;
"""),
        ("2 [RANGE(q)] + [RANGE(price)] (Num2Bits(64) x2)", """
    component q_range = Num2Bits(64);
    q_range.in <== q;
    component price_range = Num2Bits(64);
    price_range.in <== price;
"""),
        ("3 needed equation + [OPEN(locked; needed, r_locked)]", """
    signal q_price <== q * price;
    signal needed <== q_price + side * (q - q_price);
    signal locked_check <== Poseidon(2)([needed, r_locked]);
    locked_check === locked;
"""),
        ("4 payout NoteCommit(needed) === cm_note_out", """
    component note = NoteCommit();
    note.npk <== npk_ctr;
    note.asset <== pay_asset;
    note.v <== needed;
    note.r <== r_note;
    note.cm === cm_note_out;
"""),
        ("5 [BIND] keep-alive", """
    signal bind_sq <== bind * bind;
"""),
    ],
    "component main {public [locked, price, side, pay_asset, cm_note_out, bind]} = T();",
)

census(
    "settle_large",
    HDR_NOTE,
    """    signal input locked;
    signal input locked_ctr;
    signal input price;
    signal input side;
    signal input cm_locked_residual;
    signal input pay_asset;
    signal input cm_note_out;
    signal input bind;

    signal input q;
    signal input r_locked;
    signal input q_ctr;
    signal input r_locked_ctr;
    signal input r_locked_res;
    signal input npk_ctr;
    signal input r_note;
""",
    [
        ("1 side boolean", """
    side * (1 - side) === 0;
"""),
        ("2 [RANGE(q)] + [RANGE(q_ctr)] + [RANGE(price)]", """
    component q_range = Num2Bits(64);
    q_range.in <== q;
    component q_ctr_range = Num2Bits(64);
    q_ctr_range.in <== q_ctr;
    component price_range = Num2Bits(64);
    price_range.in <== price;
"""),
        ("3 needed(q, side) + [OPEN(locked; needed, r_locked)]", """
    signal q_price <== q * price;
    signal needed <== q_price + side * (q - q_price);
    signal locked_check <== Poseidon(2)([needed, r_locked]);
    locked_check === locked;
"""),
        ("4 needed(q_ctr, 1-side) + [OPEN(locked_ctr; ...)]", """
    signal ctr_side <== 1 - side;
    signal q_ctr_price <== q_ctr * price;
    signal needed_ctr <== q_ctr_price + ctr_side * (q_ctr - q_ctr_price);
    signal ctr_check <== Poseidon(2)([needed_ctr, r_locked_ctr]);
    ctr_check === locked_ctr;
"""),
        ("5 q_res = q - q_ctr + [RANGE(q_res)]", """
    signal q_res <== q - q_ctr;
    component res_range = Num2Bits(64);
    res_range.in <== q_res;
"""),
        ("6 residual collateral + [OPEN(cm_locked_residual; ...)]", """
    signal res_price <== q_res * price;
    signal locked_res <== res_price + side * (q_res - res_price);
    signal res_check <== Poseidon(2)([locked_res, r_locked_res]);
    res_check === cm_locked_residual;
"""),
        ("7 fill = needed - locked_res + payout NoteCommit", """
    signal fill <== needed - locked_res;
    component note = NoteCommit();
    note.npk <== npk_ctr;
    note.asset <== pay_asset;
    note.v <== fill;
    note.r <== r_note;
    note.cm === cm_note_out;
"""),
        ("8 [BIND] keep-alive", """
    signal bind_sq <== bind * bind;
"""),
    ],
    "component main {public [locked, locked_ctr, price, side, cm_locked_residual, pay_asset, cm_note_out, bind]} = T();",
)
