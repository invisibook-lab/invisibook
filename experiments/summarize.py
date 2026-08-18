#!/usr/bin/env python3
"""Turn the raw experiment records into summaries.

Each experiment script calls one subcommand:

    summarize.py rq1 --raw ... --traffic ... --json-out ... --md-out ...
    summarize.py rq2 --index ... --json-out ... --md-out ... --csv-out ...
    summarize.py rq3 --out-dir ... --runs N --json-out ... --md-out ...

Every summary keeps the median and the 95th percentile, because a small
sample of a heavy-tailed measurement has no meaningful mean.
"""

import argparse
import json
import re
from pathlib import Path


# ────────────────────────────── statistics ──────────────────────────────


def percentile(values, q):
    """Linear-interpolated percentile of `values`; `q` is in [0, 100].
    `values` may be unsorted but must not be empty."""
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    pos = (len(xs) - 1) * q / 100.0
    low = int(pos)
    high = min(low + 1, len(xs) - 1)
    return xs[low] + (xs[high] - xs[low]) * (pos - low)


def stats(values):
    """Median, 95th percentile, minimum, maximum and count of `values`.
    Returns zeros when `values` is empty."""
    xs = [v for v in values if v is not None]
    if not xs:
        return {"median": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0, "n": 0}
    return {
        "median": percentile(xs, 50),
        "p95": percentile(xs, 95),
        "min": min(xs),
        "max": max(xs),
        "n": len(xs),
    }


def read_json(path):
    """Parse a JSON file, or return None when it is missing or broken."""
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def ms(x):
    """Format milliseconds with a thin space every three digits."""
    return f"{x:,.0f}".replace(",", " ")


def gib(x):
    """Format bytes as GiB."""
    return f"{x / 1024 ** 3:.2f}"


def mib(x):
    """Format bytes as MiB."""
    return f"{x / 1024 ** 2:.1f}"


# ──────────────────────────────── RQ1 ───────────────────────────────────


def rq1(args):
    raw = read_json(args.raw) or {}
    traffic = read_json(args.traffic) or {}
    env = read_json(args.environment) or {}

    single_prove = raw.get("baseline_single_prover", {}).get("prove_ms", [])
    single_verify = raw.get("baseline_single_prover", {}).get("verify_ms", [])

    mock = raw.get("cozk2p_mock_inprocess", [])
    mock_phase = lambda key: stats([r.get(key, 0.0) for r in mock])

    quic = raw.get("cozk2p_quic_2process", [])
    # One record per party per run: both traders run the same protocol.
    parties = [p for run in quic for p in run.get("per_party", [])]
    quic_phase = lambda key: stats([p.get(key, 0.0) for p in parties])

    # The cryptographic total of one session: build + prove + open + verify.
    def crypto_total(rec):
        return (
            rec.get("build_ms", 0.0)
            + rec.get("prove_ms", 0.0)
            + rec.get("open_ms", 0.0)
            + rec.get("verify_ms", 0.0)
        )

    mock_total = stats([crypto_total(r) for r in mock])
    quic_total = stats([crypto_total(p) for p in parties])
    single_total = stats(
        [p + v for p, v in zip(single_prove, single_verify)]
    )

    summary = {
        "environment": env,
        "circuit": {
            "turboplonk_gates": raw.get("circuit_gates"),
            "public_signals": raw.get("public_signals"),
            "proof_bytes_compressed": raw.get("proof_size_bytes", {}).get("compressed"),
            "proof_bytes_uncompressed": raw.get("proof_size_bytes", {}).get(
                "uncompressed"
            ),
            "verifying_key_bytes_compressed": raw.get("vk_size_bytes_compressed"),
        },
        "single_prover": {
            "prove_ms": stats(single_prove),
            "verify_ms": stats(single_verify),
            "total_ms": single_total,
        },
        "two_party_in_process": {
            "build_ms": mock_phase("build_ms"),
            "prove_ms": mock_phase("prove_ms"),
            "open_ms": mock_phase("open_ms"),
            "verify_ms": mock_phase("verify_ms"),
            "session_overhead_ms": mock_phase("session_overhead_ms"),
            "total_ms": mock_total,
        },
        "two_party_quic": {
            "build_ms": quic_phase("build_ms"),
            "prove_ms": quic_phase("prove_ms"),
            "open_ms": quic_phase("open_ms"),
            "verify_ms": quic_phase("verify_ms"),
            "total_ms": quic_total,
            "session_wall_clock_ms": stats([p.get("total_ms", 0.0) for p in parties]),
            "peak_rss_bytes": stats([p.get("peak_rss_bytes", 0) for p in parties]),
        },
        "traffic_per_trader": {
            "a_to_b_bytes": traffic.get("a_to_b_bytes", 0),
            "b_to_a_bytes": traffic.get("b_to_a_bytes", 0),
            "a_to_b_datagrams": traffic.get("a_to_b_datagrams", 0),
            "b_to_a_datagrams": traffic.get("b_to_a_datagrams", 0),
        },
    }
    if single_total["median"] > 0:
        summary["overhead_over_single_prover"] = {
            "in_process": mock_total["median"] / single_total["median"],
            "quic": quic_total["median"] / single_total["median"],
        }

    Path(args.json_out).write_text(json.dumps(summary, indent=2))

    # Stacked-bar input: one row per configuration, one column per phase.
    rows = [
        ("single prover", 0.0, summary["single_prover"]["prove_ms"]["median"], 0.0,
         summary["single_prover"]["verify_ms"]["median"]),
        ("in-process two-party",
         summary["two_party_in_process"]["build_ms"]["median"],
         summary["two_party_in_process"]["prove_ms"]["median"],
         summary["two_party_in_process"]["open_ms"]["median"],
         summary["two_party_in_process"]["verify_ms"]["median"]),
        ("two-process QUIC",
         summary["two_party_quic"]["build_ms"]["median"],
         summary["two_party_quic"]["prove_ms"]["median"],
         summary["two_party_quic"]["open_ms"]["median"],
         summary["two_party_quic"]["verify_ms"]["median"]),
    ]
    with open(args.csv_out, "w") as f:
        f.write("configuration,build_ms,prove_ms,open_ms,verify_ms\n")
        for name, b, p, o, v in rows:
            f.write(f"{name},{b:.1f},{p:.1f},{o:.1f},{v:.1f}\n")

    q = summary["two_party_quic"]
    m = summary["two_party_in_process"]
    s = summary["single_prover"]
    lines = [
        "# RQ1 — the cost of the cryptography",
        "",
        f"Runs: {q['total_ms']['n'] // 2 if q['total_ms']['n'] else 0} sessions over QUIC "
        f"(two traders each), {m['total_ms']['n']} in-process sessions, "
        f"{s['prove_ms']['n']} single-prover runs.",
        "",
        "## Latency per phase (ms)",
        "",
        "| configuration | build | prove | open | verify | total | p95 total |",
        "|---|---:|---:|---:|---:|---:|---:|",
        f"| single prover | — | {ms(s['prove_ms']['median'])} | — | "
        f"{s['verify_ms']['median']:.1f} | {ms(s['total_ms']['median'])} | "
        f"{ms(s['total_ms']['p95'])} |",
        f"| two parties, one process | {ms(m['build_ms']['median'])} | "
        f"{ms(m['prove_ms']['median'])} | {ms(m['open_ms']['median'])} | "
        f"{m['verify_ms']['median']:.1f} | {ms(m['total_ms']['median'])} | "
        f"{ms(m['total_ms']['p95'])} |",
        f"| two processes, QUIC | {ms(q['build_ms']['median'])} | "
        f"{ms(q['prove_ms']['median'])} | {ms(q['open_ms']['median'])} | "
        f"{q['verify_ms']['median']:.1f} | {ms(q['total_ms']['median'])} | "
        f"{ms(q['total_ms']['p95'])} |",
        "",
    ]
    if "overhead_over_single_prover" in summary:
        o = summary["overhead_over_single_prover"]
        lines += [
            f"Overhead over the single prover: {o['in_process']:.1f}x in one "
            f"process, {o['quic']:.1f}x over QUIC.",
            "",
        ]
    t = summary["traffic_per_trader"]
    c = summary["circuit"]
    lines += [
        "## Resources and constant sizes",
        "",
        "| metric | value |",
        "|---|---:|",
        f"| peak memory per trader (median) | {gib(q['peak_rss_bytes']['median'])} GiB |",
        f"| peak memory per trader (p95) | {gib(q['peak_rss_bytes']['p95'])} GiB |",
        f"| trader A sends | {mib(t['a_to_b_bytes'])} MiB in {t['a_to_b_datagrams']:,} datagrams |",
        f"| trader B sends | {mib(t['b_to_a_bytes'])} MiB in {t['b_to_a_datagrams']:,} datagrams |",
        f"| TurboPlonk gates | {c['turboplonk_gates']} |",
        f"| public signals | {c['public_signals']} |",
        f"| proof size | {c['proof_bytes_compressed']} B compressed "
        f"({c['proof_bytes_uncompressed']} B uncompressed) |",
        f"| verifying key size | {c['verifying_key_bytes_compressed']} B compressed |",
        "",
        f"Machine: {env.get('cpu', '?')}, {env.get('logical_cpus', '?')} logical CPUs, "
        f"{env.get('memory_gib', '?')} GiB, {env.get('os', '?')}, kernel "
        f"{env.get('kernel', '?')}.",
        "",
    ]
    Path(args.md_out).write_text("\n".join(lines))


# ──────────────────────────────── RQ2 ───────────────────────────────────


def rq2(args):
    index = read_json(args.index) or {}
    env = read_json(args.environment) or {}
    # RQ1 measured the same session WITHOUT the relay. The difference at
    # 0 ms is what the relay itself costs.
    baseline = read_json(args.baseline) if args.baseline else None
    points = []

    # The index names files next to itself, so a result directory moves.
    here = Path(args.index).parent
    for point in index.get("points", []):
        bench = read_json(here / point["bench"]) or {}
        traffic = read_json(here / point["traffic"]) or {}
        parties = [
            p for run in bench.get("cozk2p_quic_2process", []) for p in run.get("per_party", [])
        ]
        phase = lambda key: stats([p.get(key, 0.0) for p in parties])
        total = stats(
            [
                p.get("build_ms", 0.0)
                + p.get("prove_ms", 0.0)
                + p.get("open_ms", 0.0)
                + p.get("verify_ms", 0.0)
                for p in parties
            ]
        )
        points.append(
            {
                "rtt_ms": point["rtt_ms"],
                "one_way_delay_ms": point["one_way_delay_ms"],
                "status": point["status"],
                "sessions": len(parties) // 2,
                "build_ms": phase("build_ms"),
                "prove_ms": phase("prove_ms"),
                "open_ms": phase("open_ms"),
                "verify_ms": phase("verify_ms"),
                "total_ms": total,
                # The relay counts the whole point; report one session.
                "traffic_bytes_per_session": (
                    traffic.get("a_to_b_bytes", 0) + traffic.get("b_to_a_bytes", 0)
                )
                / max(len(parties) // 2, 1),
            }
        )

    summary = {
        "environment": env,
        "rate_mbit": index.get("rate_mbit"),
        "runs_per_point": index.get("runs"),
        "points": points,
    }
    if baseline:
        summary["direct_quic_total_ms"] = (
            baseline.get("two_party_quic", {}).get("total_ms", {}).get("median")
        )
    Path(args.json_out).write_text(json.dumps(summary, indent=2))

    with open(args.csv_out, "w") as f:
        f.write("rtt_ms,build_ms,prove_ms,open_ms,verify_ms,total_ms,p95_total_ms\n")
        for p in points:
            f.write(
                f"{p['rtt_ms']},{p['build_ms']['median']:.1f},"
                f"{p['prove_ms']['median']:.1f},{p['open_ms']['median']:.1f},"
                f"{p['verify_ms']['median']:.1f},{p['total_ms']['median']:.1f},"
                f"{p['total_ms']['p95']:.1f}\n"
            )

    lines = [
        "# RQ2 — the effect of the round-trip time",
        "",
        f"Rate cap {summary['rate_mbit']} Mbit/s, {summary['runs_per_point']} sessions "
        "per point, medians of both traders.",
        "",
        "| RTT (ms) | build | prove | open | verify | total | p95 total |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for p in points:
        if p["status"] != "ok" or p["total_ms"]["n"] == 0:
            lines.append(f"| {p['rtt_ms']} | did not finish | | | | | |")
            continue
        lines.append(
            f"| {p['rtt_ms']} | {ms(p['build_ms']['median'])} | "
            f"{ms(p['prove_ms']['median'])} | {ms(p['open_ms']['median'])} | "
            f"{p['verify_ms']['median']:.1f} | {ms(p['total_ms']['median'])} | "
            f"{ms(p['total_ms']['p95'])} |"
        )
    ok = [p for p in points if p["status"] == "ok" and p["total_ms"]["n"]]
    if len(ok) >= 2:
        first, last = ok[0], ok[-1]
        growth = last["total_ms"]["median"] / max(first["total_ms"]["median"], 1e-9)
        lines += [
            "",
            f"From {first['rtt_ms']} ms to {last['rtt_ms']} ms the total grows "
            f"{growth:.1f}x, from {ms(first['total_ms']['median'])} ms to "
            f"{ms(last['total_ms']['median'])} ms.",
        ]
    lines += [
        "",
        f"Traffic per session (both directions): "
        f"{mib(ok[0]['traffic_bytes_per_session']) if ok else '0'} MiB.",
    ]
    direct = summary.get("direct_quic_total_ms")
    if direct and ok:
        lines += [
            "",
            f"The relay itself costs {ms(ok[0]['total_ms']['median'] - direct)} ms: "
            f"the same session without the relay (RQ1) takes {ms(direct)} ms, and "
            f"the 0 ms point here takes {ms(ok[0]['total_ms']['median'])} ms. Every "
            "point carries that same hop, so the points compare with each other.",
        ]
    lines.append("")
    Path(args.md_out).write_text("\n".join(lines))


# ──────────────────────────────── RQ3 ───────────────────────────────────

# Node log lines the summary reads.
VERIFY_RE = re.compile(r"\[zk\] (\S+) ok in ([0-9.]+) ms")
PAYLOAD_RE = re.compile(r"\[tx\] (\S+) payload (\d+) B")


def parse_node_log(path):
    """Collect the verification times and payload sizes the node logged.
    Returns (verifications, payloads) as name → list of values."""
    verifications, payloads = {}, {}
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return verifications, payloads
    for name, value in VERIFY_RE.findall(text):
        verifications.setdefault(name, []).append(float(value))
    for name, value in PAYLOAD_RE.findall(text):
        payloads.setdefault(name, []).append(int(value))
    return verifications, payloads


# Both traders submit these writings, for liveness. The first one takes
# effect and the chain rejects the second, so a trade needs only one copy.
SUBMITTED_TWICE = ("SubmitCompareCoZk2p", "SettlePair")


def effective_payload(payloads, runs):
    """Bytes one trade must put on chain: every writing counted once per
    effect. `payloads` maps a writing name to the sizes the node logged,
    and `runs` is the number of trades those sizes come from."""
    total = 0.0
    for name, values in payloads.items():
        if not values:
            continue
        median = percentile(values, 50)
        count = 1 if name in SUBMITTED_TWICE else len(values) / max(runs, 1)
        total += median * count
    return round(total)


def rq3(args):
    env = read_json(args.environment) or {}
    out_dir = Path(args.out_dir)
    runs = []
    verifications, payloads = {}, {}

    for i in range(1, args.runs + 1):
        record = read_json(out_dir / f"rq3_run{i}_stats.json")
        if record is None:
            continue
        runs.append(record)
        v, p = parse_node_log(out_dir / f"rq3_run{i}.log")
        for name, values in v.items():
            verifications.setdefault(name, []).extend(values)
        for name, values in p.items():
            payloads.setdefault(name, []).extend(values)

    if not runs:
        raise SystemExit("no run statistics found")

    def field(path, default=0.0):
        """Median over the runs of one dotted field of the run record."""
        values = []
        for r in runs:
            node = r
            for key in path.split("."):
                node = node.get(key, {}) if isinstance(node, dict) else default
            values.append(node if isinstance(node, (int, float)) else default)
        return stats(values)

    # The protocol steps, as the session recorded them, trader by trader.
    def steps(trader):
        labels = [label for label, _ in runs[0]["session"][trader]["steps"]]
        return [
            {
                "label": label,
                "ms": stats(
                    [
                        dict(r["session"][trader]["steps"]).get(label, 0.0)
                        for r in runs
                    ]
                ),
            }
            for label in labels
        ]

    alice_steps, bob_steps = steps("alice"), steps("bob")

    # Categories: what the trade spends its wall clock on. Both traders
    # settle at the same time, so one trader's session covers that span.
    # The four categories add up to the full trade.
    session_total = field("session.alice.total_ms")["median"]
    anchor_wait = field("session.alice.compare_onchain_wait_ms")["median"]
    crypto_ms = session_total - anchor_wait
    order_prove_ms = (
        field("order.alice.prove_ms")["median"] + field("order.bob.prove_ms")["median"]
    )
    chain_wait_ms = (
        field("order.alice.land_ms")["median"]
        + field("order.bob.land_ms")["median"]
        + field("order.match_ms")["median"]
        + anchor_wait
    )
    # What is left of the settlement driver: the rendezvous, each side's own
    # Groth16 settlement proof, the leg exchange, and the settlement
    # submission with its confirmation.
    settle_tail_ms = field("settle_ms")["median"] - session_total

    summary = {
        "environment": env,
        "runs": len(runs),
        "scenario": runs[0].get("scenario"),
        "order": {
            "alice_prove_ms": field("order.alice.prove_ms"),
            "alice_land_ms": field("order.alice.land_ms"),
            "bob_prove_ms": field("order.bob.prove_ms"),
            "bob_land_ms": field("order.bob.land_ms"),
            "match_ms": field("order.match_ms"),
        },
        "session": {
            trader: {
                key: field(f"session.{trader}.{key}")
                for key in (
                    "build_ms",
                    "prove_ms",
                    "open_ms",
                    "verify_ms",
                    "compare_onchain_wait_ms",
                    "leg_exchange_ms",
                    "total_ms",
                    "peak_rss_bytes",
                )
            }
            for trader in ("alice", "bob")
        },
        "steps": {"alice": alice_steps, "bob": bob_steps},
        "settle_ms": field("settle_ms"),
        "full_trade_ms": field("full_trade_ms"),
        "categories_ms": {
            "collaborative_cryptography": crypto_ms,
            "single_prover_order_proofs": order_prove_ms,
            "chain_waits": chain_wait_ms,
            "settlement_submission_and_legs": settle_tail_ms,
        },
        "chain_verification_ms": {
            name: stats(values) for name, values in sorted(verifications.items())
        },
        "onchain_payload_bytes": {
            name: {"per_writing": stats(values), "count": len(values),
                   "total": sum(values)}
            for name, values in sorted(payloads.items())
        },
        "onchain_payload_received_bytes": sum(sum(v) for v in payloads.values()),
        "onchain_payload_effective_bytes": effective_payload(payloads, len(runs)),
    }
    Path(args.json_out).write_text(json.dumps(summary, indent=2))

    lines = [
        "# RQ3 — the end-to-end cost of one trade",
        "",
        f"{summary['runs']} trade(s). Scenario: {summary['scenario']}.",
        "",
        "## Wall clock, step by step (ms, median)",
        "",
        "| step | trader A | trader B |",
        "|---|---:|---:|",
        f"| order proof (Groth16) | {ms(summary['order']['alice_prove_ms']['median'])} "
        f"| {ms(summary['order']['bob_prove_ms']['median'])} |",
        f"| order submission until it lands | "
        f"{ms(summary['order']['alice_land_ms']['median'])} | "
        f"{ms(summary['order']['bob_land_ms']['median'])} |",
        f"| matching | {ms(summary['order']['match_ms']['median'])} | "
        f"{ms(summary['order']['match_ms']['median'])} |",
    ]
    for a, b in zip(alice_steps, bob_steps):
        lines.append(f"| {a['label']} | {ms(a['ms']['median'])} | {ms(b['ms']['median'])} |")
    lines += [
        f"| session subprocess, total | "
        f"{ms(summary['session']['alice']['total_ms']['median'])} | "
        f"{ms(summary['session']['bob']['total_ms']['median'])} |",
        f"| settlement driver, both traders | {ms(summary['settle_ms']['median'])} | "
        f"{ms(summary['settle_ms']['median'])} |",
        f"| **full trade** | **{ms(summary['full_trade_ms']['median'])}** | |",
        "",
        "## Where the time goes",
        "",
        "| category | ms |",
        "|---|---:|",
        f"| collaborative cryptography | {ms(crypto_ms)} |",
        f"| single-prover order proofs | {ms(order_prove_ms)} |",
        f"| chain waits (blocks and polling) | {ms(chain_wait_ms)} |",
        f"| settlement submission, own leg and confirmation | {ms(settle_tail_ms)} |",
        "",
        "## What the chain does",
        "",
        "| proof | verifications | median (ms) | p95 (ms) |",
        "|---|---:|---:|---:|",
    ]
    for name, s in summary["chain_verification_ms"].items():
        lines.append(f"| {name} | {s['n']} | {s['median']:.2f} | {s['p95']:.2f} |")
    lines += [
        "",
        "| writing | submissions | payload each (B) | payload total (B) |",
        "|---|---:|---:|---:|",
    ]
    for name, p in summary["onchain_payload_bytes"].items():
        lines.append(
            f"| {name} | {p['count']} | {p['per_writing']['median']:.0f} | {p['total']} |"
        )
    lines += [
        "",
        f"On-chain payload of one trade: "
        f"{summary['onchain_payload_effective_bytes']} B. Both traders submit "
        "the comparison and the settlement for liveness, so the node receives "
        f"{summary['onchain_payload_received_bytes'] // max(summary['runs'], 1)} B "
        "and rejects the second copy of each.",
        "",
        f"Peak memory per trader: "
        f"{gib(summary['session']['alice']['peak_rss_bytes']['median'])} GiB (A), "
        f"{gib(summary['session']['bob']['peak_rss_bytes']['median'])} GiB (B).",
        "",
        f"Machine: {env.get('cpu', '?')}, {env.get('logical_cpus', '?')} logical CPUs, "
        f"{env.get('memory_gib', '?')} GiB, {env.get('os', '?')}.",
        "",
    ]
    Path(args.md_out).write_text("\n".join(lines))


# ──────────────────────────────── main ──────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("rq1", help="summarize the cryptographic cost")
    p1.add_argument("--raw", required=True)
    p1.add_argument("--traffic", required=True)
    p1.add_argument("--environment", required=True)
    p1.add_argument("--json-out", required=True)
    p1.add_argument("--md-out", required=True)
    p1.add_argument("--csv-out", required=True)
    p1.set_defaults(func=rq1)

    p2 = sub.add_parser("rq2", help="summarize the round-trip-time sweep")
    p2.add_argument("--index", required=True)
    p2.add_argument("--environment", required=True)
    p2.add_argument("--baseline", help="rq1_summary.json, for the relay's own cost")
    p2.add_argument("--json-out", required=True)
    p2.add_argument("--md-out", required=True)
    p2.add_argument("--csv-out", required=True)
    p2.set_defaults(func=rq2)

    p3 = sub.add_parser("rq3", help="summarize the end-to-end trade")
    p3.add_argument("--out-dir", required=True)
    p3.add_argument("--runs", type=int, default=1)
    p3.add_argument("--environment", required=True)
    p3.add_argument("--json-out", required=True)
    p3.add_argument("--md-out", required=True)
    p3.set_defaults(func=rq3)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
