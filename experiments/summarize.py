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


def share_export_ms(record):
    """Native final-share export, with the old open_ms key as a raw-data fallback."""
    return record.get("share_export_ms", record.get("open_ms", 0.0))


# ──────────────────────────────── RQ1 ───────────────────────────────────


def rq1(args):
    raw = read_json(args.raw) or {}
    traffic = read_json(args.traffic) or {}
    env = read_json(args.environment) or {}

    single_prove = raw.get("baseline_single_prover", {}).get("prove_ms", [])
    single_verify = raw.get("baseline_single_prover", {}).get("verify_ms", [])

    mock = raw.get("cozk2p_mock_inprocess", [])
    mock_phase = lambda key: stats([r.get(key, 0.0) for r in mock])
    mock_share_export = stats([share_export_ms(r) for r in mock])

    quic = [run for run in raw.get("cozk2p_quic_2process", []) if run.get("per_party")]
    parties = [p for run in quic for p in run["per_party"]]

    # Keep the session, rather than each of its two correlated traders, as the
    # unit of analysis. A phase completes when the slower trader completes it.
    quic_phase = lambda key: stats(
        [max(p.get(key, 0.0) for p in run["per_party"]) for run in quic]
    )
    quic_share_export = stats(
        [max(share_export_ms(p) for p in run["per_party"]) for run in quic]
    )

    # The proof core excludes the surrounding MPC comparison/session steps.
    def proof_core(rec):
        return (
            rec.get("build_ms", 0.0)
            + rec.get("prove_ms", 0.0)
            + share_export_ms(rec)
            + rec.get("verify_ms", 0.0)
        )

    mock_proof_core = stats([proof_core(r) for r in mock])
    mock_total = stats([r.get("total_ms", 0.0) for r in mock])
    quic_proof_core = stats(
        [max(proof_core(p) for p in run["per_party"]) for run in quic]
    )
    quic_total = stats([run.get("total_ms", 0.0) for run in quic])
    single_total = stats(
        [p + v for p, v in zip(single_prove, single_verify)]
    )

    summary = {
        "protocol_version": raw.get("protocol_version", "legacy-opened-proof"),
        "environment": env,
        "circuit": {
            "turboplonk_gates": raw.get("circuit_gates"),
            "public_signals": raw.get("public_signals"),
            "proof_bytes_compressed": raw.get("proof_size_bytes", {}).get("compressed"),
            "proof_bytes_uncompressed": raw.get("proof_size_bytes", {}).get(
                "uncompressed"
            ),
            "comparison_share_bytes_compressed": raw.get(
                "comparison_share_size_bytes_compressed"
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
            "share_export_ms": mock_share_export,
            "verify_ms": mock_phase("verify_ms"),
            "session_overhead_ms": mock_phase("session_overhead_ms"),
            "proof_core_ms": mock_proof_core,
            "total_ms": mock_total,
        },
        "two_party_quic": {
            "build_ms": quic_phase("build_ms"),
            "prove_ms": quic_phase("prove_ms"),
            "share_export_ms": quic_share_export,
            "verify_ms": quic_phase("verify_ms"),
            "proof_core_ms": quic_proof_core,
            "total_ms": quic_total,
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

    # Stacked-bar input plus the two totals used by the paper table.
    rows = [
        ("single prover", 0.0, summary["single_prover"]["prove_ms"]["median"], 0.0,
         summary["single_prover"]["verify_ms"]["median"],
         summary["single_prover"]["total_ms"]["median"],
         summary["single_prover"]["total_ms"]["median"]),
        ("in-process two-party",
         summary["two_party_in_process"]["build_ms"]["median"],
         summary["two_party_in_process"]["prove_ms"]["median"],
         summary["two_party_in_process"]["share_export_ms"]["median"],
         summary["two_party_in_process"]["verify_ms"]["median"],
         summary["two_party_in_process"]["proof_core_ms"]["median"],
         summary["two_party_in_process"]["total_ms"]["median"]),
        ("two-process QUIC",
         summary["two_party_quic"]["build_ms"]["median"],
         summary["two_party_quic"]["prove_ms"]["median"],
         summary["two_party_quic"]["share_export_ms"]["median"],
         summary["two_party_quic"]["verify_ms"]["median"],
         summary["two_party_quic"]["proof_core_ms"]["median"],
         summary["two_party_quic"]["total_ms"]["median"]),
    ]
    with open(args.csv_out, "w") as f:
        f.write(
            "configuration,build_ms,prove_ms,share_export_ms,verify_ms,"
            "proof_core_ms,session_total_ms\n"
        )
        for name, b, p, o, v, core, total in rows:
            f.write(f"{name},{b:.1f},{p:.1f},{o:.1f},{v:.1f},{core:.1f},{total:.1f}\n")

    q = summary["two_party_quic"]
    m = summary["two_party_in_process"]
    s = summary["single_prover"]
    lines = [
        "# RQ1 — the cost of the cryptography",
        "",
        f"Runs: {q['total_ms']['n']} sessions over QUIC "
        f"(two traders each), {m['total_ms']['n']} in-process sessions, "
        f"{s['prove_ms']['n']} single-prover runs.",
        "One observation is recorded per session; two-process phase values use the slower trader.",
        f"Protocol: {summary['protocol_version']}.",
        "",
        "## Latency per phase and session (ms)",
        "",
        "| configuration | build | prove | share export | local verify | proof core | session total | p95 session |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        f"| single prover | — | {ms(s['prove_ms']['median'])} | — | "
        f"{s['verify_ms']['median']:.1f} | {ms(s['total_ms']['median'])} | "
        f"{ms(s['total_ms']['median'])} | "
        f"{ms(s['total_ms']['p95'])} |",
        f"| two parties, one process | {ms(m['build_ms']['median'])} | "
        f"{ms(m['prove_ms']['median'])} | {ms(m['share_export_ms']['median'])} | "
        f"{m['verify_ms']['median']:.1f} | {ms(m['proof_core_ms']['median'])} | "
        f"{ms(m['total_ms']['median'])} | "
        f"{ms(m['total_ms']['p95'])} |",
        f"| two processes, QUIC | {ms(q['build_ms']['median'])} | "
        f"{ms(q['prove_ms']['median'])} | {ms(q['share_export_ms']['median'])} | "
        f"{q['verify_ms']['median']:.1f} | {ms(q['proof_core_ms']['median'])} | "
        f"{ms(q['total_ms']['median'])} | "
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
        f"| comparison share size | {c['comparison_share_bytes_compressed']} B compressed |",
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
        runs = [
            run
            for run in bench.get("cozk2p_quic_2process", [])
            if run.get("per_party")
        ]
        phase = lambda key: stats(
            [
                max(p.get(key, 0.0) for p in run["per_party"])
                for run in runs
            ]
        )
        export = stats(
            [max(share_export_ms(p) for p in run["per_party"]) for run in runs]
        )
        proof_core = stats(
            [
                max(
                    p.get("build_ms", 0.0)
                    + p.get("prove_ms", 0.0)
                    + share_export_ms(p)
                    + p.get("verify_ms", 0.0)
                    for p in run["per_party"]
                )
                for run in runs
            ]
        )
        total = stats([run.get("total_ms", 0.0) for run in runs])
        points.append(
            {
                "rtt_ms": point["rtt_ms"],
                "one_way_delay_ms": point["one_way_delay_ms"],
                "status": point["status"],
                "protocol_version": bench.get("protocol_version", "legacy-opened-proof"),
                "sessions": len(runs),
                "build_ms": phase("build_ms"),
                "prove_ms": phase("prove_ms"),
                "share_export_ms": export,
                "verify_ms": phase("verify_ms"),
                "proof_core_ms": proof_core,
                "total_ms": total,
                # The relay counts the whole point; report one session.
                "traffic_bytes_per_session": (
                    traffic.get("a_to_b_bytes", 0) + traffic.get("b_to_a_bytes", 0)
                )
                / max(len(runs), 1),
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
        f.write(
            "rtt_ms,build_ms,prove_ms,share_export_ms,verify_ms,proof_core_ms,"
            "session_total_ms,p95_session_total_ms\n"
        )
        for p in points:
            f.write(
                f"{p['rtt_ms']},{p['build_ms']['median']:.1f},"
                f"{p['prove_ms']['median']:.1f},{p['share_export_ms']['median']:.1f},"
                f"{p['verify_ms']['median']:.1f},{p['proof_core_ms']['median']:.1f},"
                f"{p['total_ms']['median']:.1f},"
                f"{p['total_ms']['p95']:.1f}\n"
            )

    lines = [
        "# RQ2 — the effect of the round-trip time",
        "",
        f"Rate cap {summary['rate_mbit']} Mbit/s, {summary['runs_per_point']} sessions "
        "per point. One observation is recorded per session; phase values use the slower trader.",
        "",
        "| RTT (ms) | build | prove | share export | local verify | proof core | session total | p95 session |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for p in points:
        if p["status"] != "ok" or p["total_ms"]["n"] == 0:
            lines.append(f"| {p['rtt_ms']} | did not finish | | | | | | |")
            continue
        lines.append(
            f"| {p['rtt_ms']} | {ms(p['build_ms']['median'])} | "
            f"{ms(p['prove_ms']['median'])} | {ms(p['share_export_ms']['median'])} | "
            f"{p['verify_ms']['median']:.1f} | {ms(p['proof_core_ms']['median'])} | "
            f"{ms(p['total_ms']['median'])} | "
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


def effective_payload(payloads, runs):
    """Bytes one trade must put on chain: every writing counted once per
    effect. `payloads` maps a writing name to the sizes the node logged,
    and `runs` is the number of trades those sizes come from."""
    total = 0.0
    for name, values in payloads.items():
        if not values:
            continue
        median = percentile(values, 50)
        # Comparison shares and settlement legs are deliberately two
        # owner submissions, so their observed per-trade count must not be
        # collapsed to one as the retired one-shot protocol did.
        count = len(values) / max(runs, 1)
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

    # Semantic phase boundaries are recorded by the app, not inferred from
    # the subprocess lifetime. The critical-path trader is selected per run,
    # so rendezvous + comparison + final settlement is one non-overlapping
    # decomposition of that run's settlement driver.
    rendezvous_ms = field(
        "semantic_settlement_phases.critical_path.rendezvous_ms"
    )["median"]
    comparison_ms = field(
        "semantic_settlement_phases.critical_path.comparison_ms"
    )["median"]
    final_settlement_ms = field(
        "semantic_settlement_phases.critical_path.final_settlement_ms"
    )["median"]
    order_prove_ms = (
        field("order.alice.prove_ms")["median"] + field("order.bob.prove_ms")["median"]
    )

    def proof_core(run, trader):
        rec = run.get("session", {}).get(trader, {})
        return (
            rec.get("build_ms", 0.0)
            + rec.get("prove_ms", 0.0)
            + share_export_ms(rec)
            + rec.get("verify_ms", 0.0)
        )

    comparison_proof_core = stats(
        [max(proof_core(run, "alice"), proof_core(run, "bob")) for run in runs]
    )

    summary = {
        "protocol_version": runs[0].get("session", {}).get("alice", {}).get(
            "protocol_version", "legacy-opened-proof"
        ),
        "environment": env,
        "runs": len(runs),
        "scenario": runs[0].get("scenario"),
        "order": {
            "alice_prove_ms": field("order.alice.prove_ms"),
            "alice_land_ms": field("order.alice.land_ms"),
            "alice_phase_ms": field("order.alice.phase_ms"),
            "bob_prove_ms": field("order.bob.prove_ms"),
            "bob_land_ms": field("order.bob.land_ms"),
            "bob_phase_ms": field("order.bob.phase_ms"),
            "match_ms": field("order.match_ms"),
        },
        "session": {
            trader: {
                key: field(f"session.{trader}.{key}")
                for key in (
                    "build_ms",
                    "prove_ms",
                    "share_export_ms",
                    "verify_ms",
                    "compare_onchain_wait_ms",
                    "leg_exchange_ms",
                    "total_ms",
                    "peak_rss_bytes",
                )
            }
            for trader in ("alice", "bob")
        },
        "semantic_settlement_phases": {
            scope: {
                key: field(f"semantic_settlement_phases.{scope}.{key}")
                for key in (
                    "rendezvous_ms",
                    "comparison_ms",
                    "settlement_proof_ms",
                    "final_settlement_ms",
                    "total_ms",
                )
            }
            for scope in ("alice", "bob", "critical_path")
        },
        "comparison_proof_core_ms": comparison_proof_core,
        "steps": {"alice": alice_steps, "bob": bob_steps},
        "settle_ms": field("settle_ms"),
        "full_trade_ms": field("full_trade_ms"),
        "categories_ms": {
            "single_prover_order_proofs": order_prove_ms,
            "rendezvous": rendezvous_ms,
            "comparison_phase": comparison_ms,
            "final_settlement_phase": final_settlement_ms,
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
        f"| **order phase: proof start → confirmed** | "
        f"**{ms(summary['order']['alice_phase_ms']['median'])}** | "
        f"**{ms(summary['order']['bob_phase_ms']['median'])}** |",
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
        "## Paper phase boundaries (ms, median)",
        "",
        "The settlement rows use the critical-path trader selected separately in each run. "
        "Rendezvous, comparison, and final settlement are non-overlapping.",
        "",
        "| phase | median (ms) | p95 (ms) |",
        "|---|---:|---:|",
        f"| order, maker | {ms(summary['order']['alice_phase_ms']['median'])} | "
        f"{ms(summary['order']['alice_phase_ms']['p95'])} |",
        f"| order, taker | {ms(summary['order']['bob_phase_ms']['median'])} | "
        f"{ms(summary['order']['bob_phase_ms']['p95'])} |",
        f"| rendezvous (reported separately) | "
        f"{ms(summary['semantic_settlement_phases']['critical_path']['rendezvous_ms']['median'])} | "
        f"{ms(summary['semantic_settlement_phases']['critical_path']['rendezvous_ms']['p95'])} |",
        f"| comparison: MPC start → both proof shares verified | "
        f"{ms(summary['semantic_settlement_phases']['critical_path']['comparison_ms']['median'])} | "
        f"{ms(summary['semantic_settlement_phases']['critical_path']['comparison_ms']['p95'])} |",
        f"| final settlement: comparison confirmed → settlement confirmed | "
        f"{ms(summary['semantic_settlement_phases']['critical_path']['final_settlement_ms']['median'])} | "
        f"{ms(summary['semantic_settlement_phases']['critical_path']['final_settlement_ms']['p95'])} |",
        f"| **complete trade** | **{ms(summary['full_trade_ms']['median'])}** | "
        f"**{ms(summary['full_trade_ms']['p95'])}** |",
        "",
        "## Cryptographic work (ms)",
        "",
        "| operation | trader A | trader B |",
        "|---|---:|---:|",
        f"| order Groth16 generation | "
        f"{ms(summary['order']['alice_prove_ms']['median'])} | "
        f"{ms(summary['order']['bob_prove_ms']['median'])} |",
        f"| settlement Groth16 generation | "
        f"{ms(summary['semantic_settlement_phases']['alice']['settlement_proof_ms']['median'])} | "
        f"{ms(summary['semantic_settlement_phases']['bob']['settlement_proof_ms']['median'])} |",
        f"| collaborative comparison proof core (slower trader) | "
        f"{ms(summary['comparison_proof_core_ms']['median'])} | — |",
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
        f"{summary['onchain_payload_effective_bytes']} B. This includes one "
        "identity-bound comparison share and one owner-bound settlement leg "
        "from each trader; all four submissions are required and accepted. "
        "Each settlement leg is verified when submitted and re-verified before "
        "the pair executes atomically.",
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
