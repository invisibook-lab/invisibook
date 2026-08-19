#!/usr/bin/env python3
"""Compare archived XOR-full-proof results with native proof-share results.

The input summaries are produced by ``experiments/summarize.py``.  Missing
files or fields are represented as ``null``/an em dash instead of preventing
the remaining measurements from being compared.
"""

import argparse
import json
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
RESULTS_DIR = SCRIPT_DIR / "results"

OLD_PROTOCOL = {
    "id": "xor_full_proof",
    "label": "XOR full-proof",
}
NEW_PROTOCOL = {
    "id": "native_final_kzg_spdz_share",
    "label": "native final-KZG SPDZ share",
}


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def load_object(path, warnings, source_name):
    try:
        value = json.loads(path.read_text())
    except OSError as exc:
        warnings.append(f"{source_name}: cannot read {path}: {exc}")
        return {}
    except ValueError as exc:
        warnings.append(f"{source_name}: invalid JSON in {path}: {exc}")
        return {}
    if not isinstance(value, dict):
        warnings.append(f"{source_name}: top-level JSON value is not an object")
        return {}
    return value


def at(root, dotted_path):
    node = root
    for key in dotted_path.split("."):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def number_at(root, dotted_path):
    value = at(root, dotted_path)
    return value if is_number(value) else None


def median_at(root, dotted_path):
    return number_at(root, f"{dotted_path}.median")


def comparison(old, new):
    change = None
    if is_number(old) and is_number(new) and old != 0:
        change = round((new - old) * 100.0 / old, 6)
    return {"old": old, "new": new, "change_pct": change}


def sum_if_complete(*values):
    return sum(values) if all(is_number(value) for value in values) else None


def status_at(point):
    status = point.get("status") if isinstance(point, dict) else None
    return status if isinstance(status, str) else None


def points_by_rtt(summary):
    result = {}
    points = summary.get("points", []) if isinstance(summary, dict) else []
    if not isinstance(points, list):
        return result
    for point in points:
        if not isinstance(point, dict) or not is_number(point.get("rtt_ms")):
            continue
        result[point["rtt_ms"]] = point
    return result


def stat_names(summary, dotted_path, preferred):
    node = at(summary, dotted_path)
    discovered = []
    if isinstance(node, dict):
        discovered = [
            name
            for name, value in node.items()
            if isinstance(value, dict) and is_number(value.get("median"))
        ]
    return list(preferred) + sorted(set(discovered) - set(preferred))


def comparison_payload(summary):
    payloads = summary.get("onchain_payload_bytes", {})
    if not isinstance(payloads, dict):
        return None, {}
    name = None
    for candidate in (
        "SubmitCompareCoZk2pShare",
        "SubmitComparisonProofShare",
        "SubmitCompareShare",
    ):
        if isinstance(payloads.get(candidate), dict):
            name = candidate
            break
    if name is None:
        for candidate, record in sorted(payloads.items()):
            lowered = candidate.lower()
            if isinstance(record, dict) and "compare" in lowered and (
                "share" in lowered or "cozk2p" in lowered
            ):
                name = candidate
                break
    return name, payloads.get(name, {}) if name else {}


def payload_metrics(summary):
    name, record = comparison_payload(summary)
    median = number_at(record, "per_writing.median")
    count = number_at(record, "count")
    runs = number_at(summary, "runs")
    submissions_per_trade = None
    per_trade = None
    if is_number(count) and is_number(runs) and runs > 0:
        submissions_per_trade = count / runs
        if is_number(median):
            per_trade = median * submissions_per_trade
        else:
            total = number_at(record, "total")
            if is_number(total):
                per_trade = total / runs
    return {
        "writing": name,
        "per_submission_median_bytes": median,
        "submissions_per_trade": submissions_per_trade,
        "per_trade_effective_bytes": per_trade,
    }


def build_rq1(old, new):
    modes = {
        "single_prover": "single_prover",
        "two_party_in_process": "two_party_in_process",
        "two_party_quic": "two_party_quic",
    }
    totals = {
        name: comparison(
            median_at(old, f"{path}.total_ms"),
            median_at(new, f"{path}.total_ms"),
        )
        for name, path in modes.items()
    }

    old_size = number_at(old, "circuit.proof_bytes_compressed")
    new_size = number_at(new, "circuit.comparison_share_bytes_compressed")

    old_traffic = old.get("traffic_per_trader", {})
    new_traffic = new.get("traffic_per_trader", {})
    directions = ("a_to_b_bytes", "b_to_a_bytes")
    traffic = {
        direction: comparison(
            number_at(old_traffic, direction), number_at(new_traffic, direction)
        )
        for direction in directions
    }
    traffic["total_bidirectional_bytes"] = comparison(
        sum_if_complete(*(number_at(old_traffic, key) for key in directions)),
        sum_if_complete(*(number_at(new_traffic, key) for key in directions)),
    )

    return {
        "median_total_ms": totals,
        "comparison_material_size_bytes": {
            "old_metric": "compressed standard proof; each XOR share has equal length",
            "new_metric": "compressed native final-KZG SPDZ proof share",
            **comparison(old_size, new_size),
        },
        "traffic_per_trader": traffic,
        "non_comparable_phase_ms": {
            "note": "open_ms and share_export_ms have different semantics; no direct change is calculated.",
            "old_open_ms": {
                "two_party_in_process": median_at(
                    old, "two_party_in_process.open_ms"
                ),
                "two_party_quic": median_at(old, "two_party_quic.open_ms"),
            },
            "new_share_export_ms": {
                "two_party_in_process": median_at(
                    new, "two_party_in_process.share_export_ms"
                ),
                "two_party_quic": median_at(
                    new, "two_party_quic.share_export_ms"
                ),
            },
        },
    }


def build_rq2(old, new):
    old_points = points_by_rtt(old)
    new_points = points_by_rtt(new)
    rows = []
    for rtt in sorted(set(old_points) | set(new_points)):
        old_point = old_points.get(rtt, {})
        new_point = new_points.get(rtt, {})
        rows.append(
            {
                "rtt_ms": rtt,
                "old_status": status_at(old_point),
                "new_status": status_at(new_point),
                "median_total_ms": comparison(
                    median_at(old_point, "total_ms"),
                    median_at(new_point, "total_ms"),
                ),
                "non_comparable_phase_ms": {
                    "old_open_ms": median_at(old_point, "open_ms"),
                    "new_share_export_ms": median_at(
                        new_point, "share_export_ms"
                    ),
                },
            }
        )
    return {
        "points": rows,
        "phase_note": "open_ms and share_export_ms are reported separately and have no direct change percentage.",
    }


def build_rq3(old, new):
    semantic_path = "semantic_settlement_phases.critical_path"
    preferred_phases = (
        "rendezvous_ms",
        "comparison_ms",
        "settlement_proof_ms",
        "final_settlement_ms",
        "total_ms",
    )
    phase_names = list(
        dict.fromkeys(
            stat_names(old, semantic_path, preferred_phases)
            + stat_names(new, semantic_path, preferred_phases)
        )
    )
    semantic = {
        name: comparison(
            median_at(old, f"{semantic_path}.{name}"),
            median_at(new, f"{semantic_path}.{name}"),
        )
        for name in phase_names
    }

    chain_path = "chain_verification_ms"
    chain_names = sorted(
        set(stat_names(old, chain_path, ()))
        | set(stat_names(new, chain_path, ()))
    )
    chain = {
        name: comparison(
            median_at(old, f"{chain_path}.{name}"),
            median_at(new, f"{chain_path}.{name}"),
        )
        for name in chain_names
    }

    old_payload = payload_metrics(old)
    new_payload = payload_metrics(new)
    payload = {
        "old_writing": old_payload["writing"],
        "new_writing": new_payload["writing"],
        "per_submission_median_bytes": comparison(
            old_payload["per_submission_median_bytes"],
            new_payload["per_submission_median_bytes"],
        ),
        "submissions_per_trade": comparison(
            old_payload["submissions_per_trade"],
            new_payload["submissions_per_trade"],
        ),
        "per_trade_effective_bytes": comparison(
            old_payload["per_trade_effective_bytes"],
            new_payload["per_trade_effective_bytes"],
        ),
    }

    return {
        "median_full_trade_ms": comparison(
            median_at(old, "full_trade_ms"), median_at(new, "full_trade_ms")
        ),
        "semantic_critical_path_ms": semantic,
        "chain_verification_ms": chain,
        "comparison_share_payload": payload,
        "total_effective_onchain_payload_bytes": comparison(
            number_at(old, "onchain_payload_effective_bytes"),
            number_at(new, "onchain_payload_effective_bytes"),
        ),
        "non_comparable_session_phase_ms": {
            "note": "open_ms and share_export_ms have different semantics; no direct change is calculated.",
            "old_open_ms": {
                trader: median_at(old, f"session.{trader}.open_ms")
                for trader in ("alice", "bob")
            },
            "new_share_export_ms": {
                trader: median_at(new, f"session.{trader}.share_export_ms")
                for trader in ("alice", "bob")
            },
        },
    }


def display_path(path):
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path.resolve())


def format_value(value, kind="number"):
    if not is_number(value):
        return "—"
    if kind == "bytes":
        return f"{value:,.0f}"
    if kind == "count":
        return f"{value:.2f}".rstrip("0").rstrip(".")
    return f"{value:,.2f}"


def format_change(item):
    value = item.get("change_pct") if isinstance(item, dict) else None
    return "—" if not is_number(value) else f"{value:+.2f}%"


def comparison_row(label, item, kind="number"):
    return (
        f"| {label} | {format_value(item.get('old'), kind)} | "
        f"{format_value(item.get('new'), kind)} | {format_change(item)} |"
    )


def render_markdown(result):
    rq1, rq2, rq3 = result["rq1"], result["rq2"], result["rq3"]
    lines = [
        "# Protocol result comparison",
        "",
        f"Old: **{OLD_PROTOCOL['label']}**. New: **{NEW_PROTOCOL['label']}**.",
        "",
        "Change is `(new - old) / old`; a negative percentage is a reduction. "
        "Missing measurements are shown as —.",
        "",
        "## RQ1 — cryptographic session",
        "",
        "| median total | old (ms) | new (ms) | change |",
        "|---|---:|---:|---:|",
    ]
    rq1_labels = {
        "single_prover": "single prover",
        "two_party_in_process": "two-party in-process",
        "two_party_quic": "two-party QUIC",
    }
    for key, label in rq1_labels.items():
        lines.append(comparison_row(label, rq1["median_total_ms"][key]))

    lines += [
        "",
        "| comparison material per party | old (B) | new (B) | change |",
        "|---|---:|---:|---:|",
        comparison_row(
            "compressed proof / native share",
            rq1["comparison_material_size_bytes"],
            "bytes",
        ),
        "",
        "The old value is the compressed standard-proof length (an XOR share "
        "has the same length); the new value is the compressed native final-KZG "
        "SPDZ share.",
        "",
        "| traffic per trader | old (B) | new (B) | change |",
        "|---|---:|---:|---:|",
    ]
    traffic_labels = {
        "a_to_b_bytes": "A → B",
        "b_to_a_bytes": "B → A",
        "total_bidirectional_bytes": "both directions",
    }
    for key, label in traffic_labels.items():
        lines.append(comparison_row(label, rq1["traffic_per_trader"][key], "bytes"))

    phases = rq1["non_comparable_phase_ms"]
    lines += [
        "",
        "| protocol-specific phase (not directly comparable) | in-process (ms) | QUIC (ms) |",
        "|---|---:|---:|",
        f"| old `open_ms` | {format_value(phases['old_open_ms']['two_party_in_process'])} | "
        f"{format_value(phases['old_open_ms']['two_party_quic'])} |",
        f"| new `share_export_ms` | "
        f"{format_value(phases['new_share_export_ms']['two_party_in_process'])} | "
        f"{format_value(phases['new_share_export_ms']['two_party_quic'])} |",
        "",
        "`open_ms` reconstructed/opened the old proof, whereas `share_export_ms` "
        "exports an unopened native share. No percentage is calculated between them.",
        "",
        "## RQ2 — network RTT",
        "",
        "| RTT (ms) | old median total (ms) | new median total (ms) | change |",
        "|---:|---:|---:|---:|",
    ]
    for point in rq2["points"]:
        item = point["median_total_ms"]
        lines.append(
            f"| {format_value(point['rtt_ms'], 'count')} | "
            f"{format_value(item['old'])} | {format_value(item['new'])} | "
            f"{format_change(item)} |"
        )

    lines += [
        "",
        "| RTT (ms) | old `open_ms` | new `share_export_ms` |",
        "|---:|---:|---:|",
    ]
    for point in rq2["points"]:
        phases = point["non_comparable_phase_ms"]
        lines.append(
            f"| {format_value(point['rtt_ms'], 'count')} | "
            f"{format_value(phases['old_open_ms'])} | "
            f"{format_value(phases['new_share_export_ms'])} |"
        )
    lines += [
        "",
        "The two phase columns above are protocol-specific and are not used to "
        "compute a change percentage.",
        "",
        "## RQ3 — end-to-end trade",
        "",
        "| metric | old | new | change |",
        "|---|---:|---:|---:|",
        comparison_row("full trade median (ms)", rq3["median_full_trade_ms"]),
        "",
        "### Semantic critical-path phases",
        "",
        "| phase | old median (ms) | new median (ms) | change |",
        "|---|---:|---:|---:|",
    ]
    for name, item in rq3["semantic_critical_path_ms"].items():
        lines.append(comparison_row(name.removesuffix("_ms").replace("_", " "), item))

    lines += [
        "",
        "### Chain verification",
        "",
        "| verifier | old median (ms) | new median (ms) | change |",
        "|---|---:|---:|---:|",
    ]
    if rq3["chain_verification_ms"]:
        for name, item in rq3["chain_verification_ms"].items():
            lines.append(comparison_row(f"`{name}`", item))
    else:
        lines.append("| — | — | — | — |")

    payload = rq3["comparison_share_payload"]
    lines += [
        "",
        "### On-chain payload",
        "",
        "| metric | old | new | change |",
        "|---|---:|---:|---:|",
        comparison_row(
            "comparison share per submission (B)",
            payload["per_submission_median_bytes"],
            "bytes",
        ),
        comparison_row(
            "comparison-share submissions per trade",
            payload["submissions_per_trade"],
            "count",
        ),
        comparison_row(
            "comparison shares per trade (effective B)",
            payload["per_trade_effective_bytes"],
            "bytes",
        ),
        comparison_row(
            "all effective on-chain payload per trade (B)",
            rq3["total_effective_onchain_payload_bytes"],
            "bytes",
        ),
        "",
        f"Comparison writing: old `{payload['old_writing'] or 'missing'}`, "
        f"new `{payload['new_writing'] or 'missing'}`.",
    ]

    session_phases = rq3["non_comparable_session_phase_ms"]
    lines += [
        "",
        "| RQ3 protocol-specific session phase (not directly comparable) | Alice (ms) | Bob (ms) |",
        "|---|---:|---:|",
        f"| old `open_ms` | {format_value(session_phases['old_open_ms']['alice'])} | "
        f"{format_value(session_phases['old_open_ms']['bob'])} |",
        f"| new `share_export_ms` | "
        f"{format_value(session_phases['new_share_export_ms']['alice'])} | "
        f"{format_value(session_phases['new_share_export_ms']['bob'])} |",
    ]

    if result["warnings"]:
        lines += ["", "## Input warnings", ""]
        lines.extend(f"- {warning}" for warning in result["warnings"])
    lines.append("")
    return "\n".join(lines)


def write_if_changed(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text() == text:
            return
    except OSError:
        pass
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text)
    temporary.replace(path)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--old-dir",
        type=Path,
        default=RESULTS_DIR / "archive_xor_fullproof",
        help="directory containing the archived rq1/rq2/rq3 summaries",
    )
    parser.add_argument(
        "--new-dir",
        type=Path,
        default=RESULTS_DIR,
        help="directory containing the current rq1/rq2/rq3 summaries",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=RESULTS_DIR / "protocol_comparison.json",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=RESULTS_DIR / "protocol_comparison.md",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    warnings = []
    old, new = {}, {}
    sources = {"old": {}, "new": {}}
    for rq in ("rq1", "rq2", "rq3"):
        old_path = args.old_dir / f"{rq}_summary.json"
        new_path = args.new_dir / f"{rq}_summary.json"
        old[rq] = load_object(old_path, warnings, f"old {rq}")
        new[rq] = load_object(new_path, warnings, f"new {rq}")
        sources["old"][rq] = display_path(old_path)
        sources["new"][rq] = display_path(new_path)

    result = {
        "schema_version": 1,
        "protocols": {"old": OLD_PROTOCOL, "new": NEW_PROTOCOL},
        "change_definition": "(new - old) / old * 100; negative means reduction",
        "non_comparable_phase_note": "old open_ms and new share_export_ms are listed separately without a direct change percentage",
        "sources": sources,
        "rq1": build_rq1(old["rq1"], new["rq1"]),
        "rq2": build_rq2(old["rq2"], new["rq2"]),
        "rq3": build_rq3(old["rq3"], new["rq3"]),
        "warnings": warnings,
    }

    json_text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    write_if_changed(args.output_json, json_text)
    write_if_changed(args.output_md, render_markdown(result))
    print(display_path(args.output_json))
    print(display_path(args.output_md))


if __name__ == "__main__":
    main()
