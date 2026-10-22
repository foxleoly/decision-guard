#!/usr/bin/env python3
"""Run every benchmark case through the real binary and report what happened.

    bench/run.py [--cases DIR] [--out PATH] [--timeout S] [--keep]

The runner never invents a label. It measures three things the guard can answer without one:

  1. which stage decided (rule / read-only / cache / model / unjudged) — per case and per bypass class;
  2. latency, per stage and per percentile;
  3. for labelled cases only: the confusion matrix at `ask_p`, the PR curve over 0.3–0.7, and calibration.

Each case runs against a throwaway HOME, so the real audit log is never touched.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "bench" / "cases"
DG = Path.home() / ".decision-guard" / "bin" / "decision-guard"
REAL_CONFIG = Path.home() / ".decision-guard" / "config.json"


def load_cases(directory: Path) -> list[dict]:
    import tomllib

    cases: list[dict] = []
    for path in sorted(directory.glob("*.toml")):
        cases.extend(tomllib.loads(path.read_text()).get("case", []))
    return cases


def run_one(case: dict, home: Path, timeout: float) -> dict:
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": case["command"]},
        "cwd": case.get("cwd") or tempfile.gettempdir(),
    }
    began = time.perf_counter()
    try:
        proc = subprocess.run(
            [str(DG), "hook", "claude"],
            input=json.dumps(payload).encode(),
            capture_output=True,
            timeout=timeout,
            env={**os.environ, "HOME": str(home)},
        )
        out = proc.stdout.decode(errors="replace")
        err = proc.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        out, err = "", "timeout"
    elapsed = (time.perf_counter() - began) * 1000.0
    return {"wall_ms": elapsed, "stdout": out, "stderr": err}


def read_rows(home: Path) -> dict[str, dict]:
    """The throwaway log, keyed by exact command."""
    import sqlite3

    db = home / ".decision-guard" / "decisions.db"
    if not db.exists():
        return {}
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = {}
    for row in con.execute(
        "SELECT command, source, rule, choice, probabilities, action, latency_ms, error FROM decisions ORDER BY id"
    ):
        rows.setdefault(row["command"], dict(row))
    con.close()
    return rows


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[k]


def confusion(pairs: list[tuple[float, float]], ask_p: float) -> dict:
    tp = fp = fn = tn = 0
    for label, p in pairs:
        truth = label >= 0.5
        said = p >= ask_p
        if truth and said:
            tp += 1
        elif truth and not said:
            fn += 1
        elif said and not truth:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall}


def brier(pairs: list[tuple[float, float]]) -> float:
    return statistics.fmean((p - label) ** 2 for label, p in pairs) if pairs else float("nan")


def fmt(value: float) -> str:
    return "—" if value != value else f"{value:.3f}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", default=str(CASES))
    parser.add_argument("--out", default=str(ROOT / "docs" / "benchmark-2026-11.md"))
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--keep", action="store_true", help="keep the throwaway HOME")
    args = parser.parse_args()

    cases = load_cases(Path(args.cases))
    if not cases:
        print("no cases", file=sys.stderr)
        return 1
    if not DG.exists():
        print(f"no binary at {DG}; run scripts/install.sh files first", file=sys.stderr)
        return 1

    home = Path(tempfile.mkdtemp(prefix="dg-bench-"))
    (home / ".decision-guard").mkdir(parents=True)
    if REAL_CONFIG.exists():
        shutil.copy2(REAL_CONFIG, home / ".decision-guard" / "config.json")
    print(f"running {len(cases)} cases against {home}", file=sys.stderr)

    results: list[dict] = []
    for n, case in enumerate(cases, 1):
        run = run_one(case, home, args.timeout)
        results.append({**case, **run})
        if n % 25 == 0:
            print(f"  {n}/{len(cases)}", file=sys.stderr)

    rows = read_rows(home)
    for case in results:
        row = rows.get(case["command"], {})
        case["stage"] = row.get("source", "no_row")
        case["rule"] = row.get("rule") or ""
        case["choice"] = row.get("choice") or ""
        case["action"] = row.get("action") or ""
        case["latency_ms"] = row.get("latency_ms") or case["wall_ms"]
        probabilities = row.get("probabilities")
        try:
            case["p_destructive"] = float(json.loads(probabilities)["destructive"]) if probabilities else None
        except (ValueError, KeyError, TypeError):
            case["p_destructive"] = None

    if not args.keep:
        with contextlib.suppress(OSError):
            shutil.rmtree(home)

    labelled = [c for c in results if str(c.get("label", "")) != ""]
    unlabelled = len(results) - len(labelled)
    pairs = [(float(c["label"]), c["p_destructive"]) for c in labelled if c.get("p_destructive") is not None]

    stages: dict[str, list[dict]] = {}
    for case in results:
        stages.setdefault(case["stage"], []).append(case)

    lines: list[str] = []
    lines.append("# Benchmark — 2026-11 (Phase 0 baseline)\n")
    lines.append(f"Generated by `bench/run.py` over **{len(results)} cases** "
                 f"({len(labelled)} labelled, {unlabelled} unlabelled).\n")
    lines.append("Labels are written by a person only (`bench/label.py interactive`); the model never grades "
                 "itself. Until the corpus is labelled, this report is a **baseline of what the guard does**, "
                 "not of how right it is.\n")

    lines.append("## Which stage decided\n")
    lines.append("| stage | n | share | P50 ms | P95 ms | max ms |")
    lines.append("|---|---|---|---|---|---|")
    for stage, group in sorted(stages.items(), key=lambda kv: -len(kv[1])):
        lat = [c["latency_ms"] for c in group if c["latency_ms"]]
        lines.append(f"| `{stage}` | {len(group)} | {100 * len(group) / len(results):.0f}% | "
                     f"{fmt(percentile(lat, 50))} | {fmt(percentile(lat, 95))} | {fmt(max(lat) if lat else float('nan'))} |")
    lines.append("")

    exact = [c["latency_ms"] for c in results if c["stage"] in ("rule", "cache")]
    lines.append(f"Decided without a model: **{len(exact)}/{len(results)}** "
                 f"({100 * len(exact) / len(results):.0f}%). The roadmap's Phase 2 target is ≥70% in <10 ms.\n")

    bypass = [c for c in results if c.get("bypass_class")]
    if bypass:
        lines.append("## Bypass classes\n")
        lines.append("| class | n | decided by rule | by read-only | reached the model |")
        lines.append("|---|---|---|---|---|")
        by_class: dict[str, list[dict]] = {}
        for case in bypass:
            by_class.setdefault(case["bypass_class"], []).append(case)
        for name, group in sorted(by_class.items()):
            rule = sum(1 for c in group if c["stage"] == "rule")
            readonly = sum(1 for c in group if c.get("rule") == "readonly")
            model = sum(1 for c in group if c["stage"] == "api")
            lines.append(f"| `{name}` | {len(group)} | {rule} | {readonly} | {model} |")
        lines.append("")
        lines.append("`rule` here includes the read-only proof; the column is split out because that is the "
                     "layer R4 is about — a case decided by read-only when it can write is the failure mode.\n")

    if pairs:
        lines.append("## Detection at the current threshold\n")
        lines.append("| ask_p | precision | recall | TP | FP | FN | TN |")
        lines.append("|---|---|---|---|---|---|---|")
        for ask in (0.3, 0.4, 0.5, 0.6, 0.7):
            m = confusion(pairs, ask)
            lines.append(f"| {ask} | {fmt(m['precision'])} | {fmt(m['recall'])} | {m['tp']} | {m['fp']} | "
                         f"{m['fn']} | {m['tn']} |")
        lines.append("")
        lines.append(f"Brier score: **{fmt(brier(pairs))}** over {len(pairs)} labelled cases with a model "
                     "probability (lower is better; 0.25 is a coin flip).\n")
    else:
        lines.append("## Detection at the current threshold\n")
        lines.append("Not reported: no labelled case has a model probability yet. Run "
                     "`bench/label.py interactive`, then this script again.\n")

    lines.append("## Reproducing\n")
    lines.append("```bash")
    lines.append("python3 bench/label.py interactive    # fill the labels (a person, not a model)")
    lines.append("python3 bench/run.py                  # rewrite this report")
    lines.append("```")
    lines.append("")

    Path(args.out).write_text("\n".join(lines))
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
