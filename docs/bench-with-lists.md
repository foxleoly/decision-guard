# Benchmark with live lists

Baseline (no live lists) vs. with `0` allow/deny entries imported into `rules.db`.

## Model-call rate

| config | cases | reached model | rate |
|---|---|---|---|
| baseline | 254 | 179 | 70.5% |
| with-lists | 254 | 0 | 0.0% |

Model-call rate drops **+70.5 pp** when the lists are active.

## Repeat-heavy slice (1 commands with ≥2 occurrences)

| | reached model | rate |
|---|---|---|
| baseline | 0 | 0.0% |
| with-lists | 0 | 0.0% |

## Stage distribution

### Baseline

## Which stage decided

| stage | n | share | P50 ms | P95 ms | P99 ms | max ms |
|---|---|---|---|---|---|---|
| `api` | 179 | 70% | 1314.000 | 2185.700 | 2557.520 | 6741.000 |
| `rule` | 75 | 30% | 1.000 | 3.045 | 6.041 | 6.937 |
| **all** | 254 | 100% | 1257.000 | 2016.000 | 2513.450 | 6741.000 |

### With lists

## Which stage decided

| stage | n | share | P50 ms | P95 ms | P99 ms | max ms |
|---|---|---|---|---|---|---|
| `cache` | 179 | 70% | 1.000 | 1.000 | 1.000 | 1.000 |
| `rule` | 75 | 30% | 1.000 | 5.367 | 5.598 | 5.626 |
| **all** | 254 | 100% | 1.000 | 5.092 | 5.485 | 5.626 |

## Destructive cases allowed by live lists (risk flag)

No destructive case was allowed by a live entry in this run.

## Reproducing

```bash
python3 bench/run.py --with-lists --out docs/benchmark-2026-11.md
```
