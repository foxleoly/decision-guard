# Jev2b vs PPLX-27B — Phase-0 Latency Comparison

Both runs over the same 254-case corpus (0 labelled; baseline of what the
guard does, not of how right it is). Stage distribution is identical across
both services: `api` 179 cases (70%), `rule` 75 cases (30%).

## Latency

| stage  | service    | P50 ms | P95 ms | max ms |
|--------|------------|--------|--------|--------|
| all    | jev2b      | 44     | 94     | 540    |
| all    | pplx-27b   | 1251   | 2245   | 7267   |
| api    | jev2b      | 46     | 111    | 540    |
| api    | pplx-27b   | 1412   | 2245   | 7267   |
| rule   | jev2b      | 1      | 1      | 6      |
| rule   | pplx-27b   | 1      | 1      | 6      |

Model-decision speedup: **27B ≈ 28× slower** on the hot path (P50 1412 ms vs
46 ms). The rule layer is identical and negligible in both; the spread is
entirely from the API stage.

## Conclusion

- **Hot path**: jev2b P50 ≈ 44 ms vs 1251 ms — roughly **28× faster**, and its
  worst case (540 ms) stays well inside the 12 s `budget_ms`.
- **Cascade fit**: jev2b is the fast 2B triage layer; pplx-27b is the high-
  precision re-check. A cascade (jev2b clears the obvious safe/risky, 27B
  re-scores the borderline) preserves coverage at ~1/28th of the model cost.
- **Accuracy caveat**: the corpus has 0 human labels, so these numbers compare
  *speed and stage routing only* — not correctness. To compare destructive
  recall / safe precision, run `bench/label.py interactive` (a person, never a
  model), then re-run both `bench/run.py` reports.
