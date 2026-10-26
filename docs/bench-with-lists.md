# Benchmark with live lists

Baseline (no live lists, independent HOME) vs. with `23` allow + `1` deny entries seeded into `rules.db`.

**Corpus note:** the benchmark corpus includes a repeat-heavy slice (93 cases, each command repeated) written into `bench/cases/repeats.toml`. These commands were verified to reach the model in the baseline run.

## Seeded patterns

Source: `bench/fixtures/live-lists.toml` (used when `config.json` has no allow/deny).

<details><summary>allow patterns</summary>

```
pip3 install*
pipx*
npm install*
yarn add*
cargo build*
cargo test*
git commit*
git add*
git stash*
git checkout -b*
sed -i.bak*
cp*
echo*
touch*
node server*
bash script*
python3 analyze*
python3 train*
python3 -m http.server*
ln -s*
brew install*
npm run build*
docker run --rm*
```

</details>

<details><summary>deny patterns</summary>

```
rm -rf /Users/foxleoly*
```

</details>

## Model-call rate

| config | cases | reached model | rate |
|---|---|---|---|
| baseline (independent HOME, no rules.db) | 347 | 272 | 78.4% |
| with-lists (independent HOME, seeded) | 347 | 198 | 57.1% |

Model-call rate drops **+21.3 pp** when the live lists are active.

## How the with-lists run avoided the model

Each case that skipped the model is attributed to the stage that decided it in the with-lists run. A `cache` hit means the verdict was already in the throwaway HOME's verdict cache (seeded by an earlier command in the same run); a `rule`/`allowlist` hit means the live list decided it before the cache was consulted.

| skip mechanism | cases |
|---|---|
| live allow-list (rule=allowlist) | 74 |
| verdict cache (stage=cache) | 0 |
| other deterministic rule (builtin/readonly/denylist) | 75 |
| still reached the model (api) | 198 |

## Stage distribution

### Baseline (independent HOME)

## Which stage decided

| stage | n | share | P50 ms | P95 ms | P99 ms | max ms |
|---|---|---|---|---|---|---|
| `api` | 272 | 78% | 1429.000 | 2168.150 | 2699.020 | 6634.000 |
| `rule` | 75 | 22% | 2.000 | 5.000 | 6.260 | 7.000 |
| **all** | 347 | 100% | 1407.000 | 2100.400 | 2650.740 | 6634.000 |

### With lists (independent HOME)

## Which stage decided

| stage | n | share | P50 ms | P95 ms | P99 ms | max ms |
|---|---|---|---|---|---|---|
| `api` | 198 | 57% | 1465.000 | 2347.800 | 2772.310 | 7565.000 |
| `rule` | 149 | 43% | 2.000 | 5.000 | 7.000 | 7.000 |
| **all** | 347 | 100% | 1375.000 | 2200.000 | 2717.340 | 7565.000 |

## Repeat-heavy slice (32 distinct commands, 95 cases)

| config | cases | reached model | rule-decided | model rate |
|---|---|---|---|---|
| baseline | 95 | 93 | 2 | 97.9% |
| with-lists | 95 | 27 | 68 | 28.4% |

Repeat-heavy slice: model-call rate drops **+69.5 pp** when the live lists are active (93/95 → 27/95).

## Destructive cases allowed by live lists (risk flag)

No destructive case was allowed by a live entry in this run.

## Reproducing

```bash
python3 bench/run.py --with-lists --out docs/bench-with-lists.md
```
