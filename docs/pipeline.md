# Pipeline

## Step 0: Feature extraction (optional)

Skip this step if you are using the pre-loaded Zenodo database dump.

Requires [bin2ml](https://github.com/valbucci/bin2ml) and radare2 6.0.4
(see [installation.md](installation.md)).

`<binaries_dir>` must contain one sub-directory per project, each holding the
raw binary files:

```bash
python -m binrankbench extract <binaries_dir> <output_dir>
```

Options:

```
-m / --modes MODE [MODE ...]   bin2ml extraction modes
                               (default: bytes finfo zigs func-cfg cg bininfo)
-n / --num-threads N           bin2ml worker threads per project (default: 8)
--min-basic-blocks N           skip functions with fewer than N basic blocks (default: 5)
```

## Step 1: Ingestion

Organise extracted data as:

```
<dataset_path>/
  <project_name>/
    <binary_name>_cfg.json
    <binary_name>_func-cfg/
    ...
```

```bash
python -m binrankbench ingest <dataset_path>
```

Options:

```
--strategies STRATEGY [...]   strategies to compute (default: all)
                              choices: ccbhash machoke fss catalog1 bytes function_details
--datasets DATASET [...]      dataset tags to attach to every ingested binary
--overwrite                   re-compute and overwrite existing signatures
--n-runners N                 TaskRunner worker count (default: 12)
--n-posters N                 TaskPoster worker count (default: 4)
--single-process              single-process pipeline, useful for debugging
```

To clear runtime logs and `.ingest_done` markers before a re-run:

```bash
python -m binrankbench ingest --clear-logs <dataset_path>
```

## Step 2: Pool selection

```bash
python evaluation/stages/00_select_pools.py
```

Partitions functions into Tier 1 (anchor pool) and Tier 2 (distractor pool).
Writes `tier1_pool.csv` and `tier2_pool.csv` to `evaluation/results/`.

## Step 3: Pair generation

```bash
python evaluation/stages/01_generate_pairs.py
```

Writes positive and negative pairs for all configured scenarios to
`evaluation/results/<config>/`.

## Step 4: Evaluation

```bash
python -m binrankbench evaluate
```

Runs stages 00–03 in order. Results go to `evaluation/results/`; logs to
`evaluation/logs/`. Individual stages can also be run directly:

```bash
python evaluation/stages/02_evaluate_positives.py
python evaluation/stages/03_evaluate_negatives.py
```

## Step 5: Analysis

```bash
jupyter lab evaluation/notebooks/
```

| Notebook | Purpose |
|---|---|
| `10_exploratory_analysis.ipynb` | Dataset statistics and function distribution |
| `11_ranking_metrics.ipynb` | MRR, Recall@K, and ranking curves per strategy |
| `12_ablation_study.ipynb` | ROC-AUC and per-feature ablation for CCBHash |

## Evaluation scenarios

| Tag | Dimension |
|---|---|
| `XO` | Optimisation level |
| `XA` | Architecture |
| `XC` | Compiler |
| `XC_XB` | Compiler + bit-width |
| `XA_XO` | Architecture + optimisation |
| `XM` | Mixed (multiple dimensions) |
| `XZ` | Obfuscation (OLLVM) |

Two evaluation protocols:

- **1vN** — one anchor ranked against N distractors (default N = 100)
- **1v1** — pairwise similarity scored on 500 000 positive pairs
