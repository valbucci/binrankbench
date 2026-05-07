# Quickstart

Reproduce paper results using the pre-loaded database dump (fuzzy hashes for
4,278,822 functions from Cisco-Talos Dataset-1). No binary analysis required.

## Docker

**1. Clone and configure**

```bash
git clone <repo-url> && cd binrankbench
cp .env.example .env      # defaults work out of the box
```

**2. Download the database dump**

Download `binrankbench_cose.dump` from Zenodo and place it in the repo root:
[https://doi.org/10.5281/zenodo.XXXXXXX](https://doi.org/10.5281/zenodo.XXXXXXX)

**3. Start the database and restore the dump**

```bash
docker compose up -d db
docker compose run --rm app pg_restore -h db -U postgres -d binrankbench binrankbench_cose.dump
```

The restore takes 10–20 minutes depending on disk speed.

**4. Run the evaluation**

```bash
docker compose run --rm app python -m binrankbench evaluate
```

Results are written to `evaluation/results/`; logs to `evaluation/logs/`.
This takes several hours on the full dataset.

**5. Explore results in JupyterLab**

```bash
docker compose up app
```

Open [http://localhost:8888](http://localhost:8888) and run the notebooks in
`evaluation/notebooks/`.

### Running other commands in Docker

Prefix any command with `docker compose run --rm app`. For example:

```bash
docker compose run --rm app python evaluation/stages/00_select_pools.py
```

The rest of this documentation shows commands without the Docker prefix; add it
when running inside the container.

## Local Python

**1. Install dependencies**

```bash
git clone <repo-url> && cd binrankbench
pip install -r requirements.txt
cp .env.example .env
```

**2. Start PostgreSQL**

```bash
docker compose up -d db     # or point DB_URL in .env at an existing instance
```

**3. Restore the database dump**

```bash
pg_restore -h localhost -U postgres -d binrankbench binrankbench_cose.dump
```

**4. Run the evaluation**

```bash
python -m binrankbench evaluate
```

**5. Open the notebooks**

```bash
jupyter lab evaluation/notebooks/
```

## Running stages individually

`python -m binrankbench evaluate` runs all four stages in sequence. To run them
one at a time:

```bash
python evaluation/stages/00_select_pools.py
python evaluation/stages/01_generate_pairs.py
python evaluation/stages/02_evaluate_positives.py
python evaluation/stages/03_evaluate_negatives.py
```

| Notebook | Purpose |
|---|---|
| `10_exploratory_analysis.ipynb` | Dataset statistics and function distribution |
| `11_ranking_metrics.ipynb` | MRR, Recall@K, and ranking curves per strategy |
| `12_ablation_study.ipynb` | ROC-AUC and per-feature ablation for CCBHash |
