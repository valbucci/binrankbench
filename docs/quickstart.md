# Quickstart

Reproduce paper results using the pre-loaded database dump (fuzzy hashes for
4,278,822 functions from Cisco-Talos Dataset-1). No binary analysis required.

## Docker

### 1. Clone and configure

```bash
git clone <repo-url> && cd binrankbench
cp .env.example .env      # defaults work out of the box
```

### 2. Download the database dump

Download `binrankbench_cose.dump` from Zenodo and place it in the repo root:
[https://doi.org/10.5281/zenodo.20439492](https://doi.org/10.5281/zenodo.20439492)

### 3. Start the database and restore the dump

```bash
docker compose up -d db
docker compose run --rm app pg_restore -h db -U postgres -d binrankbench binrankbench_cose.dump
```

The restore takes 10-20 minutes depending on disk speed.

### 4. Run the evaluation with Docker

```bash
docker compose run --rm app python -m binrankbench evaluate
```

Results are written to `evaluation/results/`; logs to `evaluation/logs/`.
This takes several hours on the full dataset.

### (*Optional*) Running other commands in Docker

Prefix any command with `docker compose run --rm app`. For example:

```bash
docker compose run --rm app python evaluation/stages/00_select_pools.py
```

The rest of this documentation shows commands without the Docker prefix; add it
when running inside the container.

## Local Python

### 1. Install dependencies

```bash
git clone <repo-url> && cd binrankbench
pip install -r requirements.txt
cp .env.example .env
```

### 2. Start PostgreSQL

```bash
docker compose up -d db     # or point DB_URL in .env at an existing instance
```

### 3. Restore the database dump

```bash
pg_restore -h localhost -U postgres -d binrankbench binrankbench_cose.dump
```

### 4. Run the evaluation

```bash
python -m binrankbench evaluate
```

### (*Optional*) Running stages individually

`python -m binrankbench evaluate` runs all four stages in sequence. To run them
one at a time:

```bash
python evaluation/steps/00_select_pools.py
python evaluation/steps/01_generate_pairs.py
python evaluation/steps/02_evaluate_positives.py
python evaluation/steps/03_evaluate_negatives.py
python evaluation/steps/04_frashbf_benchmark.py
```
