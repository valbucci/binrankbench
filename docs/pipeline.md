# Pipeline

You may jump straight to step 2 if you are using the [database dump on Zenodo](https://zenodo.org/records/20439493/files/binrankbench_cose.dump).

## Step 0: Feature extraction (optional)

Requires [bin2ml](https://github.com/valbucci/bin2ml) and radare2 6.0.4
(see [installation.md](installation.md)).

`<binaries_dir>` must contain one sub-directory per project, each holding the
raw binary files:

```bash
python -m binrankbench extract <binaries_dir> <output_dir>
```

Options:

```plaintext
-m / --modes MODE [MODE ...]   bin2ml extraction modes
                               (default: bytes finfo zigs func-cfg cg bininfo)
-n / --num-threads N           bin2ml worker threads per project (default: 8)
--min-basic-blocks N           skip functions with fewer than N basic blocks
                               (default: 5)
```

## Step 1: Ingestion

Organise extracted data as:

```plaintext
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

```plaintext
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

## 2. Evaluation

```bash
python -m binrankbench evaluate
```

Runs evaluation all steps 00-04 in order.

- Results stored in `evaluation/results/`;
- Logs stored in `evaluation/logs/`.

Individual steps can also be run as follows:

```bash
python evaluation/steps/02_evaluate_positives.py
python evaluation/steps/03_evaluate_negatives.py
```

### Accuracy

The accuracy evaluation follows the procedure described in the paper below:

> Marcelli, Andrea, et al.
> "How machine learning is solving the binary function similarity problem."
> 31st USENIX Security Symposium (USENIX Security 22). 2022.

#### Scenarios

- Single variable:
  - `arch`: different instruction-set architecture (e.g. mips32 vs. arm32)
  - `bit`: different bitness (e.g. x86 vs. x64)
  - `comp`: different compiler (e.g. gcc vs. clang)
  - `ver`: different compiler version (e.g. gcc-5 vs. gcc-7)
  - `opt`: different compiler optimisations (e.g. O1 vs. Os)
- Aggregated:
  - `XO`: same as `opt`
  - `XC`: `comp` + `ver` + `opt`
  - `XA`: `arch` + `bit`
  - `XC_XB`: `comp` + `ver` + `opt` + `bit`
  - `XA_XO`: `arch` + `bit` + `opt`
  - `XM`: any variable may diverge
  - `XZ`: all variables must diverge

**Note:**

- The `XO` scenario is identical to `opt`.
- An additional `XZ` scenario not included in the original paper
  was introduced as stress test.

#### Configurations

- **1vN**: One positive pair ranked against many negatives
       (default N = 100).
  - Evaluates search and ranking performance:
    *find a target function within a large distractor haystack*.
  - Scenarios: `XO`, `XA`, `XC`, `XC_XB`, `XA_XO`, `XM`, `XZ`
- **1v1**: Equal positive and negative pairs.
  - Evaluates the accuracy of similarity estimations:
    *how likely is it for positive pairs to score a
    higher similarity than negatives*.
  - Scenarios: `arch`, `bit`, `comp`, `ver`, `opt`, `XZ`

### Efficiency

The efficiency evaluation is inspired by the FRASHER framework
as described in the paper below:

> Göbel, Thomas, et al.
> "FRASHER–A framework for automated evaluation of similarity hashing."
> Forensic Science International: Digital Investigation 42 (2022): 301407.

The original paper evaluated byte-level fuzzy hashes. In contrast,
binary-function fuzzy hashing draws from heterogeneous feature sets.
Therefore, the evaluation focuses on practical efficiency performance,
including the following:

- *Generation speed*: given cached radare2 features, how many fuzzy hash
                    digests per second can be generated.
- Comparison speed: after generating the digests, how many pair similarities
                    can be estimated per second.

**Note:** The absolute results will depend on the compute at hand.
      Hence, the relevant results is how each algorithm will be ranked
      against each other.
