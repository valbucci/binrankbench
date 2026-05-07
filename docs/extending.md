# Adding a New Similarity Strategy

Two layers to implement:

1. **Algorithm** (`binrankbench/modules/`) — pure Python, no database dependency.
2. **Storage** (`binrankbench/storage/models/signatures/`) — SQLAlchemy ORM table that persists the computed digest.

## Checklist

```
[ ] 1. Create  binrankbench/modules/my_strategy.py
[ ] 2. Create  binrankbench/storage/models/signatures/my_strategy.py
[ ] 3. Add one import line in  binrankbench/storage/models/signatures/__init__.py
[ ] 4. Add a Task class in  binrankbench/modules/generate/tasks.py
[ ] 5. Wire the Task into the result and worker layers
```

## Step 1: Implement the algorithm

Create `binrankbench/modules/my_strategy.py`. The module must expose a builder
that accepts radare2-extracted data and returns a digest, plus a similarity function.

```python
"""My custom hash strategy."""
from binrankbench.common.types import R2FunctionInfoIn, R2CodeInfoIn, R2CallGraph


class MyStrategyFeatures:
    """Holds the computed sub-features before they are serialised."""
    def __init__(self, digest: str, param_a: int):
        self.digest = digest
        self.param_a = param_a


class MyStrategyBuilder:
    @classmethod
    def build(
        cls,
        func_info: R2FunctionInfoIn,
        cfg: R2CodeInfoIn,
        call_graph: R2CallGraph,
    ) -> MyStrategyFeatures:
        """Compute the signature for a single function."""
        # ... your algorithm here ...
        digest = "deadbeef"
        return MyStrategyFeatures(digest=digest, param_a=64)


class MyStrategy:
    @staticmethod
    def hash_similarity(digest_a: str, digest_b: str) -> float:
        """Return a similarity score in [0, 1]."""
        return 1.0 if digest_a == digest_b else 0.0
```

The types in `binrankbench.common.types` (`R2FunctionInfoIn`, `R2ZignatureIn`,
`R2CodeInfoIn`, `R2CallGraph`, ...) map directly to the JSON files produced by
bin2ml / radare2. See `binrankbench/common/types.py` for the full set.

Export the public API from `binrankbench/modules/__init__.py`:

```python
from binrankbench.modules.my_strategy import MyStrategy
```

## Step 2: Create the ORM signature model

Create `binrankbench/storage/models/signatures/my_strategy.py`:

```python
"""My strategy ORM model."""
from __future__ import annotations
from sqlalchemy import ForeignKey, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column
from . import Signature


class MyStrategySignature(Signature, strategy="my_strategy"):
    __tablename__ = "my_strategy_signature"

    signature_id: Mapped[int] = mapped_column(
        ForeignKey("signature.id", ondelete="CASCADE"), primary_key=True
    )
    digest: Mapped[str] = mapped_column(Text, nullable=False)
    param_a: Mapped[int] = mapped_column(Integer, nullable=False, default=64)
```

`strategy="my_strategy"` must be unique; the registry raises `ValueError` at
import time on a collision. `signature_id` must be `ForeignKey("signature.id")`
with `primary_key=True`.

## Step 3: Register the import

Add one line inside `_load_signatures()` in
`binrankbench/storage/models/signatures/__init__.py`:

```python
def _load_signatures() -> None:
    from . import catalog1
    from . import ccbhash
    from . import fss
    from . import machoke
    from . import bytes
    from . import my_strategy   # ← ADD THIS LINE
```

Then run schema migration (safe on an existing database):

```bash
python -c "
from binrankbench.storage import get_engine, init_db
init_db(get_engine())
print('Done')
"
```

## Step 4: Add a Task class

Add `MyStrategyTask` to `binrankbench/modules/generate/tasks.py` following the
pattern of the existing tasks (e.g. `MachokeTask`):

```python
class MyStrategyTask(JSONPayloadTask):
    def _run(self) -> MyStrategyResult:
        from binrankbench.modules.my_strategy import MyStrategyBuilder
        features = MyStrategyBuilder.build(
            func_info=...,
            cfg=...,
            call_graph=self._get_callgraph(),
        )
        return MyStrategyResult(
            func_addr=self.func_addr, success=True, error=None,
            my_strategy_features=features,
        )

    def run(self) -> MyStrategyResult:
        try:
            return self._run()
        except Exception as e:
            return self.handle_error(MyStrategyResult, self.func_addr, e)
```

Add the corresponding `MyStrategyResult` to
`binrankbench/modules/generate/result.py` (follow `MachokeResult`), and register
`MyStrategyTask: "my_strategy"` in `TASK_TYPE_MAP` at the bottom of `tasks.py`.

## Step 5: Wire the worker and writer

In `binrankbench/storage/mp_worker.py`, add `"my_strategy"` to the list of
strategies checked in the poster loop, matching the pattern for machoke/ccbhash.

In `binrankbench/storage/writer.py`, add:
- Import of `MyStrategySignature`
- A `write_my_strategy(func, features)` method that calls `write_signature`
- An `elif isinstance(res, MyStrategyResult)` branch in `write_batch`

## Complex strategies (feature deduplication)

If your strategy computes sub-features that should be deduplicated across
functions (like CCBHash with its 13 component hashes), follow the pattern in
`signatures/ccbhash.py`, `storage/models/dedup.py`, and `storage/writer.py`:

1. Define dedup table classes in `dedup.py` (subclass `ByteDedupBase`).
2. Add a fingerprint model in your signature file with a `UNIQUE` constraint spanning all feature columns.
3. Add `bulk_write_my_strategy` to `DBWriter` using `bulk_get_or_create_multi` and `bulk_upsert_pivots`.

## FAQ

**How do I query my new strategy from a notebook?**

```python
from binrankbench.storage.session import get_engine, make_session_factory
from binrankbench.storage.models.signatures.my_strategy import MyStrategySignature
```

**Can I add columns to an existing signature?**

Add the column to the ORM class and run a database migration (Alembic recommended
for production; `init_db` for development scratch databases).

**What if two strategies produce the same `strategy` string?**

The registry raises `ValueError` at import time and identifies the conflicting class.
