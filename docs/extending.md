# Adding a New Similarity Strategy

Three layers to implement:

1. **Algorithm:** Binary-function similarity algorithm at `binrankbench/modules/`.
2. **Database:** SQLAlchemy object-relational mapping for DB persistence at
             `binrankbench/storage/models/signatures/`.
3. **Generate:** Digest generation task and result handling at
             `binrankbench/modules/generate/tasks.py` and
             `binrankbench/modules/generate/result.py`
4. **Ingest:** Add your new strategy to the ingest pipeline by updating the
           worker class at `binrankbench/storage/mp_worker.py` and
           `binrankbench/storage/writer.py`.

## 1. Implement the algorithm

Create `binrankbench/modules/my_strategy.py` and
export the public API from `binrankbench/modules/__init__.py`.

**Note:** The `R2*` types in `binrankbench.common.types` map directly to the
JSON files produced by bin2ml / radare2.

## 2. Create the ORM signature model

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

**Note:** `strategy="my_strategy"` must be unique; the registry raises
`ValueError` at import time on a collision. `signature_id` must
be `ForeignKey("signature.id")` with `primary_key=True`.

To register the import, add one line inside `_load_signatures()` in
`binrankbench/storage/models/signatures/__init__.py`:

```python
def _load_signatures() -> None:
    from . import catalog1
    from . import ccbhash
    from . import fss
    from . import machoke
    from . import bytes
    from . import my_strategy   # <- ADD THIS LINE
```

Then run schema migration (safe on an existing database):

```bash
python -c "
from binrankbench.storage import get_engine, init_db
init_db(get_engine())
print('Done')
"
```

## 3. Add a Task class

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

## 4. Wire the worker and writer

In `binrankbench/storage/mp_worker.py`, add `"my_strategy"` to the list of
strategies checked in the poster loop, matching the pattern for machoke/ccbhash.

In `binrankbench/storage/writer.py`, add:

- Import of `MyStrategySignature`
- A `write_my_strategy(func, features)` method that calls `write_signature`
- An `elif isinstance(res, MyStrategyResult)` branch in `write_batch`

## (*Optional*) Attribute deduplication

If your strategy computes sub-features that should be deduplicated across
functions (like CCBHash with its 13 component hashes), follow the pattern in
`signatures/ccbhash.py`, `storage/models/dedup.py`, and `storage/writer.py`:

1. Define dedup table classes in `dedup.py` (subclass `ByteDedupBase`).
2. Add a fingerprint model in your signature file with a `UNIQUE` constraint
   spanning all feature columns.
3. Add `bulk_write_my_strategy` to `DBWriter` using `bulk_get_or_create_multi`
   and `bulk_upsert_pivots`.
