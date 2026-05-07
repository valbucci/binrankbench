"""
DBWriter — high-level API for writing analysis results to the storage layer.

Each write method:
  1. ``get_or_create`` the fingerprint row (enforces UNIQUE content dedup).
  2. Upsert the function↔fingerprint pivot row.
  3. Upsert the ``strategy_membership`` row (bookkeeping).

Usage
-----
    from binrankbench.storage.session import get_engine, get_session, init_db
    from binrankbench.storage.writer import DBWriter

    engine = get_engine("postgresql+psycopg2://user:pw@localhost/binrankbench")
    init_db(engine)

    with get_session(engine) as sess:
        writer = DBWriter(sess)
        func = writer.get_or_create_function(
            project="openssh", bin_name="sshd", func_addr="0x401234",
            func_name="do_accept",
        )
        writer.write_ccbhash(func, features=ccbhash_features_obj)
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any
import logging

logger = logging.getLogger(__name__)

import struct
from sqlalchemy import select as _select, update as _update, bindparam, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from dataclasses import asdict

from binrankbench.common.hex import hexvalue_to_bytes
from binrankbench.modules.fss import FunctionSimSearch
from binrankbench.modules.generate.result import (
    CCBHashResult, MachokeResult,
    FunctionSimSearchResult, Catalog1Result,
    BytesResult, FunctionDetailsResult, SkipInfo
)

from .models import (
    Binary,
    BinaryDatasetTag,
    Catalog1Fingerprint,
    CATALOG1_NUM_SLOTS,
    CCBHashFingerprint,
    Dataset,
    Function,
    FunctionByteSig,
    FunctionCCBHash,
    FunctionCatalog1,
    FunctionFSSMarcelli,
    FunctionFSSMarcelliWeighted,
    FunctionFSSOriginal,
    FunctionMachoke,
    FunctionName,
    FunctionScalars,
    FSSMarcelliFingerprint,
    FSSMarcelliWeightedFingerprint,
    FSSOriginalFingerprint,
    SkipLog,
    SkipReason,
    StrategyID,
    StrategyMembership,
    ByteFingerprint,
    Project,
    get_or_create,
    bulk_get_or_create,
)
from .models.dedup import ByteSequence
from .models.signatures.machoke import MachokeHash
from .models.signatures.ccbhash import (
    CCBHashNameSubhash, CCBHashCFGSubhash, CCBHashCallGraphSubhash,
    CCBHashOpcodesSubhash, CCBHashVarArgsSubhash, CCBHashVarLocalsSubhash,
)


class DBWriter:
    """Wraps a Session and exposes a write API.  Callers control commit."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._project_cache: dict[str, Project] = {}
        self._binary_cache: dict[tuple[int, str], Binary] = {}
        self._sequence_cache: dict[bytes, int] = {}
        self._fingerprint_cache: dict[tuple[int, ...], int] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_membership(self, function: Function, strategy_id: StrategyID) -> None:
        """Upsert a strategy_membership row."""
        existing = self.session.execute(
            _select(StrategyMembership).where(
                StrategyMembership.function_id == function.id,
                StrategyMembership.strategy_id == int(strategy_id),
            )
        ).scalar_one_or_none()
        if existing is None:
            row = StrategyMembership(
                function_id=function.id,
                strategy_id=int(strategy_id),
            )
            try:
                with self.session.begin_nested():
                    self.session.add(row)
                    self.session.flush()
            except IntegrityError:
                pass


    def _upsert_pivot(
        self,
        pivot_cls: type,
        function: Function,
        fingerprint_id: int,
        fk_col: str = "fingerprint_id",
    ) -> Any:
        """Insert or retrieve the pivot row for (function, fingerprint)."""
        existing = self.session.execute(
            _select(pivot_cls).where(
                getattr(pivot_cls, "function_id") == function.id
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        row = pivot_cls(function_id=function.id, **{fk_col: fingerprint_id})
        try:
            with self.session.begin_nested():
                self.session.add(row)
                self.session.flush()
        except IntegrityError:
            # It was inserted concurrently. Fetch it since we might need the object.
            row = self.session.execute(
                _select(pivot_cls).where(
                    getattr(pivot_cls, "function_id") == function.id
                )
            ).scalar_one_or_none()
        return row

    def bulk_record_membership(self, functions: list[Function], strategy_id: StrategyID) -> None:
        if not functions: return
        stmt = pg_insert(StrategyMembership).values([
            {"function_id": f.id, "strategy_id": int(strategy_id)}
            for f in functions
        ]).on_conflict_do_nothing(
            index_elements=['function_id', 'strategy_id']
        )
        self.session.execute(stmt)

    def bulk_upsert_pivots(self, pivot_cls: type, associations: list[dict]) -> None:
        if not associations: return
        stmt = pg_insert(pivot_cls).values(associations).on_conflict_do_nothing(
            index_elements=['function_id']
        )
        self.session.execute(stmt)

    def bulk_get_or_create_multi(
        self, model: type, unique_cols: list[str], values: list[dict]
    ) -> dict[tuple, int]:
        if not values: return {}
        stmt = pg_insert(model).values(values).on_conflict_do_nothing(
            index_elements=unique_cols
        )
        self.session.execute(stmt)
        
        # 2. Fetch IDs for all requested records. 
        # Using handle single-column .in_() or multi-column tuple_().in_() 
        # is significantly faster in PostgreSQL than large OR blocks.
        query_cols = [getattr(model, col) for col in unique_cols]
        
        results = []
        if len(unique_cols) == 1:
            # Single column optimization: col.in_([v1, v2, ...])
            col_name = unique_cols[0]
            all_vals = list({v[col_name] for v in values})
            col_attr = getattr(model, col_name)
            
            non_null_vals = [v for v in all_vals if v is not None]
            has_null = None in all_vals
            
            for i in range(0, len(non_null_vals), 1000):
                chunk = non_null_vals[i:i+1000]
                results.extend(self.session.execute(
                    _select(*query_cols, model.id).where(col_attr.in_(chunk))
                ).all())
                
            if has_null:
                results.extend(self.session.execute(
                    _select(*query_cols, model.id).where(col_attr.is_(None))
                ).all())
        else:
            # Multi-column optimization: tuple_(col1, col2).in_([(v1, v2), ...])
            unique_tuples = list({tuple(v[col] for col in unique_cols) for v in values})
            
            non_null_tuples = [t for t in unique_tuples if None not in t]
            null_tuples = [t for t in unique_tuples if None in t]
            
            for i in range(0, len(non_null_tuples), 500):
                chunk = non_null_tuples[i:i+500]
                results.extend(self.session.execute(
                    _select(*query_cols, model.id).where(tuple_(*query_cols).in_(chunk))
                ).all())
                
            if null_tuples:
                from sqlalchemy import and_, or_
                conditions = []
                for t in null_tuples:
                    conds = []
                    for col_idx, val in enumerate(t):
                        if val is None:
                            conds.append(query_cols[col_idx].is_(None))
                        else:
                            conds.append(query_cols[col_idx] == val)
                    conditions.append(and_(*conds))
                    
                for i in range(0, len(conditions), 500):
                    chunk = conditions[i:i+500]
                    results.extend(self.session.execute(
                        _select(*query_cols, model.id).where(or_(*chunk))
                    ).all())
            
        return {tuple(row[:-1]): row[-1] for row in results}

    # ------------------------------------------------------------------
    # Core entities
    # ------------------------------------------------------------------

    def get_or_create_project(self, name: str) -> Project:
        if name in self._project_cache:
            return self._project_cache[name]
        proj, _ = get_or_create(self.session, Project, unique_on={"name": name})
        self._project_cache[name] = proj
        return proj

    def get_or_create_binary(
        self, project: str | Project, bin_name: str, *,
        arch: str | None = None, bits: int | None = None,
        cc: str | None = None, compiler: str | None = None,
        opt_level: str | None = None, sha256: str | None = None,
    ) -> Binary:
        if isinstance(project, str):
            project = self.get_or_create_project(project)
        
        cache_key = (project.id, bin_name)
        if cache_key in self._binary_cache:
            return self._binary_cache[cache_key]
            
        binary, _ = get_or_create(
            self.session, Binary,
            unique_on={"project_id": project.id, "bin_name": bin_name},
            defaults={"arch": arch, "bits": bits, "cc": cc,
                      "compiler": compiler, "opt_level": opt_level, "sha256": sha256},
        )
        self._binary_cache[cache_key] = binary
        return binary

    def get_or_create_function(
        self, project: str | Project, bin_name: str, func_addr: str, *,
        func_name: str | None = None,
        arch: str | None = None, bits: int | None = None,
        cc: str | None = None, compiler: str | None = None,
        opt_level: str | None = None, sha256: str | None = None,
    ) -> Function:
        if not func_addr:
            raise ValueError(f"Empty or missing function address for {bin_name}")
            
        try:
            addr_int = int(str(func_addr), 0)
            if addr_int < 0:
                raise ValueError(f"Function address cannot be negative: {func_addr}")
            if addr_int == 0:
                logger.warning(f"Suspicious function address (0) inserted for {bin_name}")
        except ValueError:
            logger.error(f"Function address '{func_addr}' cannot be parsed as an integer for {bin_name}")
            raise ValueError(f"Invalid function address format: {func_addr}")
            
        binary = self.get_or_create_binary(
            project, bin_name, arch=arch, bits=bits, cc=cc,
            compiler=compiler, opt_level=opt_level, sha256=sha256,
        )
        name_id: int | None = None
        if func_name:
            fn_row, _ = get_or_create(
                self.session, FunctionName, unique_on={"name": func_name}
            )
            name_id = fn_row.id
        function, _ = get_or_create(
            self.session, Function,
            unique_on={"binary_id": binary.id, "func_addr": func_addr},
            defaults={"name_id": name_id},
        )
        return function

    def bulk_get_or_create_functions(
        self, project: str | Project, definitions: list[dict]
    ) -> dict[tuple[str, str], Function]:
        """
        Bulk get or create functions, yielding a mapping of (bin_name, func_addr) -> Function.
        definitions: list of dicts with keys 'bin_name', 'func_addr', and optionally 'func_name'.
        """
        if not definitions: return {}
        
        if isinstance(project, str):
            project = self.get_or_create_project(project)
            
        # Validate function addresses
        valid_defs = []
        for d in definitions:
            try:
                addr_int = int(str(d["func_addr"]), 0)
                if addr_int < 0: continue
                valid_defs.append(d)
            except (ValueError, TypeError):
                continue
                
        if not valid_defs: return {}
            
        # 1. Resolve Binaries
        unique_bins = {d["bin_name"] for d in valid_defs}
        un_cached_bins = [b for b in unique_bins if (project.id, b) not in self._binary_cache]
        if un_cached_bins:
            bin_values = [{"project_id": project.id, "bin_name": b} for b in un_cached_bins]
            bin_maps = self.bulk_get_or_create_multi(Binary, ["project_id", "bin_name"], bin_values)
            for b_name in un_cached_bins:
                b_id = bin_maps[(project.id, b_name)]
                self._binary_cache[(project.id, b_name)] = Binary(id=b_id, project_id=project.id, bin_name=b_name)
        
        # 2. Resolve Function Names
        unique_names = {d.get("func_name") for d in valid_defs if d.get("func_name")}
        name_maps = {}
        if unique_names:
            name_values = [{"name": n} for n in unique_names]
            name_maps = self.bulk_get_or_create_multi(FunctionName, ["name"], name_values)
            
        # 3. Resolve Functions
        unique_func_values = []
        seen = set()
        for d in valid_defs:
            bin_id = self._binary_cache[(project.id, d["bin_name"])].id
            name_id = name_maps.get((d.get("func_name"),)) if d.get("func_name") else None
            k = (bin_id, d["func_addr"])
            if k not in seen:
                seen.add(k)
                unique_func_values.append({
                    "binary_id": bin_id,
                    "func_addr": d["func_addr"],
                    "name_id": name_id
                })
                
        func_maps = self.bulk_get_or_create_multi(Function, ["binary_id", "func_addr"], unique_func_values)
        
        # 4. Synthesize Function objects
        results = {}
        for d in valid_defs:
            bin_id = self._binary_cache[(project.id, d["bin_name"])].id
            f_id = func_maps.get((bin_id, d["func_addr"]))
            if f_id:
                results[(d["bin_name"], d["func_addr"])] = Function(id=f_id, binary_id=bin_id, func_addr=d["func_addr"])
            
        return results

    # ------------------------------------------------------------------
    # Dataset / tagging
    # ------------------------------------------------------------------

    def get_or_create_dataset(self, name: str, description: str = "") -> Dataset:
        ds, _ = get_or_create(
            self.session, Dataset,
            unique_on={"name": name},
            defaults={"description": description or None},
        )
        return ds

    def tag_binary(self, binary: Binary, dataset: Dataset) -> None:
        existing = self.session.execute(
            _select(BinaryDatasetTag).where(
                BinaryDatasetTag.binary_id == binary.id,
                BinaryDatasetTag.dataset_id == dataset.id,
            )
        ).scalar_one_or_none()
        if existing is None:
            self.session.add(BinaryDatasetTag(binary_id=binary.id, dataset_id=dataset.id))
            self.session.flush()

    # ------------------------------------------------------------------
    # Function scalars
    # ------------------------------------------------------------------

    def write_function_scalars(
        self, function: Function, scalars: dict[str, int | None],
    ) -> FunctionScalars:
        _valid = {
            "ninstructions", "nbbs", "indegree", "outdegree",
            "nlocals", "nargs", "stackframe", "size",
            "cc", "ebbs", "edges", "bbsum",
        }
        filtered = {k: v for k, v in scalars.items() if k in _valid}
        existing = self.session.execute(
            _select(FunctionScalars).where(FunctionScalars.function_id == function.id)
        ).scalar_one_or_none()
        if existing is not None:
            for k, v in filtered.items():
                setattr(existing, k, v)
            self.session.flush()
            return existing
        row = FunctionScalars(function_id=function.id, **filtered)
        self.session.add(row)
        self.session.flush()
        return row

    # ------------------------------------------------------------------
    # CCBHash
    # ------------------------------------------------------------------

    def write_ccbhash(self, function: Function, features: Any) -> FunctionCCBHash:
        """Write CCBHash: dedup sub-hashes → get_or_create fingerprint → upsert pivot."""
        session = self.session

        def enc(model_cls: type, hex_val: str) -> int:
            row, _ = get_or_create(session, model_cls, unique_on={"value": bytes.fromhex(hex_val)})
            return row.id

        fp, _ = get_or_create(
            session, CCBHashFingerprint,
            unique_on={
                "name_subhash_id":        enc(CCBHashNameSubhash,       str(features.name_hash)),
                "cfg_subhash_id":         enc(CCBHashCFGSubhash,        str(features.cfg_hash)),
                "call_graph_subhash_id":  enc(CCBHashCallGraphSubhash,  str(features.call_graph_hash)),
                "opcodes_subhash_id":     enc(CCBHashOpcodesSubhash,    str(features.opcodes_hash)),
                "var_args_subhash_id":    enc(CCBHashVarArgsSubhash,    str(features.args_hash)),
                "var_locals_subhash_id":  enc(CCBHashVarLocalsSubhash,  str(features.locals_hash)),
                "ninstructions_bucket":   int(features.ninstructions_hash, 16),
                "indegree_bucket":        int(features.indegree_hash,    16),
                "outdegree_bucket":       int(features.outdegree_hash,   16),
                "nvars_bucket":           int(features.nvars_hash,       16),
                "cc_bucket":              int(features.cc_hash,          16),
                "nblocks_bucket":         int(features.nblocks_hash,     16),
                "stackframe_bucket":      int(features.stackframe_hash,  16),
            },
        )
        pivot = self._upsert_pivot(FunctionCCBHash, function, fp.id)
        self._record_membership(function, StrategyID.ccbhash)
        return pivot

    # ------------------------------------------------------------------
    # FSS
    # ------------------------------------------------------------------

    def write_fss_original(
        self, function: Function, first: bytes, second: bytes
    ) -> FunctionFSSOriginal:
        fp, _ = get_or_create(
            self.session, FSSOriginalFingerprint,
            unique_on={"first": first, "second": second},
        )
        pivot = self._upsert_pivot(FunctionFSSOriginal, function, fp.id)
        self._record_membership(function, StrategyID.fss_original)
        return pivot

    def write_fss_marcelli(
        self, function: Function, first: bytes, second: bytes
    ) -> FunctionFSSMarcelli:
        fp, _ = get_or_create(
            self.session, FSSMarcelliFingerprint,
            unique_on={"first": first, "second": second},
        )
        pivot = self._upsert_pivot(FunctionFSSMarcelli, function, fp.id)
        self._record_membership(function, StrategyID.fss_marcelli)
        return pivot

    def write_fss_marcelli_weighted(
        self, function: Function, first: bytes, second: bytes
    ) -> FunctionFSSMarcelliWeighted:
        fp, _ = get_or_create(
            self.session, FSSMarcelliWeightedFingerprint,
            unique_on={"first": first, "second": second},
        )
        pivot = self._upsert_pivot(FunctionFSSMarcelliWeighted, function, fp.id)
        self._record_membership(function, StrategyID.fss_marcelli_weighted)
        return pivot

    # ------------------------------------------------------------------
    # Machoke
    # ------------------------------------------------------------------

    def write_machoke(
        self, function: Function, digest: bytes, machoke_line: str = ""
    ) -> FunctionMachoke:
        fp, _ = get_or_create(
            self.session, MachokeHash,
            unique_on={"digest": digest},
            defaults={"line": machoke_line},
        )
        pivot = self._upsert_pivot(FunctionMachoke, function, fp.id)
        self._record_membership(function, StrategyID.machoke)
        return pivot

    # ------------------------------------------------------------------
    # Byte Signature
    # ------------------------------------------------------------------

    def get_or_create_byte_sequence(self, bytes_data: bytes | None) -> int | None:
        """Fetch or create a ByteSequence row for given raw bytes."""
        if not bytes_data:
            return None
        b_hash = hashlib.sha256(bytes_data).digest()
        row, _ = get_or_create(
            self.session, ByteSequence,
            unique_on={"bytes_hash": b_hash},
            defaults={"bytes_sequence": bytes_data},
        )
        return row.id

    def write_byte_signature(
        self, function: Function,
        raw_bytes: bytes,
        nibble_mask: bytes | None = None,
        bit_mask: bytes | None = None,
    ) -> FunctionByteSig:

        raw_id = self.get_or_create_byte_sequence(raw_bytes)
        if not raw_id:
            raise ValueError("raw_bytes cannot be empty")
        fp, _ = get_or_create(
            self.session, ByteFingerprint,
            unique_on={
                "raw_bytes_id":  raw_id,
                "nibble_mask_id": self.get_or_create_byte_sequence(nibble_mask),
                "bit_mask_id":    self.get_or_create_byte_sequence(bit_mask),
            },
        )
        pivot = self._upsert_pivot(FunctionByteSig, function, fp.id)
        self._record_membership(function, StrategyID.bytes_signature)
        return pivot

    # ------------------------------------------------------------------
    # Catalog1
    # ------------------------------------------------------------------

    def write_catalog1(
        self, function: Function, minhash_values: list[int],
    ) -> FunctionCatalog1:
        """
        Write a Catalog1 signature.

        Parameters
        ----------
        function:
            Target function.
        minhash_values:
            List of 32-bit MinHash integers in slot order.  Must have exactly
            ``CATALOG1_NUM_SLOTS`` (16) entries; pad or truncate as needed.
        """
        if len(minhash_values) != CATALOG1_NUM_SLOTS:
            raise ValueError(
                f"Expected {CATALOG1_NUM_SLOTS} minhash values, "
                f"got {len(minhash_values)}"
            )
        slot_vals = {
            f"slot_{i:02d}": int(v) & 0xFFFFFFFF
            for i, v in enumerate(minhash_values)
        }
        fp, _ = get_or_create(self.session, Catalog1Fingerprint, unique_on=slot_vals)
        pivot = self._upsert_pivot(FunctionCatalog1, function, fp.id)
        self._record_membership(function, StrategyID.catalog1)
        return pivot

    def _bulk_resolve(self, model: type, col_name: str, values: set[Any]) -> dict[Any, int]:
        """Generic bulk resolution of values to IDs for a given model."""
        if not values:
            return {}
        mapping = bulk_get_or_create(
            self.session, model,
            unique_on_col=col_name,
            values=list(values)
        )
        return {val: obj.id for val, obj in mapping.items()}

    def bulk_write_ccbhash(self, results: list[tuple[Function, Any]]) -> None:
        """Bulk write CCBHash results."""
        if not results: return
        
        subs = {
            "name": set(), "cfg": set(), "cg": set(), 
            "op": set(), "args": set(), "locals": set()
        }
        for _, feat in results:
            subs["name"].add(bytes.fromhex(str(feat.name_hash)))
            subs["cfg"].add(bytes.fromhex(str(feat.cfg_hash)))
            subs["cg"].add(bytes.fromhex(str(feat.call_graph_hash)))
            subs["op"].add(bytes.fromhex(str(feat.opcodes_hash)))
            subs["args"].add(bytes.fromhex(str(feat.args_hash)))
            subs["locals"].add(bytes.fromhex(str(feat.locals_hash)))
            
        maps = {
            "name": self.bulk_get_or_create_multi(CCBHashNameSubhash, ["value"], [{"value": v} for v in subs["name"]]),
            "cfg": self.bulk_get_or_create_multi(CCBHashCFGSubhash, ["value"], [{"value": v} for v in subs["cfg"]]),
            "cg": self.bulk_get_or_create_multi(CCBHashCallGraphSubhash, ["value"], [{"value": v} for v in subs["cg"]]),
            "op": self.bulk_get_or_create_multi(CCBHashOpcodesSubhash, ["value"], [{"value": v} for v in subs["op"]]),
            "args": self.bulk_get_or_create_multi(CCBHashVarArgsSubhash, ["value"], [{"value": v} for v in subs["args"]]),
            "locals": self.bulk_get_or_create_multi(CCBHashVarLocalsSubhash, ["value"], [{"value": v} for v in subs["locals"]]),
        }
        
        fp_values = []
        for func, feat in results:
            fp_values.append({
                "name_subhash_id":        maps["name"][(bytes.fromhex(str(feat.name_hash)),)],
                "cfg_subhash_id":         maps["cfg"][(bytes.fromhex(str(feat.cfg_hash)),)],
                "call_graph_subhash_id":  maps["cg"][(bytes.fromhex(str(feat.call_graph_hash)),)],
                "opcodes_subhash_id":     maps["op"][(bytes.fromhex(str(feat.opcodes_hash)),)],
                "var_args_subhash_id":    maps["args"][(bytes.fromhex(str(feat.args_hash)),)],
                "var_locals_subhash_id":  maps["locals"][(bytes.fromhex(str(feat.locals_hash)),)],
                "ninstructions_bucket":   int(feat.ninstructions_hash, 16),
                "indegree_bucket":        int(feat.indegree_hash,    16),
                "outdegree_bucket":       int(feat.outdegree_hash,   16),
                "nvars_bucket":           int(feat.nvars_hash,       16),
                "cc_bucket":              int(feat.cc_hash,          16),
                "nblocks_bucket":         int(feat.nblocks_hash,     16),
                "stackframe_bucket":      int(feat.stackframe_hash,  16),
            })
            
        unique_cols = list(fp_values[0].keys())
        fp_maps = self.bulk_get_or_create_multi(CCBHashFingerprint, unique_cols, fp_values)
        
        pivots = []
        for (func, _), d in zip(results, fp_values):
            fp_key = tuple(d[c] for c in unique_cols)
            pivots.append({"function_id": func.id, "fingerprint_id": fp_maps[fp_key]})
            
        self.bulk_upsert_pivots(FunctionCCBHash, pivots)
        self.bulk_record_membership([r[0] for r in results], StrategyID.ccbhash)

    def bulk_write_catalog1(
        self, function_results: list[tuple[Function, list[int]]]
    ) -> None:
        """Bulk write Catalog1 results."""
        if not function_results: return

        unique_cols = [f"slot_{i:02d}" for i in range(CATALOG1_NUM_SLOTS)]
        fp_values = [
            {f"slot_{i:02d}": int(v) & 0xFFFFFFFF for i, v in enumerate(vals)}
            for _, vals in function_results
        ]
        fp_maps = self.bulk_get_or_create_multi(Catalog1Fingerprint, unique_cols, fp_values)

        pivots = [
            {"function_id": func.id, "fingerprint_id": fp_maps[tuple(d[c] for c in unique_cols)]}
            for (func, _), d in zip(function_results, fp_values)
        ]
        self.bulk_upsert_pivots(FunctionCatalog1, pivots)
        self.bulk_record_membership([r[0] for r in function_results], StrategyID.catalog1)

    def bulk_write_fss(self, results: list[tuple[Function, bytes, bytes, StrategyID]]) -> None:
        """Bulk write Function Similarity Search (FSS) variants."""
        if not results: return
        variants = {
            StrategyID.fss_original: (FSSOriginalFingerprint, FunctionFSSOriginal),
            StrategyID.fss_marcelli: (FSSMarcelliFingerprint, FunctionFSSMarcelli),
            StrategyID.fss_marcelli_weighted: (FSSMarcelliWeightedFingerprint, FunctionFSSMarcelliWeighted),
        }
        
        for strat, (fp_cls, pivot_cls) in variants.items():
            strat_results = [r for r in results if r[3] == strat]
            if not strat_results: continue
            
            fp_values = [{"first": r[1], "second": r[2]} for r in strat_results]
            fp_maps = self.bulk_get_or_create_multi(fp_cls, ["first", "second"], fp_values)
            
            pivots = [{"function_id": r[0].id, "fingerprint_id": fp_maps[(r[1], r[2])]} for r in strat_results]
            self.bulk_upsert_pivots(pivot_cls, pivots)
            self.bulk_record_membership([r[0] for r in strat_results], strat)

    def bulk_write_machoke(self, results: list[tuple[Function, bytes, str]]) -> None:
        """Bulk write Machoke results."""
        if not results: return
        
        fp_values = [{"digest": r[1], "line": r[2]} for r in results]
        fp_maps = self.bulk_get_or_create_multi(MachokeHash, ["digest"], fp_values)
        
        pivots = [{"function_id": r[0].id, "fingerprint_id": fp_maps[(r[1],)]} for r in results]
        self.bulk_upsert_pivots(FunctionMachoke, pivots)
        self.bulk_record_membership([r[0] for r in results], StrategyID.machoke)

    def bulk_write_bytes(self, results: list[tuple[Function, Any]]) -> None:
        """Bulk write Byte signature results with in-memory caching."""
        if not results: return
        
        # 1. Resolve ByteSequences (raw bytes and masks)
        all_bytes_to_hash = set()
        for _, res in results:
            if res.raw_bytes: all_bytes_to_hash.add(res.raw_bytes)
            if res.nibble_sig_mask: all_bytes_to_hash.add(res.nibble_sig_mask)
            if res.bit_sig_mask: all_bytes_to_hash.add(res.bit_sig_mask)
            
        # Filter out sequences already in cache
        missing_bytes = [b for b in all_bytes_to_hash if b not in self._sequence_cache]
        
        if missing_bytes:
            seq_values = [{"bytes_hash": hashlib.sha256(b).digest(), "bytes_sequence": b} for b in missing_bytes]
            seq_maps = self.bulk_get_or_create_multi(ByteSequence, ["bytes_hash"], seq_values)
            # Update cache: seq_maps is {(hash,): id}
            for b in missing_bytes:
                h = hashlib.sha256(b).digest()
                self._sequence_cache[b] = seq_maps[(h,)]
        
        def get_seq_id(b):
            if not b: return None
            return self._sequence_cache.get(b)

        # 2. Resolve ByteFingerprints
        fp_lookup = [] # List of tuples (raw_id, nibble_id, bit_id)
        for _, res in results:
            fp_lookup.append((
                get_seq_id(res.raw_bytes),
                get_seq_id(res.nibble_sig_mask),
                get_seq_id(res.bit_sig_mask)
            ))
            
        # Filter out fingerprints already in cache
        unique_fps = list(set(fp_lookup))
        missing_fps = [fp for fp in unique_fps if fp not in self._fingerprint_cache]
        
        if missing_fps:
            fp_values = [
                {"raw_bytes_id": fp[0], "nibble_mask_id": fp[1], "bit_mask_id": fp[2]}
                for fp in missing_fps
            ]
            fp_maps = self.bulk_get_or_create_multi(
                ByteFingerprint, 
                ["raw_bytes_id", "nibble_mask_id", "bit_mask_id"], 
                fp_values
            )
            # Update cache: fp_maps is {(raw_id, nibble_id, bit_id): id}
            for fp in missing_fps:
                self._fingerprint_cache[fp] = fp_maps[fp]
        
        # 3. Create Pivots (FunctionByteSig)
        pivots = []
        for (func, _), fp_key in zip(results, fp_lookup):
            fp_id = self._fingerprint_cache[fp_key]
            pivots.append({"function_id": func.id, "fingerprint_id": fp_id})
            
        self.bulk_upsert_pivots(FunctionByteSig, pivots)
        self.bulk_record_membership([r[0] for r in results], StrategyID.bytes_signature)


    def bulk_write_scalars(self, results: list[tuple[Function, dict]]) -> None:
        """Bulk write Function Scalars."""
        if not results: return
        _valid = {
            "ninstructions", "nbbs", "indegree", "outdegree",
            "nlocals", "nargs", "stackframe", "size",
            "cc", "ebbs", "edges", "bbsum",
        }
        
        values = []
        for func, d_dict in results:
            filtered = {k: v for k, v in d_dict.items() if k in _valid}
            filtered["function_id"] = func.id
            values.append(filtered)
            
        stmt = pg_insert(FunctionScalars).values(values)
        update_dict = {
            c.name: c
            for c in stmt.excluded
            if c.name in _valid
        }
        stmt = stmt.on_conflict_do_update(
            index_elements=['function_id'],
            set_=update_dict
        )
        self.session.execute(stmt)

    def write_batch(self, batch: list[tuple[Function, Any]]) -> None:
        """
        Write a batch of mixed results efficiently.
        Groups results by type and uses bulk methods.
        """
        if not batch: return

        by_type = {
            "ccbhash": [], "catalog1": [],
            "fss": [], "machoke": [], "bytes": [], "scalars": [],
        }
        for func, res in batch:
            if isinstance(res, CCBHashResult):
                by_type["ccbhash"].append((func, res.ccbhash_features))
            elif isinstance(res, Catalog1Result):
                if getattr(res, "catalog1", None) is not None:
                    raw = hexvalue_to_bytes(res.catalog1) # type: ignore
                    n_slots = len(raw) // 4
                    minhash_values = list(struct.unpack(f">{n_slots}I", raw[:n_slots * 4]))
                    if len(minhash_values) < CATALOG1_NUM_SLOTS:
                        minhash_values += [0] * (CATALOG1_NUM_SLOTS - len(minhash_values))
                    else:
                        minhash_values = minhash_values[:CATALOG1_NUM_SLOTS]
                    by_type["catalog1"].append((func, minhash_values))
            elif isinstance(res, FunctionSimSearchResult):
                if getattr(res, "fss_plain", None):
                    f = FunctionSimSearch.fromhex(res.fss_plain) # type: ignore
                    by_type["fss"].append((func, f.first.to_bytes(8, "big"), f.second.to_bytes(8, "big"), StrategyID.fss_original))
                if getattr(res, "mss_plain", None):
                    f = FunctionSimSearch.fromhex(res.mss_plain) # type: ignore
                    by_type["fss"].append((func, f.first.to_bytes(8, "big"), f.second.to_bytes(8, "big"), StrategyID.fss_marcelli))
                if getattr(res, "mss_weighted", None):
                    f = FunctionSimSearch.fromhex(res.mss_weighted) # type: ignore
                    by_type["fss"].append((func, f.first.to_bytes(8, "big"), f.second.to_bytes(8, "big"), StrategyID.fss_marcelli_weighted))
            elif isinstance(res, MachokeResult):
                if getattr(res, "machoke_digest", None) and getattr(res, "machoke_line", None):
                    by_type["machoke"].append((
                        func, hexvalue_to_bytes(res.machoke_digest), # type: ignore
                        res.machoke_line or ""
                    ))
            elif isinstance(res, BytesResult):
                by_type["bytes"].append((func, res))
            elif isinstance(res, FunctionDetailsResult):
                d = asdict(res)
                if "nblocks" in d: d["nbbs"] = d.pop("nblocks")
                by_type["scalars"].append((func, d))

        if by_type["ccbhash"]: self.bulk_write_ccbhash(by_type["ccbhash"])
        if by_type["catalog1"]: self.bulk_write_catalog1(by_type["catalog1"])
        if by_type["fss"]:     self.bulk_write_fss(by_type["fss"])
        if by_type["machoke"]: self.bulk_write_machoke(by_type["machoke"])
        if by_type["bytes"]:   self.bulk_write_bytes(by_type["bytes"])
        if by_type["scalars"]: self.bulk_write_scalars(by_type["scalars"])

    # ------------------------------------------------------------------
    # Skip log
    # ------------------------------------------------------------------

    def bulk_write_skips(self, skips: list["SkipInfo"], project: str) -> None:
        """Bulk-insert SkipLog rows for a list of SkipInfo objects.

        Idempotent: duplicate (function_id, strategy_id) pairs are silently
        ignored via ON CONFLICT DO NOTHING.
        """
        if not skips:
            return

        from binrankbench.storage.ingest import _STRATEGY_IDS

        # 1. Resolve Functions (bulk get or create)
        func_defs = [
            {"bin_name": s.binary_name, "func_addr": hex(s.func_addr)}
            for s in skips
        ]
        
        functions = self.bulk_get_or_create_functions(project, func_defs)

        # Map to function IDs
        func_map = {
            (b_name, f_addr): func.id
            for (b_name, f_addr), func in functions.items()
        }

        # 2. Resolve SkipReasons (get_or_create as these are few)
        unique_reasons = list({s.reason for s in skips})
        reason_map = self.bulk_get_or_create_multi(
            SkipReason, ["explanation"], [{"explanation": r} for r in unique_reasons]
        )  # returns {(explanation,): id}

        # 3. Build + insert SkipLog rows by expanding tasks to strategies
        rows = []
        for s in skips:
            f_id = func_map.get((s.binary_name, hex(s.func_addr)))
            reason_id = reason_map.get((s.reason,))
            if f_id is None or reason_id is None:
                continue
                
            # Maps e.g. "fss" -> [StrategyID.fss_original, StrategyID.fss_marcelli, StrategyID.fss_marcelli_weighted]
            strats = _STRATEGY_IDS.get(s.task_type, [])
            for strat in strats:
                rows.append({
                    "function_id": f_id,
                    "strategy_id": strat.value,
                    "reason_id":   reason_id,
                })

        if rows:
            stmt = pg_insert(SkipLog).values(rows).on_conflict_do_nothing(
                index_elements=["function_id", "strategy_id"]
            )
            self.session.execute(stmt)
