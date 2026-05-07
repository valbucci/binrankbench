"""Shared utility helpers for evaluation stages."""
import math
import base64
import pandas as pd
from typing import Optional
from sqlalchemy import select
from sqlalchemy.orm import joinedload, Session
from typing import Iterator
from tqdm import tqdm
from dataclasses import dataclass

import sys

from .context import PROJECT_ROOT
sys.path.insert(0, str(PROJECT_ROOT))

from binrankbench.storage.models.core import Function
from binrankbench.storage.models.signatures.bytes import ByteFingerprint, FunctionByteSig
from binrankbench.storage.models.signatures.catalog1 import FunctionCatalog1
from binrankbench.storage.models.signatures.ccbhash import FunctionCCBHash
from binrankbench.storage.models.signatures.fss import (
    FunctionFSSMarcelli,
    FunctionFSSMarcelliWeighted,
    FunctionFSSOriginal,
)
from binrankbench.storage.models.signatures.machoke import FunctionMachoke
from evaluation.utils.constants import CAT1_NUM_PERMS


def _chunked(lst: list, size: int) -> Iterator[list]:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def _chunked_tqdm(lst: list, size: int, desc: str) -> Iterator[list]:
    for i in tqdm(range(0, len(lst), size), desc=desc):
        yield lst[i : i + size]


def _missing(val) -> bool:
    return val is None or (isinstance(val, float) and math.isnan(val))


def _encode_for_csv(obj):
    # Convert bytes -> base64 string, tuples -> lists, keep ints/strs
    if isinstance(obj, bytes):
        return {"__type__": "bytes", "b64": base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, tuple):
        return {"__type__": "tuple", "items": [_encode_for_csv(x) for x in obj]}
    if isinstance(obj, list):
        return {"__type__": "list", "items": [_encode_for_csv(x) for x in obj]}
    # primitive
    return obj

def _decode_from_csv(obj):
    if isinstance(obj, dict) and "__type__" in obj:
        t = obj["__type__"]
        if t == "bytes":
            return base64.b64decode(obj["b64"])
        if t == "tuple":
            return tuple(_decode_from_csv(x) for x in obj["items"])
        if t == "list":
            return [_decode_from_csv(x) for x in obj["items"]]
    return obj




@dataclass
class FunctionFingerprints:
    function_id: int
    machoke: Optional[bytes] = None
    ccb:     Optional[str] = None
    fsso:    Optional[tuple[bytes, bytes]] = None
    fssm:    Optional[tuple[bytes, bytes]] = None
    fssmw:   Optional[tuple[bytes, bytes]] = None
    cat1:    Optional[tuple[int, ...]] = None
    bysig:   Optional[tuple[bytes, bytes, int]] = None  # (raw_bytes_seq, nibble_mask_seq, cc)
    nbbs:    Optional[int] = None


def fetch_fingerprints(session: Session, 
                       func_ids: list[int]) -> list[FunctionFingerprints]:
    stmt = (
        select(Function)
        .where(Function.id.in_(func_ids))
        .options(
            joinedload(Function.machoke).joinedload(FunctionMachoke.fingerprint),
            joinedload(Function.ccbhash).joinedload(FunctionCCBHash.fingerprint),
            joinedload(Function.fss_original).joinedload(FunctionFSSOriginal.fingerprint),
            joinedload(Function.fss_marcelli).joinedload(FunctionFSSMarcelli.fingerprint),
            joinedload(Function.fss_marcelli_weighted).joinedload(FunctionFSSMarcelliWeighted.fingerprint),
            joinedload(Function.catalog1).joinedload(FunctionCatalog1.fingerprint),
            joinedload(Function.byte_sig).joinedload(FunctionByteSig.fingerprint).joinedload(ByteFingerprint.raw_bytes_seq),
            joinedload(Function.byte_sig).joinedload(FunctionByteSig.fingerprint).joinedload(ByteFingerprint.nibble_mask_seq),
            joinedload(Function.scalars),
        )
    )
    
    signatures_list = []
    function_results = session.execute(stmt).scalars().all()
    for f in function_results:
        signatures = FunctionFingerprints(function_id=f.id)
        if f.machoke and f.machoke.fingerprint:
            signatures.machoke = f.machoke.fingerprint.digest

        if f.ccbhash and f.ccbhash.fingerprint:
            signatures.ccb = f.ccbhash.fingerprint.digest

        if f.fss_original and f.fss_original.fingerprint:
            signatures.fsso = (f.fss_original.fingerprint.first, f.fss_original.fingerprint.second)

        if f.fss_marcelli and f.fss_marcelli.fingerprint:
            signatures.fssm = (f.fss_marcelli.fingerprint.first, f.fss_marcelli.fingerprint.second)

        if f.fss_marcelli_weighted and f.fss_marcelli_weighted.fingerprint:
            signatures.fssmw = (f.fss_marcelli_weighted.fingerprint.first, f.fss_marcelli_weighted.fingerprint.second)

        if f.catalog1 and f.catalog1.fingerprint:
            fp = f.catalog1.fingerprint
            signatures.cat1 = tuple(getattr(fp, f"slot_{i:02d}") for i in range(CAT1_NUM_PERMS))

        if f.byte_sig and f.byte_sig.fingerprint:
            raw = f.byte_sig.fingerprint.raw_bytes_seq.bytes_sequence if f.byte_sig.fingerprint.raw_bytes_seq else None
            mask = f.byte_sig.fingerprint.nibble_mask_seq.bytes_sequence if f.byte_sig.fingerprint.nibble_mask_seq else None
            cc = f.scalars.cc if f.scalars and f.scalars.cc is not None else 0
            if raw and mask:
                signatures.bysig = (raw, mask, cc)

        if f.scalars and f.scalars.nbbs is not None:
            signatures.nbbs = int(f.scalars.nbbs)

        signatures_list.append(signatures)
    return signatures_list


def fetch_fingerprints_in_chunks(session: Session, ids: list[int], 
                                 chunk_size=2000, 
                                 desc: str = "Fetching fingerprints"
                                 ) -> list[FunctionFingerprints]:
    fingerprints_list = []
    for chunk in tqdm(list(_chunked(ids, chunk_size)), desc=desc):
        signatures_chunk = fetch_fingerprints(session, chunk)
        fingerprints_list.extend(signatures_chunk)
    return fingerprints_list
