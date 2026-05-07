"""DB helpers and shared constants for fixture extraction scripts."""
import bisect
import math
from sqlalchemy import func, select

from binrankbench.storage.models.core import Function, FunctionScalars, StrategyMembership
from binrankbench.storage.models.dataset import BinaryDatasetTag, Dataset
from evaluation.utils.constants import BUCKET_LABELS, N_STRATEGIES, DATASET_NAME, NBBS_MIN


def fetch_dataset1_binary_ids(session) -> list[int]:
    """Return all binary IDs tagged as Dataset-1. One row per binary."""
    stmt = (
        select(BinaryDatasetTag.binary_id)
        .join(BinaryDatasetTag.dataset)
        .where(Dataset.name == DATASET_NAME)
    )
    return [row[0] for row in session.execute(stmt).all()]


def compute_boundaries_from_nbbs(nbbs_list: list[int]) -> list[float]:
    """Return 12 boundary values (deciles + P95 split, capped at P99.5).

    Boundaries: P0, P10, P20, ..., P90, P95, P99.5 (12 values, 11 buckets).
    Functions above P99.5 are excluded as extreme outliers (~0.5% of the pool).
    Ties on integer nbbs are resolved by bumping each duplicate boundary up by 1,
    ensuring pd.cut always receives increasing edges.
    """
    sorted_nbbs = sorted(nbbs_list)
    n = len(sorted_nbbs)
    raw = [
        float(sorted_nbbs[0]),
        float(sorted_nbbs[math.ceil(n * 0.10) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.20) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.30) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.40) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.50) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.60) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.70) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.80) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.90) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.95) - 1]),
        float(sorted_nbbs[math.ceil(n * 0.995) - 1]),
    ]
    result = [raw[0]]
    for b in raw[1:]:
        # Bump by 1 if the next boundary is equal to the previous
        result.append(max(b, result[-1] + 1.0))
    return result


def compute_boundaries_from_ids(session, binary_ids: list[int]) -> list[float]:
    """Return 12 boundary values (deciles + P95 split, capped at P99.5).

    Boundaries: P0, P10, P20, ..., P90, P95, P99.5 (12 values, 11 buckets).
    Functions above P99.5 are excluded as extreme outliers (~0.5% of the pool).
    Ties on integer nbbs are resolved by bumping each duplicate boundary up by 1,
    ensuring pd.cut always receives increasing edges.
    """
    col = FunctionScalars.nbbs
    stmt = (
        select(
            func.min(col).label("p0"),
            func.percentile_cont(0.10).within_group(col.asc()).label("p10"),
            func.percentile_cont(0.20).within_group(col.asc()).label("p20"),
            func.percentile_cont(0.30).within_group(col.asc()).label("p30"),
            func.percentile_cont(0.40).within_group(col.asc()).label("p40"),
            func.percentile_cont(0.50).within_group(col.asc()).label("p50"),
            func.percentile_cont(0.60).within_group(col.asc()).label("p60"),
            func.percentile_cont(0.70).within_group(col.asc()).label("p70"),
            func.percentile_cont(0.80).within_group(col.asc()).label("p80"),
            func.percentile_cont(0.90).within_group(col.asc()).label("p90"),
            func.percentile_cont(0.95).within_group(col.asc()).label("p95"),
            func.percentile_cont(0.995).within_group(col.asc()).label("p99_5"),
        )
        .select_from(Function)
        .join(Function.scalars)
        .where(Function.binary_id.in_(binary_ids))
        .where(col.isnot(None))
        .where(col >= NBBS_MIN)
    )
    raw = [float(v) for v in session.execute(stmt).one()]
    result = [raw[0]]
    for b in raw[1:]:
        result.append(max(b, result[-1] + 1.0))
    return result


def _tier1_subquery():
    """SQLAlchemy subquery: function IDs that have all N_STRATEGIES strategy records."""
    return (
        select(StrategyMembership.function_id)
        .group_by(StrategyMembership.function_id)
        .having(func.count() == N_STRATEGIES)
        .subquery()
    )


def _assign_bucket(nbbs: int, boundaries: list[float]) -> str | None:
    """Return the BUCKET_LABELS entry for nbbs, or None if above the P99.5 cap."""
    idx = bisect.bisect_left(boundaries[1:], nbbs)
    return BUCKET_LABELS[idx] if idx < len(BUCKET_LABELS) else None
