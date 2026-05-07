"""
binrankbench.storage.models public surface.

All model classes are importable directly from this package::

    from binrankbench.storage.models import (
        Project, Binary, Function, FunctionName, FunctionScalars,
        StrategyMembership,
        CCBHashFingerprint, FunctionCCBHash,
        Catalog1Fingerprint, FunctionCatalog1,
        ...
    )
"""
# Trigger ORM mapper registration by importing all modules in dependency order.

from .base import Base
from .signatures.strategy_type import StrategyID, StrategyType

# Core entities (no outbound FKs to signature tables)
from .core import (
    Binary,
    Function,
    FunctionName,
    FunctionScalars,
    Project,
    SkipLog,
    SkipReason,
    StrategyMembership,
)
from .dataset import BinaryDatasetTag, Dataset

# Dedup tables
from .dedup import (
    ByteDedupBase,
    ByteSequence,
    get_or_create,
    bulk_get_or_create,
)

# CCBHash (includes its own private dedup tables)
from .signatures.ccbhash import (
    CCBHashNameSubhash,
    CCBHashCFGSubhash,
    CCBHashCallGraphSubhash,
    CCBHashOpcodesSubhash,
    CCBHashVarArgsSubhash,
    CCBHashVarLocalsSubhash,
    CCBHashFingerprint,
    FunctionCCBHash,
)

# FSS
from .signatures.fss import (
    FSSOriginalFingerprint,
    FSSMarcelliFingerprint,
    FSSMarcelliWeightedFingerprint,
    FunctionFSSOriginal,
    FunctionFSSMarcelli,
    FunctionFSSMarcelliWeighted,
)

# Machoke
from .signatures.machoke import MachokeHash, FunctionMachoke

# Byte signature
from .signatures.bytes import ByteFingerprint, FunctionByteSig

# Catalog1
from .signatures.catalog1 import (
    Catalog1Fingerprint,
    FunctionCatalog1,
    CATALOG1_NUM_SLOTS,
)

__all__ = [
    # Base
    "Base",
    # Core entities
    "Project", "Binary", "Function", "FunctionName", "FunctionScalars",
    "StrategyMembership",
    # Skip log
    "SkipReason", "SkipLog",
    # Dataset tagging
    "Dataset", "BinaryDatasetTag",
    # Strategy lookup
    "StrategyID", "StrategyType",
    # Dedup — shared
    "ByteDedupBase", "ByteSequence", "get_or_create", "bulk_get_or_create",
    # Dedup — CCBHash (private but re-exported for tests)
    "CCBHashNameSubhash", "CCBHashCFGSubhash", "CCBHashCallGraphSubhash",
    "CCBHashOpcodesSubhash", "CCBHashVarArgsSubhash", "CCBHashVarLocalsSubhash",
    # Fingerprints + pivots
    "CCBHashFingerprint", "FunctionCCBHash",
    "FSSOriginalFingerprint", "FunctionFSSOriginal",
    "FSSMarcelliFingerprint", "FunctionFSSMarcelli",
    "FSSMarcelliWeightedFingerprint", "FunctionFSSMarcelliWeighted",
    "MachokeHash", "FunctionMachoke",
    "ByteFingerprint", "FunctionByteSig",
    "Catalog1Fingerprint", "FunctionCatalog1",
    "CATALOG1_NUM_SLOTS",
]
