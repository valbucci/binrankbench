"""
Strategy signature files package.

Each module defines a fingerprint table (unique content entity) and a
function association / pivot table.  There is no polymorphic base class.

Modules
-------
ccbhash  — CCBHashFingerprint, FunctionCCBHash
fss      — FSSOriginalFingerprint, FSSMarcelliFingerprint,
            FunctionFSSOriginal, FunctionFSSMarcelli
machoke  — FunctionMachoke   (MachokeHash is the fingerprint)
bytes    — ByteFingerprint, FunctionByteSig
catalog1 — Catalog1MinhashValue, Catalog1Fingerprint, FunctionCatalog1
"""
