"""
Matplotlib compatibility patches. Call apply_patches() before importing pyplot.

Patches:
  - matplotlib 3.10.x / Python 3.14: Path.__deepcopy__ calls deepcopy(super(), memo)
    which recurses infinitely. Replaced with a version that copies Path's own fields
    directly and uses copy.copy (not deepcopy) for any remaining attributes.
"""
import copy
import matplotlib.path as _mpath


def _path_deepcopy_fixed(self: _mpath.Path, memo: dict) -> _mpath.Path:
    cls = type(self)
    result = cls.__new__(cls)
    memo[id(self)] = result
    result._vertices = self._vertices.copy()  # type: ignore[attr-defined]
    result._codes    = self._codes.copy() if self._codes is not None else None  # type: ignore[attr-defined]
    result._readonly = False  # type: ignore[attr-defined]
    for k, v in self.__dict__.items():
        if k not in ("_vertices", "_codes", "_readonly"):
            try:
                setattr(result, k, copy.copy(v))
            except Exception:
                setattr(result, k, v)
    return result


_patched = False


def apply_patches() -> None:
    global _patched
    if _patched:
        return
    _mpath.Path.__deepcopy__ = _path_deepcopy_fixed  # type: ignore[assignment]
    _patched = True
