"""
DuckDB analytics connection.

Opens a DuckDB in-process database that attaches to PostgreSQL via the
``postgres_scanner`` extension and provides columnar-speed reads without
keeping a persistent copy of the data.

Usage (notebook)
----------------
    from binrankbench.storage.analytics import open_analytics

    con = open_analytics("postgresql://user:pw@localhost/binrankbench")

    df = con.execute(\"\"\"
        SELECT f.func_addr, c.digest, c.byte_size
        FROM pg.function f
        JOIN pg.signature       p  ON p.function_id = f.id
                                    AND p.strategy = 'catalog1'
        JOIN pg.catalog1_signature c ON c.signature_id = p.id
        WHERE f.binary_id = 1
    \"\"\").df()

Or use :func:`query` as a convenience wrapper::

    df = query(con, \"SELECT * FROM pg.function LIMIT 10\")
"""
from __future__ import annotations

import duckdb


def open_analytics(pg_dsn: str, *, duckdb_path: str = ":memory:") -> duckdb.DuckDBPyConnection:
    """
    Open a DuckDB connection with the PostgreSQL scanner extension loaded and
    the project's Postgres database attached as ``pg``.

    Parameters
    ----------
    pg_dsn:
        PostgreSQL DSN, e.g. ``"postgresql://user:pw@host/db"``.
        DuckDB's ``postgres_scanner`` accepts the same format as libpq.
    duckdb_path:
        Path to a persistent DuckDB file (for caching), or ``":memory:"``
        (default) for a pure in-process connection.

    Returns
    -------
    duckdb.DuckDBPyConnection
        Ready-to-query connection.  Tables from Postgres are accessed as
        ``pg.<tablename>``.
    """
    con = duckdb.connect(duckdb_path)
    con.execute("INSTALL postgres; LOAD postgres;")
    con.execute(f"ATTACH '{pg_dsn}' AS pg (TYPE postgres, READ_ONLY)")
    return con


def query(con: duckdb.DuckDBPyConnection, sql: str, **params: object):
    """
    Execute ``sql`` and return a pandas DataFrame.

    Parameters
    ----------
    con:
        Connection returned by :func:`open_analytics`.
    sql:
        SQL string (can reference ``pg.<table>`` for Postgres tables).
    **params:
        Named bind parameters (passed via ``con.execute(sql, params)``).

    Example
    -------
        df = query(con, "SELECT * FROM pg.function WHERE binary_id = $bid", bid=1)
    """
    if params:
        return con.execute(sql, params).df()
    return con.execute(sql).df()


def signature_dataframe(
    con: duckdb.DuckDBPyConnection,
    strategy: str,
    *,
    binary_id: int | None = None,
    project_name: str | None = None,
) -> object:
    """
    Convenience: return all rows for a given signature strategy as a DataFrame.

    Joins ``function → signature → <strategy>_signature`` automatically.

    Parameters
    ----------
    strategy:
        Strategy name, e.g. ``"catalog1"``, ``"ccbhash"``, ``"machoke"``.
    binary_id:
        Filter to a specific binary.
    project_name:
        Filter to all binaries belonging to a project.
    """
    table = f"{strategy}_signature"
    where_clauses = [f"p.strategy = '{strategy}'"]
    if binary_id is not None:
        where_clauses.append(f"f.binary_id = {int(binary_id)}")
    if project_name is not None:
        where_clauses.append(f"proj.name = '{project_name}'")

    project_join = (
        "JOIN pg.binary b ON b.id = f.binary_id "
        "JOIN pg.project proj ON proj.id = b.project_id "
        if project_name else ""
    )
    where = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
        SELECT f.func_addr, f.func_name, f.binary_id, s.*
        FROM pg.function f
        {project_join}
        JOIN pg.signature p ON p.function_id = f.id
        JOIN pg.{table} s   ON s.signature_id = p.id
        {where}
    """
    return con.execute(sql).df()
