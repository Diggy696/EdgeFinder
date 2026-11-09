"""Offline sample storage helper; legacy acquisition is disabled in Phase A."""

import sqlite3
from contextlib import closing


def main():
    """Reject legacy acquisition unconditionally during Phase A."""
    raise SystemExit("Phase A is offline; legacy nflverse acquisition is disabled.")


def replace_sample(database, selected, rows):
    """Atomically replace the disposable sample, preserving it on failure."""
    table = "nfl_2025_weekly_player_sample"
    # All identifiers come from the fixed mapping above, never from user input.
    numeric = {"season", "week", "targets", "receptions", "receiving_yards", "receiving_tds"}
    definitions = ", ".join(
        f'"{name}" {"INTEGER" if name in numeric else "TEXT"}' for name in selected
    )
    columns = ", ".join(f'"{name}"' for name in selected)
    placeholders = ", ".join("?" for _ in selected)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        # Repeated tests replace only this disposable sample table.
        connection.execute(f'DROP TABLE IF EXISTS "{table}"')
        connection.execute(f'CREATE TABLE "{table}" ({definitions})')
        connection.executemany(
            f'INSERT INTO "{table}" ({columns}) VALUES ({placeholders})', rows
        )
        inserted = connection.total_changes
        count = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        if inserted != len(rows) or count != inserted:
            raise RuntimeError("SQLite sample record count verification failed")
        # The context manager commits on success and rolls back on any failure,
        # including DROP/CREATE because BEGIN precedes both statements.
    with closing(sqlite3.connect(database)) as connection:
        count = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    if inserted != len(rows) or count != inserted:
        raise RuntimeError("SQLite sample record count verification failed")
    return inserted, count


if __name__ == "__main__":
    main()
