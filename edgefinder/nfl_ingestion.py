"""Run the first, deliberately small NFL weekly-stat ingestion test."""

import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import nflreadpy
import polars as pl


def main():
    stats = nflreadpy.load_player_stats(seasons=[2025], summary_level="week")
    schema = stats.schema
    print(f"Dataset: {stats.height} rows, {stats.width} columns", flush=True)
    print(f"Available columns: {', '.join(schema)}", flush=True)
    print(f"Schema: {schema}", flush=True)

    # Resolve source names only after inspecting the returned schema.
    candidates = {
        "player_id": ("player_id", "gsis_id"),
        "player_name": ("player_display_name", "player_name", "player"),
        "season": ("season",),
        "week": ("week",),
        "team": ("team", "recent_team"),
        "targets": ("targets",),
        "receptions": ("receptions",),
        "receiving_yards": ("receiving_yards",),
        "receiving_tds": ("receiving_tds",),
    }
    selected = {}
    for destination, alternatives in candidates.items():
        source = next((name for name in alternatives if name in schema), None)
        if source is not None:
            selected[destination] = source
        else:
            print(f"Unavailable sample field: {destination}", flush=True)

    required = {"season", "week", "team"}
    missing = required - selected.keys()
    if missing or not ({"player_id", "player_name"} & selected.keys()):
        raise ValueError(f"Missing required identity/context fields: {sorted(missing)}; "
                         f"identity fields found: {sorted({'player_id', 'player_name'} & selected.keys())}")
    if not ({"targets", "receptions", "receiving_yards", "receiving_tds"} & selected.keys()):
        raise ValueError("No supported receiving-stat columns were returned")

    print(f"Selected fields (SQLite name -> source): {selected}", flush=True)
    activity = next(
        name for name in ("targets", "receptions", "receiving_yards", "receiving_tds")
        if name in selected
    )
    sample = (
        stats.filter(pl.col(selected[activity]) > 0)
        .select(list(selected.values()))
        .sort(list(selected.values()), nulls_last=True)
        .head(20)
    )
    for record in sample.to_dicts():
        print(ascii(record), flush=True)
    rows = list(sample.iter_rows())
    database = Path(__file__).resolve().parent.parent / "edgefinder.db"
    inserted, count = replace_sample(database, selected, rows)
    print(f"Successfully inserted: {inserted}; verified SQLite count: {count}", flush=True)
    print(f"Database: {database}; table: nfl_2025_weekly_player_sample", flush=True)


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
    try:
        main()
    except (ConnectionError, TimeoutError):
        print(
            "NFL download failed. Check network access to the public nflverse "
            "release on GitHub, then rerun python -m edgefinder.nfl_ingestion. "
            "The SQLite sample was not modified.",
            file=sys.stderr,
        )
        sys.exit(1)
