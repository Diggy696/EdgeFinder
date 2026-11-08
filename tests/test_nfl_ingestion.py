"""Offline regression test for atomic sample replacement."""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from edgefinder.nfl_ingestion import replace_sample


class SampleReplacementTests(unittest.TestCase):
    def test_failed_insert_preserves_previous_table(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "sample.db"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute(
                    "CREATE TABLE nfl_2025_weekly_player_sample (prior_value TEXT)"
                )
                connection.execute(
                    "INSERT INTO nfl_2025_weekly_player_sample VALUES (?)", ("original",)
                )
            # The first row inserts successfully; the second cannot bind to SQLite.
            with self.assertRaises(sqlite3.ProgrammingError):
                replace_sample(
                    database, {"player_id": "player_id"}, [("new",), (object(),)]
                )
            with closing(sqlite3.connect(database)) as connection:
                cursor = connection.execute("SELECT * FROM nfl_2025_weekly_player_sample")
                self.assertEqual([column[0] for column in cursor.description], ["prior_value"])
                self.assertEqual(cursor.fetchall(), [("original",)])


if __name__ == "__main__":
    unittest.main()
