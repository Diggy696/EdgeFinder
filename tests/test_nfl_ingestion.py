"""Offline regression tests for the Phase A guard and atomic sample replacement."""

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from edgefinder.nfl_ingestion import replace_sample


class ImportSafetyTests(unittest.TestCase):
    def check_fresh_process(self, mode):
        # Install guards before importing the target module. No real provider,
        # credentials, environment files, or databases should be consulted.
        script = r'''
import os
import runpy
import sys
import unittest

mode = TEST_MODE
attempts = []
blocked = {'nflreadpy', 'polars', 'requests', 'pydantic_settings', 'dotenv'}
message = 'Phase A is offline; legacy nflverse acquisition is disabled.'

def reject(event):
    attempts.append(event)
    raise AssertionError('Unexpected import or I/O during offline guard check')

class RejectProvider:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in blocked:
            reject('provider import')

assert not blocked.intersection(sys.modules)
sys.meta_path.insert(0, RejectProvider())

def audit(event, args):
    if event.startswith('socket.') or event == 'sqlite3.connect':
        reject(event)
    if event in {
        'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename',
        'os.truncate', 'os.link', 'os.symlink',
    }:
        reject(event)
    if event == 'open':
        path, file_mode, flags = args
        write_flags = (
            os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        )
        if (
            isinstance(file_mode, str)
            and any(character in file_mode for character in 'wax+')
        ) or flags & write_flags:
            reject('file write')
        if isinstance(path, (str, bytes)):
            name = os.path.basename(os.fsdecode(path)).lower()
            if (
                name in {'.env', '.netrc', '_netrc', 'edgefinder.db'}
                or name.startswith('.env.')
                or not name.endswith(('.py', '.pyc', '.pyd', '.dll'))
            ):
                reject('unexpected/protected file read')

sys.addaudithook(audit)

if mode in {'import', 'discover', 'main'}:
    import edgefinder.nfl_ingestion

if mode == 'discover':
    suite = unittest.defaultTestLoader.discover('tests', top_level_dir='.')
    assert suite.countTestCases() > 0
elif mode in {'main', 'module'}:
    try:
        if mode == 'main':
            edgefinder.nfl_ingestion.main()
        else:
            sys.argv = ['edgefinder.nfl_ingestion']
            runpy.run_module(
                'edgefinder.nfl_ingestion',
                run_name='__main__',
                alter_sys=True,
            )
    except SystemExit as error:
        assert error.code == message, repr(error.code)
    else:
        raise AssertionError('Legacy acquisition did not fail closed')
elif mode != 'import':
    raise AssertionError('Unknown test mode')

assert not blocked.intersection(sys.modules)
assert not attempts, attempts
print('PROVIDER_IMPORTS=0; UNEXPECTED_IO=0')
'''.replace("TEST_MODE", repr(mode))
        result = subprocess.run(
            [sys.executable, "-B", "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "PROVIDER_IMPORTS=0; UNEXPECTED_IO=0\n",
        )
        self.assertEqual(result.stderr, "")

    def test_legacy_module_import_does_not_load_provider_configuration(self):
        self.check_fresh_process("import")

    def test_ordinary_unittest_discovery_is_safe_without_settings_patches(self):
        self.check_fresh_process("discover")

    def test_direct_main_fails_closed_before_provider_imports_or_io(self):
        self.check_fresh_process("main")

    def test_module_execution_fails_closed_before_provider_imports_or_io(self):
        self.check_fresh_process("module")

    def test_python_m_exits_nonzero_with_phase_a_message(self):
        message = "Phase A is offline; legacy nflverse acquisition is disabled."
        for arguments in ((), ("--help",), ("--allow-live",)):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-m",
                        "edgefinder.nfl_ingestion",
                        *arguments,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, message + "\n")


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
