"""Entirely synthetic fixtures; every connection is sqlite3 ':memory:'."""

import json
import sqlite3
import unittest

from edgefinder.storage.database import (
    _QUARANTINE_SQL, add_snapshot, canonical, connect, create_run, evidence_hash, initialize,
    seal_run, transaction,
)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')
        self.addCleanup(self.db.close)
        initialize(self.db)
        with transaction(self.db):
            for kind, name in [('PLAYER', 'player'), ('TEAM', 'team'), ('GAME', 'game')]:
                self.db.execute(
                    'INSERT INTO identifier_namespace(provider,kind,name) VALUES(?,?,?)',
                    ('synthetic', kind, name))
            for kind, label in [('PLAYER', 'Player Alpha'), ('TEAM', 'Home'),
                                ('TEAM', 'Away'), ('GAME', 'Game Alpha'),
                                ('PLAYER', 'Player Corrected')]:
                self.db.execute('INSERT INTO entity(kind,label) VALUES(?,?)', (kind, label))
        self.identities = [
            {'namespace_id': 1, 'identifier': 'p1'},
            {'namespace_id': 2, 'identifier': 'home'},
            {'namespace_id': 2, 'identifier': 'away'},
            {'namespace_id': 3, 'identifier': 'g1'},
        ]
        self.schedule = [{
            'namespace_id': 3, 'identifier': 'g1',
            'home_namespace_id': 2, 'home_identifier': 'home',
            'away_namespace_id': 2, 'away_identifier': 'away',
            'kickoff_local': '2030-10-01 13:00',
        }]
        self.stats = [{
            'namespace_id': 1, 'identifier': 'p1',
            'game_namespace_id': 3, 'game_identifier': 'g1',
            'team_namespace_id': 2, 'team_identifier': 'home',
            'payload': {'synthetic_yards': 0},
        }]

    def snapshot(self, role, rows, **kwargs):
        return add_snapshot(self.db, provider='synthetic', role=role,
                            loader_scope='synthetic-season', rows=rows, **kwargs)

    def fixture(self, identities=None, schedule=None, stats=None, **times):
        ids = [self.snapshot('IDENTITY', self.identities if identities is None else identities, **times),
               self.snapshot('SCHEDULE', self.schedule if schedule is None else schedule, **times),
               self.snapshot('STATS', self.stats if stats is None else stats, **times)]
        run = create_run(self.db, identity=ids[0], schedule=ids[1], stats=ids[2])
        return run, ids

    def records(self, snapshot):
        return [row[0] for row in self.db.execute(
            'SELECT id FROM source_record WHERE snapshot_id=? ORDER BY ordinal', (snapshot,))]

    def bind(self, run, record, entity):
        return self.db.execute(
            'INSERT INTO identifier_binding(run_id,namespace_id,identifier,entity_id,source_record_id) '
            'SELECT ?,namespace_id,identifier,?,id FROM source_record WHERE id=?',
            (run, entity, record)).lastrowid

    def bindings(self, run, identity_snapshot, player_entity=1):
        return [self.bind(run, record, entity) for record, entity in
                zip(self.records(identity_snapshot), [player_entity, 2, 3, 4])]

    def game(self, run, record, bindings):
        _, home, away, game = bindings
        return self.db.execute(
            'INSERT INTO game_observation(run_id,source_record_id,game_binding,home_binding,away_binding) '
            'VALUES(?,?,?,?,?)', (run, record, game, home, away)).lastrowid

    def player_game(self, run, record, bindings, game):
        return self.db.execute(
            'INSERT INTO player_game_observation(run_id,source_record_id,player_binding,team_binding,game_observation_id) '
            'VALUES(?,?,?,?,?)', (run, record, bindings[0], bindings[1], game)).lastrowid

    def promote(self, run, snapshots, player_entity=1):
        bindings = self.bindings(run, snapshots[0], player_entity)
        game = self.game(run, self.records(snapshots[1])[0], bindings)
        player = self.player_game(run, self.records(snapshots[2])[0], bindings, game)
        return bindings, game, player

    def select(self, run, mode='RETROSPECTIVE', as_of=None):
        return self.db.execute(
            'INSERT INTO research_selection(run_id,mode,as_of) VALUES(?,?,?)',
            (run, mode, as_of)).lastrowid

    def test_successful_player_game_team_joins(self):
        run, snapshots = self.fixture()
        bindings, game, player = self.promote(run, snapshots)
        seal_run(self.db, run)
        self.select(run)
        row = self.db.execute(
            'SELECT b.entity_id,t.entity_id,g.entity_id FROM player_game_observation p '
            'JOIN identifier_binding b ON b.id=p.player_binding '
            'JOIN identifier_binding t ON t.id=p.team_binding '
            'JOIN game_observation o ON o.id=p.game_observation_id '
            'JOIN identifier_binding g ON g.id=o.game_binding WHERE p.id=?', (player,)).fetchone()
        self.assertEqual(tuple(row), (1, 2, 4))

    def test_cross_snapshot_and_cross_run_mismatches(self):
        run, snapshots = self.fixture()
        bindings, game, _ = self.promote(run, snapshots)
        other_stats = self.snapshot('STATS', [dict(self.stats[0], payload={'synthetic_yards': 1})])
        other_identity = self.snapshot('IDENTITY', [dict(self.identities[0], payload='changed'), *self.identities[1:]])
        other_schedule = self.snapshot('SCHEDULE', [dict(self.schedule[0], payload='changed')])
        other_run = create_run(self.db, identity=snapshots[0], schedule=snapshots[1], stats=snapshots[2])
        with self.assertRaises(sqlite3.IntegrityError):
            self.bind(run, self.records(other_identity)[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.game(run, self.records(other_schedule)[0], bindings)
        with self.assertRaises(sqlite3.IntegrityError):
            self.player_game(run, self.records(other_stats)[0], bindings, game)
        with self.assertRaises(sqlite3.IntegrityError):
            self.game(other_run, self.records(snapshots[1])[0], bindings)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('INSERT INTO quarantine VALUES(?,?,?)', (run, self.records(other_stats)[0], 'foreign'))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO finding(run_id,source_record_id,severity,code,message) VALUES(?,?,'WARNING','x','x')",
                            (run, self.records(other_stats)[0]))

    def test_null_player_is_preserved_and_quarantined(self):
        run, snapshots = self.fixture(stats=[dict(self.stats[0], identifier=None)])
        record = self.records(snapshots[2])[0]
        self.assertIsNone(self.db.execute('SELECT identifier FROM source_record WHERE id=?', (record,)).fetchone()[0])
        self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine WHERE run_id=? AND source_record_id=?',
                                         (run, record)).fetchone()[0], 1)
        bindings = self.bindings(run, snapshots[0])
        game = self.game(run, self.records(snapshots[1])[0], bindings)
        with self.assertRaises(sqlite3.IntegrityError):
            self.player_game(run, record, bindings, game)
        seal_run(self.db, run)

    def test_ambiguous_alias_blocks_promotion(self):
        rows = [*self.identities, dict(self.identities[0], payload={'candidate': 'other'})]
        run, snapshots = self.fixture(identities=rows)
        # Even removing the automatic quarantine cannot bypass the alias guard.
        self.db.execute('DELETE FROM quarantine WHERE run_id=?', (run,))
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'ambiguous'):
            self.bind(run, self.records(snapshots[0])[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            seal_run(self.db, run)

    def test_duplicate_source_rows_preserved_and_quarantined(self):
        run, snapshots = self.fixture(stats=[self.stats[0], self.stats[0]])
        records = self.records(snapshots[2])
        self.assertEqual(len(records), 2)
        values = self.db.execute('SELECT normalized FROM source_record WHERE snapshot_id=?', (snapshots[2],)).fetchall()
        self.assertEqual(values[0][0], values[1][0])
        self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine WHERE run_id=?', (run,)).fetchone()[0], 2)
        bindings = self.bindings(run, snapshots[0])
        game = self.game(run, self.records(snapshots[1])[0], bindings)
        self.db.execute('DELETE FROM quarantine WHERE run_id=?', (run,))
        for record in records:
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'duplicate'):
                self.player_game(run, record, bindings, game)
        for record in records:
            self.db.execute('INSERT INTO quarantine VALUES(?,?,?)', (run, record, 'duplicate'))
        seal_run(self.db, run)

    def test_duplicate_identity_and_schedule_rows_cannot_promote(self):
        run, snapshots = self.fixture(identities=[*self.identities, self.identities[0]],
                                      schedule=[self.schedule[0], self.schedule[0]])
        self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine WHERE run_id=?', (run,)).fetchone()[0], 5)
        self.db.execute('DELETE FROM quarantine WHERE run_id=?', (run,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.bind(run, self.records(snapshots[0])[0], 1)
        bindings = [None] + [self.bind(run, record, entity) for record, entity in
                            zip(self.records(snapshots[0])[1:4], [2, 3, 4])]
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'duplicate'):
            self.game(run, self.records(snapshots[1])[0], bindings)

    def test_identical_content_reuses_snapshot_including_reordered_rows(self):
        first = self.snapshot('IDENTITY', self.identities)
        second = self.snapshot('IDENTITY', list(reversed(self.identities)))
        self.assertEqual(first, second)
        self.assertEqual(len(self.records(first)), 4)
        row = self.db.execute('SELECT retrieved_at,original_file_sha256 FROM source_snapshot WHERE id=?', (first,)).fetchone()
        self.assertEqual(tuple(row), (None, None))

    def test_snapshot_reuse_rejects_new_or_changed_temporal_claims(self):
        first = self.snapshot('IDENTITY', self.identities)
        with self.assertRaisesRegex(ValueError, 'different temporal metadata'):
            self.snapshot('IDENTITY', self.identities, retrieved_at='2030-11-01T00:00:00Z')
        self.assertEqual(self.db.execute('SELECT count(*) FROM source_snapshot').fetchone()[0], 1)
        self.assertIsNone(self.db.execute('SELECT retrieved_at FROM source_snapshot WHERE id=?', (first,)).fetchone()[0])

        times = {'retrieved_at': '2030-10-03T00:00:00Z',
                 'publication_at': '2030-10-02T00:00:00Z',
                 'publication_evidence': 'synthetic original log'}
        published = self.snapshot('STATS', self.stats, **times)
        original = tuple(self.db.execute('SELECT * FROM source_snapshot WHERE id=?', (published,)).fetchone())
        self.assertEqual(self.snapshot('STATS', self.stats, **times), published)
        for changes in ({'publication_evidence': 'synthetic different log'},
                        {'publication_at': '2030-10-01T00:00:00Z'},
                        {'retrieved_at': '2030-10-04T00:00:00Z'}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'different temporal metadata'):
                self.snapshot('STATS', self.stats, **(times | changes))
        with self.assertRaises(ValueError):
            self.snapshot('STATS', self.stats)
        self.assertEqual(tuple(self.db.execute('SELECT * FROM source_snapshot WHERE id=?', (published,)).fetchone()), original)
        self.assertEqual(len(self.records(published)), 1)

    def test_snapshot_reuse_validates_metadata_before_existing_content_lookup(self):
        self.snapshot('STATS', self.stats)
        for metadata in (
            {'retrieved_at': 'not a timestamp'},
            {'retrieved_at': '2030-02-30T00:00:00Z'},
            {'retrieved_at': '2030-10-01T00:00:00-04:00'},
            {'publication_at': '2030-10-01T00:00:00Z'},
            {'publication_at': 'invalid', 'publication_evidence': 'log'},
            {'publication_at': '2030-10-01T00:00:00Z', 'publication_evidence': ''},
            {'publication_at': '2030-10-02T00:00:00Z', 'publication_evidence': 'log',
             'retrieved_at': '2030-10-01T00:00:00Z'},
        ):
            with self.subTest(metadata=metadata), self.assertRaises(sqlite3.IntegrityError):
                self.snapshot('STATS', self.stats, **metadata)
        self.assertEqual(self.db.execute('SELECT count(*) FROM source_snapshot').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM source_record').fetchone()[0], 1)
        self.assertFalse(self.db.in_transaction)

    def test_changed_content_and_duplicate_multiplicity_create_snapshots(self):
        first = self.snapshot('IDENTITY', self.identities)
        second = self.snapshot('IDENTITY', [dict(self.identities[0], payload=0), *self.identities[1:]])
        third = self.snapshot('IDENTITY', [*self.identities, self.identities[0]])
        self.assertEqual(len({first, second, third}), 3)

    def test_corrected_interpretation_is_a_new_run(self):
        run, snapshots = self.fixture()
        old_bindings, _, _ = self.promote(run, snapshots)
        seal_run(self.db, run)
        selection = self.select(run)
        new_run = create_run(self.db, identity=snapshots[0], schedule=snapshots[1], stats=snapshots[2])
        new_bindings, _, _ = self.promote(new_run, snapshots, player_entity=5)
        seal_run(self.db, new_run)
        self.select(new_run)
        self.assertNotEqual(run, new_run)
        self.assertEqual(self.db.execute('SELECT entity_id FROM identifier_binding WHERE id=?', (old_bindings[0],)).fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT entity_id FROM identifier_binding WHERE id=?', (new_bindings[0],)).fetchone()[0], 5)
        self.assertEqual(self.db.execute('SELECT run_id FROM research_selection WHERE id=?', (selection,)).fetchone()[0], run)

    def test_referenced_binding_cannot_be_relocated_to_another_run(self):
        run, snapshots = self.fixture()
        bindings, _, player = self.promote(run, snapshots)
        other_run = create_run(self.db, identity=snapshots[0], schedule=snapshots[1], stats=snapshots[2])
        original = tuple(self.db.execute('SELECT * FROM identifier_binding WHERE id=?', (bindings[0],)).fetchone())
        # Previously this moved the same PK into an open run while a player-game
        # observation in the original run still referenced it; FK checks passed.
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                'INSERT OR REPLACE INTO identifier_binding(id,run_id,namespace_id,identifier,entity_id,source_record_id) '
                'SELECT id,?,namespace_id,identifier,entity_id,source_record_id FROM identifier_binding WHERE id=?',
                (other_run, bindings[0]))
        self.assertEqual(tuple(self.db.execute('SELECT * FROM identifier_binding WHERE id=?', (bindings[0],)).fetchone()), original)
        seal_run(self.db, run)
        self.select(run)
        other_bindings = self.bindings(other_run, snapshots[0])
        # An unreferenced binding in the other open run may still be corrected.
        self.db.execute(
            'INSERT OR REPLACE INTO identifier_binding(id,run_id,namespace_id,identifier,entity_id,source_record_id) '
            'SELECT id,run_id,namespace_id,identifier,5,source_record_id FROM identifier_binding WHERE id=?',
            (other_bindings[0],))
        result = self.db.execute(
            'SELECT b.run_id,b.entity_id FROM player_game_observation p '
            'JOIN identifier_binding b ON b.id=p.player_binding WHERE p.id=?', (player,)).fetchone()
        self.assertEqual(tuple(result), (run, 1))
        self.assertEqual(self.db.execute('SELECT entity_id FROM identifier_binding WHERE id=?', (other_bindings[0],)).fetchone()[0], 5)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_referenced_home_and_away_bindings_cannot_be_corrupted_in_same_run(self):
        run, snapshots = self.fixture()
        bindings = self.bindings(run, snapshots[0])
        game = self.game(run, self.records(snapshots[1])[0], bindings)
        # This originally made both participants the same entity while retaining
        # valid foreign keys, because only the insert-time game check ran.
        for binding, replacement_entity in ((bindings[1], 3), (bindings[2], 2)):
            with self.subTest(binding=binding), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(
                    'INSERT OR REPLACE INTO identifier_binding(id,run_id,namespace_id,identifier,entity_id,source_record_id) '
                    'SELECT id,run_id,namespace_id,identifier,?,source_record_id FROM identifier_binding WHERE id=?',
                    (replacement_entity, binding))
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute('DELETE FROM identifier_binding WHERE id=?', (binding,))
        row = self.db.execute(
            'SELECT h.entity_id,a.entity_id FROM game_observation g '
            'JOIN identifier_binding h ON h.id=g.home_binding '
            'JOIN identifier_binding a ON a.id=g.away_binding WHERE g.id=?', (game,)).fetchone()
        self.assertEqual(tuple(row), (2, 3))
        self.player_game(run, self.records(snapshots[2])[0], bindings, game)
        seal_run(self.db, run)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_referenced_game_observation_cannot_be_deleted_or_relocated(self):
        run, snapshots = self.fixture()
        _, game, player = self.promote(run, snapshots)
        other_run = create_run(self.db, identity=snapshots[0], schedule=snapshots[1], stats=snapshots[2])
        other = self.bindings(other_run, snapshots[0])
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('DELETE FROM game_observation WHERE id=?', (game,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                'INSERT OR REPLACE INTO game_observation(id,run_id,source_record_id,game_binding,home_binding,away_binding) '
                'VALUES(?,?,?,?,?,?)', (game, other_run, self.records(snapshots[1])[0], other[3], other[1], other[2]))
        self.assertEqual(self.db.execute('SELECT run_id FROM game_observation WHERE id=?', (game,)).fetchone()[0], run)
        self.assertEqual(self.db.execute('SELECT game_observation_id FROM player_game_observation WHERE id=?', (player,)).fetchone()[0], game)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_composite_run_ownership_and_immediate_restrict_constraints(self):
        expected = {
            'game_observation': {'game_binding', 'home_binding', 'away_binding'},
            'player_game_observation': {'player_binding', 'team_binding', 'game_observation_id'},
        }
        for table, columns in expected.items():
            foreign_keys = {}
            for row in self.db.execute(f'PRAGMA foreign_key_list({table})'):
                foreign_keys.setdefault(row['id'], []).append(row)
            actual = set()
            for group in foreign_keys.values():
                if len(group) == 2:
                    self.assertEqual({(r['from'], r['to']) for r in group if r['from'] == 'run_id'}, {('run_id', 'run_id')})
                    self.assertTrue(all(r['on_delete'] == 'RESTRICT' for r in group))
                    actual.update(r['from'] for r in group if r['to'] == 'id')
            self.assertEqual(actual, columns)
        # RESTRICT must reject replacement even if recursive DELETE guards are
        # disabled, rather than waiting until a replacement restores the key.
        run, snapshots = self.fixture()
        bindings, _, _ = self.promote(run, snapshots)
        self.db.execute('PRAGMA recursive_triggers=OFF')
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(
                    'INSERT OR REPLACE INTO identifier_binding(id,run_id,namespace_id,identifier,entity_id,source_record_id) '
                    'SELECT id,run_id,namespace_id,identifier,5,source_record_id FROM identifier_binding WHERE id=?',
                    (bindings[0],))
        finally:
            self.db.execute('PRAGMA recursive_triggers=ON')
        self.assertEqual(self.db.execute('SELECT entity_id FROM identifier_binding WHERE id=?', (bindings[0],)).fetchone()[0], 1)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_sealed_interpretations_reject_all_child_changes_and_replace(self):
        run, snapshots = self.fixture(stats=[self.stats[0], dict(self.stats[0], identifier=None)])
        bindings, game, player = self.promote(run, snapshots)
        self.db.execute("INSERT INTO finding(run_id,severity,code,message) VALUES(?,'WARNING','synthetic','warning')", (run,))
        seal_run(self.db, run)
        selection = self.select(run)
        for table in ('identifier_binding', 'game_observation', 'player_game_observation', 'finding', 'quarantine'):
            with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(f'DELETE FROM {table} WHERE run_id=?', (run,))
            with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(f'UPDATE {table} SET run_id=run_id WHERE run_id=?', (run,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.bind(run, self.records(snapshots[0])[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO finding(run_id,severity,code,message) VALUES(?,'WARNING','x','x')", (run,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('UPDATE validation_run SET sealed=0 WHERE id=?', (run,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('DELETE FROM validation_run WHERE id=?', (run,))
        for sql in ('UPDATE research_selection SET mode=mode WHERE id=?', 'DELETE FROM research_selection WHERE id=?'):
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(sql, (selection,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('INSERT OR REPLACE INTO entity(id,kind,label) VALUES(1,\'PLAYER\',\'replacement\')')
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('INSERT OR REPLACE INTO validation_run(id,identity_snapshot,schedule_snapshot,stats_snapshot) VALUES(?,?,?,?)',
                            (run, *snapshots))

    def test_transaction_rolls_back_injected_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            with transaction(self.db):
                self.db.execute("INSERT INTO entity(kind,label) VALUES('PLAYER','rolled back')")
                raise RuntimeError('injected')
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.db.execute('SELECT count(*) FROM entity').fetchone()[0], 5)
        with self.assertRaises(RuntimeError):
            with transaction(self.db):
                with transaction(self.db):
                    pass
        self.assertFalse(self.db.in_transaction)

    def test_loader_rolls_back_partial_snapshot_on_constraint_failure(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.snapshot('IDENTITY', [self.identities[0], {'namespace_id': 999, 'identifier': 'bad'}])
        self.assertEqual(self.db.execute('SELECT count(*) FROM source_snapshot').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM source_record').fetchone()[0], 0)

    def test_unknown_kickoff_timezone_stays_unknown(self):
        run, snapshots = self.fixture()
        self.promote(run, snapshots)
        seal_run(self.db, run)
        row = self.db.execute('SELECT kickoff_local,kickoff_timezone,kickoff_utc FROM source_record WHERE id=?',
                              (self.records(snapshots[1])[0],)).fetchone()
        self.assertEqual(tuple(row), ('2030-10-01 13:00', None, None))
        with self.assertRaises(sqlite3.IntegrityError):
            self.snapshot('SCHEDULE', [dict(self.schedule[0], kickoff_utc='2030-10-01T17:00:00Z')])

    def test_unsupported_historical_selections_rejected(self):
        run, snapshots = self.fixture()
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(run)
        self.promote(run, snapshots)
        seal_run(self.db, run)
        self.select(run)
        for mode in ('OBSERVED_BY_EDGEFINDER', 'VERIFIED_PUBLICATION'):
            with self.assertRaises(sqlite3.IntegrityError):
                self.select(run, mode, '2030-10-02T00:00:00Z')

    def test_supported_temporal_modes_and_cutoff_boundaries(self):
        run, snapshots = self.fixture(retrieved_at='2030-10-03T00:00:00Z',
                                     publication_at='2030-10-02T00:00:00Z',
                                     publication_evidence='synthetic publication log')
        self.promote(run, snapshots)
        seal_run(self.db, run)
        self.select(run, 'OBSERVED_BY_EDGEFINDER', '2030-10-03T00:00:00Z')
        self.select(run, 'VERIFIED_PUBLICATION', '2030-10-02T00:00:00Z')
        for mode, cutoff in [('OBSERVED_BY_EDGEFINDER', '2030-10-02T00:00:00Z'),
                             ('VERIFIED_PUBLICATION', '2030-10-01T00:00:00Z')]:
            with self.assertRaises(sqlite3.IntegrityError):
                self.select(run, mode, cutoff)
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(run, 'OBSERVED_BY_EDGEFINDER')

    def test_every_selected_snapshot_requires_time_support(self):
        identity = self.snapshot('IDENTITY', self.identities)
        schedule = self.snapshot('SCHEDULE', self.schedule, retrieved_at='2030-10-03T00:00:00Z')
        stats = self.snapshot('STATS', self.stats, retrieved_at='2030-10-03T00:00:00Z')
        run = create_run(self.db, identity=identity, schedule=schedule, stats=stats)
        self.promote(run, [identity, schedule, stats])
        seal_run(self.db, run)
        with self.assertRaises(sqlite3.IntegrityError):
            self.select(run, 'OBSERVED_BY_EDGEFINDER', '2030-10-03T00:00:00Z')

    def test_canonical_hash_preserves_types_and_empty_values(self):
        values = [None, 0, '', False, 0.0, '0', [], {}]
        self.assertEqual(len({evidence_hash([canonical(v)]) for v in values}), len(values))
        self.assertEqual(canonical({'a': 1, 'b': 2}), canonical({'b': 2, 'a': 1}))
        self.assertNotEqual(canonical([1, 2]), canonical([2, 1]))
        ids = {self.snapshot('STATS', [dict(self.stats[0], payload=value)]) for value in values}
        self.assertEqual(len(ids), len(values))
        for invalid in (float('nan'), float('inf'), {1: 'bad'}, (1, 2)):
            with self.assertRaises((TypeError, ValueError)):
                canonical(invalid)

    def test_canonical_rejects_single_character_surrogate_pair_collision(self):
        scalar = '\U0001f600'
        surrogate_pair = '\ud83d\ude00'
        self.assertEqual(len(scalar), 1)
        self.assertEqual(len(surrogate_pair), 2)
        # ASCII JSON alone collapses these distinct Python strings to the same
        # bytes. Accept the scalar character, reject the surrogate representation.
        self.assertEqual(json.dumps(scalar, ensure_ascii=True), json.dumps(surrogate_pair, ensure_ascii=True))
        canonical(scalar)
        canonical({scalar: 'valid key'})
        for invalid in (surrogate_pair, '\ud800', '\udfff',
                        {'nested': [surrogate_pair]}, {surrogate_pair: 'invalid key'}):
            with self.subTest(value=repr(invalid)), self.assertRaisesRegex(ValueError, 'surrogate'):
                canonical(invalid)

    def test_surrogate_ingestion_rejection_leaves_no_partial_evidence(self):
        first = self.snapshot('STATS', [dict(self.stats[0], payload='\U0001f600')])
        for invalid in ('\ud83d\ude00', {'\ud83d\ude00': 'key'}, {'nested': ['\ud800']}):
            with self.subTest(payload=repr(invalid)), self.assertRaisesRegex(ValueError, 'surrogate'):
                self.snapshot('STATS', [self.stats[0], dict(self.stats[0], payload=invalid)])
            # Also reject the colliding one-row snapshot before deduplication.
            with self.assertRaisesRegex(ValueError, 'surrogate'):
                self.snapshot('STATS', [dict(self.stats[0], payload=invalid)])
        self.assertEqual(self.db.execute('SELECT count(*) FROM source_snapshot').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM source_record').fetchone()[0], 1)
        self.assertEqual(len(self.records(first)), 1)
        self.assertFalse(self.db.in_transaction)

    def test_create_run_uses_covering_indexes_without_correlated_scans(self):
        _, snapshots = self.fixture()
        plan = [row['detail'] for row in self.db.execute(
            'EXPLAIN QUERY PLAN ' + _QUARANTINE_SQL,
            {'run': 999, 'identity': snapshots[0], 'schedule': snapshots[1], 'stats': snapshots[2]})]
        covered = [detail for detail in plan if 'COVERING INDEX source_record_identity_keys' in detail]
        self.assertGreaterEqual(len(covered), 4, plan)
        self.assertFalse(any('CORRELATED' in detail for detail in plan), plan)

    def test_create_run_scales_with_duplicate_heavy_synthetic_snapshots(self):
        identity = self.snapshot('IDENTITY', self.identities)
        schedule = self.snapshot('SCHEDULE', self.schedule)
        steps = []
        for size in (512, 2048):
            stats = self.snapshot('STATS', [self.stats[0]] * size)
            ticks = 0

            def progress():
                nonlocal ticks
                ticks += 1
                return 0

            self.db.set_progress_handler(progress, 100)
            try:
                run = create_run(self.db, identity=identity, schedule=schedule, stats=stats)
            finally:
                self.db.set_progress_handler(None, 0)
            steps.append(ticks)
            self.assertEqual(self.db.execute('SELECT count(*) FROM quarantine WHERE run_id=?', (run,)).fetchone()[0], size)
        # Four times as many rows permits six times as many VM steps; the old
        # duplicate-count scans grow quadratically (approximately sixteen times).
        self.assertGreater(steps[0], 0)
        self.assertLess(steps[1], steps[0] * 6, steps)

    def test_seal_missing_run_raises_and_rolls_back(self):
        with self.assertRaisesRegex(ValueError, 'Validation run 999 does not exist'):
            seal_run(self.db, 999)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.db.execute('SELECT count(*) FROM validation_run').fetchone()[0], 0)

    def test_source_evidence_is_immutable_and_hash_checked(self):
        snapshot = self.snapshot('IDENTITY', self.identities)
        record = self.records(snapshot)[0]
        for sql, value in [
            ('UPDATE source_record SET identifier=identifier WHERE id=?', record),
            ('DELETE FROM source_record WHERE id=?', record),
            ('UPDATE source_snapshot SET retrieved_at=NULL WHERE id=?', snapshot),
            ('DELETE FROM source_snapshot WHERE id=?', snapshot),
        ]:
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(sql, (value,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('INSERT INTO source_record(snapshot_id,ordinal,namespace_id,payload,normalized) '
                            'SELECT snapshot_id,99,namespace_id,payload,normalized FROM source_record WHERE id=?', (record,))
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'hash mismatch'):
            with transaction(self.db):
                new = self.db.execute("INSERT INTO source_snapshot(provider,role,loader_scope,normalization_version,normalized_sha256) "
                                      "VALUES('synthetic','IDENTITY','fake','edgefinder.normalized.v1',?)", ('0' * 64,)).lastrowid
                self.db.execute('INSERT INTO source_record(snapshot_id,ordinal,namespace_id,identifier,payload,normalized) '
                                'SELECT ?,ordinal,namespace_id,identifier,payload,normalized FROM source_record WHERE id=?', (new, record))
                self.db.execute('UPDATE source_snapshot SET sealed=1 WHERE id=?', (new,))

    def test_blocking_findings_and_complete_interpretation_required(self):
        run, snapshots = self.fixture()
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'every selected record'):
            seal_run(self.db, run)
        self.promote(run, snapshots)
        finding = self.db.execute("INSERT INTO finding(run_id,severity,code,message) VALUES(?,'BLOCKING','x','synthetic block')", (run,)).lastrowid
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'blocking'):
            seal_run(self.db, run)
        self.db.execute('DELETE FROM finding WHERE id=?', (finding,))
        seal_run(self.db, run)

    def test_namespace_entity_role_and_timestamp_constraints(self):
        self.assertEqual(self.db.execute('PRAGMA foreign_keys').fetchone()[0], 1)
        self.assertEqual(self.db.execute('PRAGMA recursive_triggers').fetchone()[0], 1)
        run, snapshots = self.fixture()
        with self.assertRaises(sqlite3.IntegrityError):
            self.bind(run, self.records(snapshots[0])[0], 2)
        with self.assertRaises(sqlite3.IntegrityError):
            create_run(self.db, identity=snapshots[1], schedule=snapshots[0], stats=snapshots[2])
        with self.assertRaises(sqlite3.IntegrityError):
            self.snapshot('SCHEDULE', self.identities[:1])
        self.db.execute("INSERT INTO identifier_namespace(provider,kind,name) VALUES('other','PLAYER','player')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.snapshot('IDENTITY', [{'namespace_id': 4, 'identifier': 'p1'}])
        for invalid in ('2030-02-30T00:00:00Z', '2030-10-01 00:00:00', '2030-10-01T00:00:00-04:00'):
            with self.assertRaises(sqlite3.IntegrityError):
                self.snapshot('IDENTITY', [dict(self.identities[0], payload=invalid)], retrieved_at=invalid)
        with self.assertRaises(sqlite3.IntegrityError):
            self.snapshot('IDENTITY', [dict(self.identities[0], payload='publication')], publication_at='2030-10-01T00:00:00Z')


if __name__ == '__main__':
    unittest.main()
