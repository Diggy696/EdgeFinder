"""Pure synthetic fixture checks; no databases, provider traffic or file writes."""

from dataclasses import FrozenInstanceError, fields, replace
import json
import sys
import unittest
from unittest.mock import patch

from edgefinder import synthetic_transform as transform
from edgefinder.storage import database
from edgefinder.synthetic_transform import (
    PreparedIdentityRow, PreparedSyntheticIdentity, SyntheticTransformCode as Code,
    SyntheticTransformError, transform_synthetic_identity_v1,
)


FORMAT = "edgefinder.synthetic.identity.v1"
MIB = 1048576
TOTAL = 8 * MIB
ROW = {"identifier": "fixture-player-1", "payload": {"sample": 7}}
_DEFAULT = object()


def fixture(rows=None, *, ensure_ascii=False):
    return json.dumps({"format": FORMAT, "rows": [ROW] if rows is None else rows},
                      ensure_ascii=ensure_ascii, separators=(",", ":")).encode("utf-8")


def normalized(identifier, payload, namespace_id=1):
    # Spell out the storage contract independently of the transformer's mapping.
    return dict(namespace_id=namespace_id, identifier=identifier,
                game_namespace_id=None, game_identifier=None,
                team_namespace_id=None, team_identifier=None,
                home_namespace_id=None, home_identifier=None,
                away_namespace_id=None, away_identifier=None,
                kickoff_local=None, kickoff_timezone=None, kickoff_utc=None,
                payload=dict(payload))


def padded_body(length):
    body = fixture()
    if length < len(body):
        raise AssertionError("Requested fixture padding is too short")
    return body + b" " * (length - len(body))


class SyntheticTransformTests(unittest.TestCase):
    def prepare(self, bodies=_DEFAULT, **changes):
        arguments = dict(occurrence_indices=(0,), namespace_id=1, loader_scope="synthetic-fixture")
        arguments.update(changes)
        return transform_synthetic_identity_v1((fixture(),) if bodies is _DEFAULT else bodies,
                                               **arguments)

    def assert_failure(self, expected, bodies=_DEFAULT, **changes):
        with self.assertRaises(SyntheticTransformError) as caught:
            self.prepare(bodies, **changes)
        error = caught.exception
        self.assertIs(error.code, expected)
        self.assertEqual(error.args, (expected.value,))
        self.assertEqual(str(error), expected.value)
        self.assertIsNone(error.__cause__)
        self.assertFalse(hasattr(error, "rows"))
        self.assertFalse(hasattr(error, "document"))
        self.assertFalse(hasattr(error, "result"))
        return error

    def test_valid_conversion_and_complete_normalized_record_accounting(self):
        result = self.prepare(namespace_id=-5)
        self.assertIs(type(result), PreparedSyntheticIdentity)
        self.assertEqual(result.namespace_id, -5)
        self.assertEqual(result.loader_scope, "synthetic-fixture")
        self.assertEqual(result.rows, (PreparedIdentityRow("fixture-player-1", (("sample", 7),)),))
        record = normalized("fixture-player-1", {"sample": 7}, -5)
        self.assertEqual(set(record), set(database.RECORD_FIELDS))
        self.assertTrue(all(record[name] is None for name in record
                            if name not in ("namespace_id", "identifier", "payload")))
        self.assertEqual(result.canonical_normalized_bytes,
                         len(database.canonical(record).encode("utf-8")))
        with patch.object(database, "canonical", wraps=database.canonical) as canonical:
            self.prepare(namespace_id=-5)
        self.assertEqual(canonical.call_args_list[-1].args, (record,))

    def test_fixed_metadata_and_no_identity_override_arguments(self):
        result = self.prepare()
        fixed = dict(format=FORMAT, transformation_id="edgefinder.synthetic.identity",
                     transformation_version="v1", provider="synthetic", role="IDENTITY",
                     normalization_version=database.NORMALIZATION_VERSION,
                     original_file_sha256=None, retrieved_at=None,
                     publication_at=None, publication_evidence=None)
        for name, value in fixed.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(result, name), value)
                with self.assertRaises(FrozenInstanceError):
                    setattr(result, name, "caller override")
                with self.assertRaises(TypeError):
                    replace(result, **{name: "caller override"})
                with self.assertRaises(TypeError):
                    self.prepare(**{name: "caller override"})

    def test_scalar_values_sorted_keys_and_type_preservation(self):
        payload = {"z": None, "t": True, "f": False, "zero": 0,
                   "min": -(2 ** 63), "max": 2 ** 63 - 1, "": "", "text": "  value  "}
        result = self.prepare((fixture([dict(identifier=None, payload=payload)]),))
        row = result.rows[0]
        self.assertIsNone(row.identifier)
        self.assertEqual(row.payload, tuple(sorted(payload.items())))
        retained = dict(row.payload)
        self.assertIs(type(retained["t"]), bool)
        self.assertIs(type(retained["f"]), bool)
        self.assertIs(type(retained["zero"]), int)
        self.assertEqual(retained["min"], -(2 ** 63))
        self.assertEqual(retained["max"], 2 ** 63 - 1)
        self.assertEqual(retained["text"], "  value  ")

    def test_empty_and_null_identifiers_empty_payloads_and_literal_null_characters(self):
        rows = [dict(identifier=value, payload={"\x00": "a\x00b"})
                for value in (None, "", "  p  ", "\x00")]
        rows.append(dict(identifier="empty-payload", payload={}))
        result = self.prepare((fixture(rows),))
        self.assertEqual([row.identifier for row in result.rows], [row["identifier"] for row in rows])
        self.assertEqual(result.rows[-1].payload, ())
        self.assertEqual(result.rows[0].payload, (("\x00", "a\x00b"),))

    def test_integer_lexical_spellings_represent_decoded_values(self):
        body = fixture().replace(b'"sample":7', b'"sample":-0')
        value = dict(self.prepare((body,)).rows[0].payload)["sample"]
        self.assertIs(type(value), int)
        self.assertEqual(value, 0)

    def test_numeric_overflow_and_forbidden_number_tokens(self):
        tokens = (b"9223372036854775808", b"-9223372036854775809", b"9" * 10000,
                  b"-" + b"9" * 10000, b"1.0", b"-0.0", b"1e0", b"1E+3",
                  b"1e9999999", b"NaN", b"Infinity", b"-Infinity")
        for token in tokens:
            with self.subTest(token_length=len(token), prefix=token[:25]):
                self.assert_failure(Code.MALFORMED_FIXTURE,
                                    (fixture().replace(b'"sample":7', b'"sample":' + token),))

    def test_numeric_syntax_errors_do_not_bypass_validation(self):
        for token in (b"+1", b"01", b"--1", b"0x10", b"1.", b".5", b"nullx"):
            with self.subTest(token=token):
                self.assert_failure(Code.MALFORMED_FIXTURE,
                                    (fixture().replace(b'"sample":7', b'"sample":' + token),))

    def test_strict_utf8_bom_and_other_encodings(self):
        bodies = (b"\xef\xbb\xbf" + fixture(), b" \xef\xbb\xbf" + fixture(),
                  b"\xff", fixture().decode().encode("utf-16"),
                  fixture().replace(b"fixture-player-1", b"\xed\xa0\x80"),
                  fixture().replace(b"fixture-player-1", b"\xc0\xaf"))
        for body in bodies:
            with self.subTest(prefix=body[:8]):
                self.assert_failure(Code.MALFORMED_FIXTURE, (body,))

    def test_trailing_json_whitespace_and_leading_whitespace_accepted(self):
        self.assertEqual(self.prepare((b" \r\n\t" + fixture() + b" \r\n\t",)), self.prepare())

    def test_trailing_content_and_invalid_json_rejected(self):
        for body in (b"", b" \t", b"{", fixture() + b"{}", fixture() + b"null",
                     fixture() + b" sensitive trailing text", fixture() + b"\x00",
                     fixture() + b"\xc2\xa0", b"/* comment */" + fixture(),
                     fixture().replace(b'"sample":7', b'"sample":7,')):
            with self.subTest(prefix=body[:10], length=len(body)):
                self.assert_failure(Code.MALFORMED_FIXTURE, (body,))

    def test_duplicate_object_keys_at_all_levels_and_escaped_equivalents(self):
        bodies = (
            fixture().replace(b'"format":', b'"format":"wrong","format":'),
            fixture().replace(b'"rows":', b'"rows":[],"rows":'),
            fixture().replace(b'"identifier":', b'"identifier":null,"identifier":'),
            fixture().replace(b'"payload":', b'"payload":{},"payload":'),
            fixture().replace(b'"sample":7', b'"sample":0,"sample":7'),
            fixture().replace(b'"sample":7', b'"sample":0,"s\\u0061mple":7'),
            fixture().replace(b'"rows":', b'"r\\u006fws":[],"rows":'),
            fixture().replace(b'"sample":7', b'"\\ud83d\\ude00":0,"\xf0\x9f\x98\x80":7'),
        )
        for body in bodies:
            with self.subTest(body_length=len(body)):
                self.assert_failure(Code.MALFORMED_FIXTURE, (body,))

    def test_valid_unicode_scalars_and_surrogate_pair_json_spellings(self):
        rows = [dict(identifier="\U0001f600", payload={"\U0001f600": "\U0010ffff", "accent": "\u00e9"})]
        literal = self.prepare((fixture(rows),))
        escaped = self.prepare((fixture(rows, ensure_ascii=True),))
        self.assertEqual(literal, escaped)
        self.assertEqual(literal.rows[0].identifier, "\U0001f600")
        self.assertEqual(dict(literal.rows[0].payload)["\U0001f600"], "\U0010ffff")

    def test_lone_or_malformed_surrogates_in_identifiers_keys_and_values(self):
        for text in ("\ud800", "\udfff", "\ud800x", "\ud800\ud800", "\udfff\ud800"):
            cases = [dict(identifier=text, payload={}), dict(identifier="p", payload={text: 0}),
                     dict(identifier="p", payload={"x": text})]
            for row in cases:
                with self.subTest(text=repr(text), row_kind=list(row)):
                    self.assert_failure(Code.MALFORMED_FIXTURE,
                                        (fixture([row], ensure_ascii=True),))

    def test_unicode_is_not_normalized_trimmed_or_case_folded(self):
        rows = [dict(identifier=value, payload={value: value})
                for value in ("\u00e9", "e\u0301", " X ", "x")]
        result = self.prepare((fixture(rows),))
        self.assertEqual(len(result.rows), 4)
        for prepared, original in zip(result.rows, rows):
            self.assertEqual(prepared.identifier, original["identifier"])
            self.assertEqual(dict(prepared.payload), original["payload"])
        self.assertNotEqual(result.rows[0], result.rows[1])

    def test_document_keys_format_and_rows_shape_are_exact(self):
        documents = (None, [], 1, True, "text", {}, {"format": FORMAT}, {"rows": []},
                     {"format": FORMAT, "rows": [], "extra": None},
                     *({"format": value, "rows": []} for value in (None, [], {}, 1, True, "v2")),
                     *({"format": FORMAT, "rows": value} for value in (None, {}, "rows", 1, True)))
        for document in documents:
            with self.subTest(document_type=type(document).__name__):
                self.assert_failure(Code.MALFORMED_FIXTURE,
                                    (json.dumps(document).encode("utf-8"),))

    def test_row_shapes_missing_and_unknown_fields_rejected(self):
        rows = (None, [], "row", 1, True, {}, {"identifier": "p"}, {"payload": {}},
                dict(ROW, extra=0), dict(ROW, namespace_id=1), dict(ROW, retrieved_at=None))
        for row in rows:
            with self.subTest(row_type=type(row).__name__):
                self.assert_failure(Code.MALFORMED_FIXTURE, (fixture([row]),))

    def test_identifier_and_payload_value_types_rejected(self):
        for identifier in (True, False, 0, 7, [], {}):
            with self.subTest(identifier_type=type(identifier).__name__):
                self.assert_failure(Code.MALFORMED_FIXTURE,
                                    (fixture([dict(identifier=identifier, payload={})]),))
        for payload in (None, True, 0, "payload", [], [1], {"x": []}, {"x": {}},
                        {"x": {"y": 1}}, {"x": [None]}):
            with self.subTest(payload_type=type(payload).__name__):
                self.assert_failure(Code.MALFORMED_FIXTURE,
                                    (fixture([dict(identifier="p", payload=payload)]),))

    def test_empty_documents_allowed_but_combined_output_must_be_nonempty(self):
        self.assert_failure(Code.MALFORMED_FIXTURE, (fixture([]),))
        result = self.prepare((fixture([]), fixture()), occurrence_indices=(0, 1, 0))
        self.assertEqual(result.rows, self.prepare().rows)
        self.assertEqual(result.canonical_normalized_bytes, self.prepare().canonical_normalized_bytes)
        self.assertEqual(result.occurrence_indices, (0, 1, 0))
        self.assert_failure(Code.MALFORMED_FIXTURE, (fixture([]), fixture([])),
                            occurrence_indices=(1, 0, 1))

    def test_occurrence_order_document_order_and_duplicate_rows_preserved(self):
        a = fixture([dict(identifier="a1", payload={}), dict(identifier="a2", payload={}),
                     dict(identifier="a1", payload={})])
        b = fixture([dict(identifier="b", payload={})])
        indices = (1, 0, 1)
        result = self.prepare((a, b), occurrence_indices=indices)
        self.assertIs(result.occurrence_indices, indices)
        self.assertEqual(tuple(row.identifier for row in result.rows), ("b", "a1", "a2", "a1", "b"))
        expected = sum(len(database.canonical(normalized(name, {})).encode("utf-8"))
                       for name in ("b", "a1", "a2", "a1", "b"))
        self.assertEqual(result.canonical_normalized_bytes, expected)

    def test_equal_bytes_in_distinct_positions_not_deduplicated_and_decoded_once_each(self):
        body = fixture()
        with patch.object(transform.json, "loads", wraps=json.loads) as decode:
            with patch.object(database, "canonical", wraps=database.canonical) as canonical:
                result = self.prepare((body, body), occurrence_indices=(1, 0, 1))
        self.assertEqual(decode.call_count, 2)
        self.assertEqual(canonical.call_count, 3)  # parameters plus one row per acquisition
        self.assertEqual(len(result.rows), 3)
        self.assertEqual(result.canonical_normalized_bytes,
                         3 * self.prepare().canonical_normalized_bytes)
        self.assert_failure(Code.INVALID_ARGUMENT, (body, body), occurrence_indices=(0,))

    def test_wrong_container_and_body_types_rejected_without_iteration_callbacks(self):
        class TupleSubclass(tuple):
            pass

        class BytesSubclass(bytes):
            pass

        class NeverIterate:
            def __iter__(self):
                raise AssertionError("Unexpected caller iteration")

        for bodies in (None, [], [fixture()], fixture(), NeverIterate(), TupleSubclass((fixture(),))):
            with self.subTest(container=type(bodies).__name__):
                self.assert_failure(Code.INVALID_ARGUMENT, bodies, occurrence_indices=(0,))
        self.assert_failure(Code.INVALID_ARGUMENT, ())
        for body in (None, "text", 1, bytearray(fixture()), memoryview(fixture()), BytesSubclass(fixture())):
            with self.subTest(body_type=type(body).__name__):
                self.assert_failure(Code.INVALID_ARGUMENT, (body,))
        for indices in (None, [], [0], "0", NeverIterate(), TupleSubclass((0,))):
            with self.subTest(indices_type=type(indices).__name__):
                self.assert_failure(Code.INVALID_ARGUMENT, occurrence_indices=indices)

    def test_invalid_occurrence_indices_and_unused_positions(self):
        for indices in ((), (True,), (False,), (0.0,), ("0",), (None,), (-1,), (1,), (10 ** 100,)):
            with self.subTest(indices=indices):
                self.assert_failure(Code.INVALID_ARGUMENT, occurrence_indices=indices)
        self.assert_failure(Code.INVALID_ARGUMENT, (fixture(), fixture()), occurrence_indices=(1, 1))

    def test_namespace_range_exact_types_and_no_database_existence_requirement(self):
        class IntSubclass(int):
            pass

        for identifier in (-(2 ** 63), -1, 0, 1, 2 ** 63 - 1):
            with self.subTest(identifier=identifier):
                self.assertEqual(self.prepare(namespace_id=identifier).namespace_id, identifier)
        for identifier in (True, False, None, "1", 1.0, IntSubclass(1), -(2 ** 63) - 1, 2 ** 63):
            with self.subTest(identifier_type=type(identifier).__name__):
                self.assert_failure(Code.INVALID_ARGUMENT, namespace_id=identifier)

    def test_loader_scope_storage_contract_without_observation_scope_narrowing(self):
        class StringSubclass(str):
            pass

        for scope in (" ", "  scope  ", "\u00e9\U0001f600", "line\nbreak", "a\x00b"):
            with self.subTest(scope=repr(scope)):
                self.assertEqual(self.prepare(loader_scope=scope).loader_scope, scope)
        for scope in (None, True, 1, b"scope", "", "\x00", "\x00scope", "\ud800", StringSubclass("scope")):
            with self.subTest(scope_type=type(scope).__name__):
                self.assert_failure(Code.INVALID_ARGUMENT, loader_scope=scope)

    def test_individual_body_exact_boundary_and_one_byte_over_before_decoding(self):
        self.assertEqual(self.prepare((padded_body(MIB),)).rows, self.prepare().rows)
        with patch.object(transform.json, "loads", side_effect=AssertionError("Unexpected decoding")):
            self.assert_failure(Code.RESOURCE_LIMIT, (b"x" * (MIB + 1),))

    def test_aggregate_body_exact_boundary_and_one_byte_over(self):
        bodies = (padded_body(MIB),) * 7 + (padded_body(MIB - 1), b" ")
        # At 8 MiB, byte validation passes and the last invalid document is decoded.
        self.assertEqual(sum(map(len, bodies)), TOTAL)
        self.assert_failure(Code.MALFORMED_FIXTURE, bodies, occurrence_indices=tuple(range(9)))
        accepted = self.prepare((padded_body(MIB),) * 8, occurrence_indices=tuple(range(8)))
        self.assertEqual(len(accepted.rows), 8)
        with patch.object(transform.json, "loads", side_effect=AssertionError("Unexpected decoding")):
            self.assert_failure(Code.RESOURCE_LIMIT, bodies[:-1] + (b"  ",),
                                occurrence_indices=tuple(range(9)))

    def test_occurrence_expanded_bytes_exact_boundary_and_one_byte_over(self):
        # Build 8 MiB exactly from eight repeats plus a second acquisition.
        repeats = 8
        body = padded_body(MIB - len(fixture()))
        remainder = TOTAL - repeats * len(body)
        other = padded_body(remainder)
        indices = (0,) * repeats + (1,)
        result = self.prepare((body, other), occurrence_indices=indices)
        self.assertEqual(len(body) * repeats + len(other), TOTAL)
        self.assertEqual(len(result.rows), 9)
        with patch.object(transform.json, "loads", side_effect=AssertionError("Unexpected decoding")):
            self.assert_failure(Code.RESOURCE_LIMIT, (body, other + b" "), occurrence_indices=indices)

    def test_occurrence_count_exact_boundary_and_one_over(self):
        result = self.prepare(occurrence_indices=(0,) * 4096)
        self.assertEqual(len(result.rows), 4096)
        self.assertEqual(result.canonical_normalized_bytes,
                         self.prepare().canonical_normalized_bytes * 4096)
        self.assert_failure(Code.RESOURCE_LIMIT, occurrence_indices=(0,) * 4097)
        self.assert_failure(Code.RESOURCE_LIMIT, (fixture([]),) * 4097)

    def test_output_row_count_exact_boundary_and_one_over(self):
        result = self.prepare((fixture([ROW] * 4096),))
        self.assertEqual(len(result.rows), 4096)
        self.assert_failure(Code.RESOURCE_LIMIT, (fixture([ROW] * 4097),))
        self.assert_failure(Code.RESOURCE_LIMIT, (fixture([ROW] * 2049),), occurrence_indices=(0, 0))

    def test_normalized_output_byte_exact_boundary_and_one_over_with_multiplicity(self):
        row = dict(identifier="p", payload={"x": ""})
        overhead = len(database.canonical(normalized("p", row["payload"])).encode("utf-8"))
        row["payload"]["x"] = "x" * (TOTAL // 16 - overhead)
        body = fixture([row])
        self.assertLess(len(body), MIB)
        accepted = self.prepare((body,), occurrence_indices=(0,) * 16)
        self.assertEqual(accepted.canonical_normalized_bytes, TOTAL)
        bigger_row = dict(identifier="p", payload={"x": row["payload"]["x"] + "x"})
        bigger = fixture([bigger_row])
        self.assertLess(15 * len(body) + len(bigger), TOTAL)
        self.assert_failure(Code.RESOURCE_LIMIT, (body, bigger), occurrence_indices=(0,) * 15 + (1,))

    def test_canonical_parameter_budget_exact_boundary_and_one_over(self):
        overhead = len(database.canonical({"namespace_id": 1, "loader_scope": ""}).encode("utf-8"))
        scope = "x" * (65536 - overhead)
        self.assertEqual(len(database.canonical({"namespace_id": 1, "loader_scope": scope})
                             .encode("utf-8")), 65536)
        self.assertEqual(self.prepare(loader_scope=scope).loader_scope, scope)
        self.assert_failure(Code.RESOURCE_LIMIT, loader_scope=scope + "x")
        self.assert_failure(Code.RESOURCE_LIMIT, loader_scope="x" * 65537)
        self.assert_failure(Code.RESOURCE_LIMIT, loader_scope="\u00e9" * 11000)

    def test_canonical_output_counts_null_fields_and_unicode_escape_expansion(self):
        row = dict(identifier="\U0001f600", payload={"\u00e9": "\u00e9"})
        body = fixture([row])
        result = self.prepare((body,), occurrence_indices=(0, 0))
        full_text = database.canonical(normalized(row["identifier"], row["payload"]))
        self.assertIn("\\ud83d\\ude00", full_text)
        self.assertIn("\\u00e9", full_text)
        self.assertGreater(len(full_text.encode("utf-8")), len(body))
        self.assertEqual(result.canonical_normalized_bytes, 2 * len(full_text.encode("utf-8")))
        outer = database.canonical(sorted([full_text, full_text]))
        self.assertNotEqual(result.canonical_normalized_bytes, len(outer.encode("utf-8")))

    def test_budget_and_reference_failures_precede_decoding(self):
        with patch.object(transform.json, "loads", side_effect=AssertionError("Unexpected decoding")):
            self.assert_failure(Code.INVALID_ARGUMENT, (b"invalid",), occurrence_indices=(1,))
            self.assert_failure(Code.INVALID_ARGUMENT, (b"invalid", b"invalid"), occurrence_indices=(0,))
            self.assert_failure(Code.RESOURCE_LIMIT, (b"x" * MIB,), occurrence_indices=(0,) * 9)

    def test_result_is_deeply_immutable_and_storage_dicts_are_fresh(self):
        result = self.prepare(occurrence_indices=(0, 0))
        self.assertFalse(hasattr(result, "__dict__"))
        self.assertFalse(hasattr(result.rows[0], "__dict__"))
        self.assertIs(type(result.rows), tuple)
        self.assertIs(type(result.rows[0].payload), tuple)
        self.assertIs(type(result.rows[0].payload[0]), tuple)
        with self.assertRaises(FrozenInstanceError):
            result.rows = ()
        with self.assertRaises(FrozenInstanceError):
            result.rows[0].identifier = "changed"
        with self.assertRaises(TypeError):
            result.rows[0].payload[0] = ("sample", 99)
        storage = [normalized(row.identifier, row.payload, result.namespace_id) for row in result.rows]
        storage[0]["payload"]["sample"] = 99
        storage[0]["identifier"] = "changed"
        self.assertEqual(storage[1]["payload"]["sample"], 7)
        self.assertEqual(result.rows[0].payload, (("sample", 7),))
        self.assertEqual(result.rows[0].identifier, "fixture-player-1")
        self.assertIsInstance(hash(result), int)

    def test_later_invalid_acquisition_has_no_partial_result_or_fixture_leak(self):
        secret = b"fixture-marker-sensitive"
        bad = fixture().replace(b'"sample":7', b'"sample":[' + secret + b"]")
        error = self.assert_failure(Code.MALFORMED_FIXTURE, (fixture(), bad), occurrence_indices=(0, 1))
        self.assertNotIn(secret.decode(), repr(error))
        self.assertEqual(set(vars(error)), {"code"})
        self.assertTrue(error.__suppress_context__)

    def test_deeply_nested_json_is_a_sanitized_fixture_error(self):
        body = b"[" * 10000 + b"0" + b"]" * 10000
        self.assert_failure(Code.MALFORMED_FIXTURE, (body,))
        # Interpreter decoder recursion behavior can vary. Exercise the explicit
        # recursion-failure boundary independently of its current nesting limit.
        with patch.object(transform.json, "loads", side_effect=RecursionError("fixture-sensitive")):
            error = self.assert_failure(Code.MALFORMED_FIXTURE)
        self.assertTrue(error.__suppress_context__)
        self.assertNotIn("fixture-sensitive", repr(error))

    def test_control_signals_propagate_unchanged(self):
        for signal in (KeyboardInterrupt(), SystemExit(7), GeneratorExit()):
            with self.subTest(signal=type(signal).__name__):
                with patch.object(transform.json, "loads", side_effect=signal):
                    with self.assertRaises(type(signal)) as caught:
                        self.prepare()
                self.assertIs(caught.exception, signal)

    def test_stable_error_codes_and_repeatable_failure_precedence(self):
        self.assertEqual({code.value for code in Code},
                         {"invalid_argument", "malformed_fixture", "resource_limit"})
        for _ in range(2):
            self.assert_failure(Code.INVALID_ARGUMENT, (b"invalid",), namespace_id=True)
            self.assert_failure(Code.RESOURCE_LIMIT, (b"invalid" * MIB,))
            self.assert_failure(Code.MALFORMED_FIXTURE, (b"invalid",))

    def test_frozen_contract_field_shapes(self):
        self.assertEqual(tuple(field.name for field in fields(PreparedIdentityRow)),
                         ("identifier", "payload"))
        self.assertEqual(tuple(field.name for field in fields(PreparedSyntheticIdentity) if field.init),
                         ("namespace_id", "loader_scope", "occurrence_indices", "rows",
                          "canonical_normalized_bytes"))

    def test_transform_paths_emit_no_io_or_application_state_events(self):
        active = {"value": False}
        attempts = []

        def guard(event, args):
            if active["value"] and (event in {"open", "import", "sqlite3.connect"}
                                    or event.startswith(("socket.", "subprocess.", "os."))):
                attempts.append(event)
                raise AssertionError("Unexpected transformer side effect")

        sys.addaudithook(guard)
        bodies = (fixture(), fixture([]))
        active["value"] = True
        try:
            self.prepare(bodies, occurrence_indices=(0, 1, 0))
            self.assert_failure(Code.INVALID_ARGUMENT, namespace_id=True)
            self.assert_failure(Code.MALFORMED_FIXTURE, (b"invalid",))
            self.assert_failure(Code.RESOURCE_LIMIT, occurrence_indices=(0,) * 4097)
        finally:
            active["value"] = False
        self.assertEqual(attempts, [])


if __name__ == "__main__":
    unittest.main()
