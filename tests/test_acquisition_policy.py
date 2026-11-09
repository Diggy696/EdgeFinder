"""Synthetic policy tests only. No provider, transport, resolver or live opt-in."""

import ast
from dataclasses import FrozenInstanceError, replace
import inspect
import sys
import unittest

from edgefinder.acquisition import contracts, policy
from edgefinder.acquisition.contracts import (
    AddressPolicyError, AddressRules, ArtifactDefinition, DefinitionError,
    PolicyError, RedirectPolicyError, URLPolicyError, URLRule, URLRules,
    ValidatedConnectionPlan, ValidatedURL,
)
from edgefinder.acquisition.policy import resolve_redirect, validate_addresses, validate_url


HOST = "artifacts.example.test"
PATH = "/releases/stats_player_week_2025.parquet"
URL = "https://" + HOST + PATH
RULES = URLRules((URLRule(HOST, PATH),))


class URLPolicyTests(unittest.TestCase):
    def test_exact_url_and_only_documented_equivalences(self):
        expected = ValidatedURL(HOST, PATH)
        for url in (URL, "HTTPS://" + HOST.upper() + PATH,
                    "https://" + HOST + ":443" + PATH):
            with self.subTest(url=url):
                actual = validate_url(url, rules=RULES)
                self.assertEqual(actual, expected)
                self.assertEqual(actual.url, URL)
                self.assertEqual((actual.scheme, actual.port), ("https", 443))

    def test_scheme_authority_and_port_rejections(self):
        for authority in ("", HOST + ":", HOST + ":80", HOST + ":444",
                          HOST + ":0443", HOST + ":+443", HOST + ":443:443",
                          HOST + ":https", HOST + ":65536", HOST + ":-1",
                          "[" + HOST + "]", "[::1]", "127.0.0.1", "127.1",
                          "2130706433", "0x7f000001", "0177.0.0.1"):
            with self.subTest(authority=authority), self.assertRaises(URLPolicyError):
                validate_url("https://" + authority + PATH, rules=RULES)
        for url in ("http://" + HOST + PATH, "ftp://" + HOST + PATH,
                    "//" + HOST + PATH, "https:" + PATH,
                    "https:///" + HOST + PATH, "https:////" + HOST + PATH):
            with self.subTest(url=url), self.assertRaises(URLPolicyError):
                validate_url(url, rules=RULES)

    def test_userinfo_including_empty_credentials_is_rejected(self):
        for userinfo in ("@", ":@", "name@", "name:synthetic@", "%40@", "@@"):
            with self.subTest(userinfo=userinfo), self.assertRaises(URLPolicyError):
                validate_url("https://" + userinfo + HOST + PATH, rules=RULES)

    def test_deceptive_and_noncanonical_hostnames(self):
        for host in (HOST + ".evil.test", "evil" + HOST, HOST + ".", "." + HOST,
                     "artifacts..example.test", "-artifacts.example.test",
                     "artifacts-.example.test", "artifacts_example.test", "*.example.test",
                     "artifact\u0455.example.test", "artifacts\u3002example.test",
                     "artifacts.example.test\uff1a443", "xn--bcher-kva.example.test",
                     "artifacts.example.123", "a" * 64 + ".test", "localhost"):
            with self.subTest(host=host), self.assertRaises(URLPolicyError):
                validate_url("https://" + host + PATH, rules=RULES)

    def test_ascii_hostname_boundaries(self):
        for host in ("a.test", "a-b.example.test", "a" * 63 + ".test"):
            rules = URLRules((URLRule(host, PATH),))
            self.assertEqual(validate_url("https://" + host + PATH, rules=rules).hostname, host)
        with self.assertRaises(DefinitionError):
            URLRule("a." * 125 + "test", PATH)

    def test_encoded_dot_empty_and_nonliteral_paths(self):
        for path in (PATH.lower().replace("stats", "%73tats"),
                     PATH.replace("/releases/", "/releases//"),
                     "/releases/./stats_player_week_2025.parquet",
                     "/other/../releases/stats_player_week_2025.parquet",
                     PATH + "/", PATH + ";x", PATH + "%2f", PATH + "%252f",
                     PATH + "%5c", PATH + "%00", PATH + "%zz", PATH + "\u00e9",
                     PATH.upper(), ""):
            with self.subTest(path=path), self.assertRaises(URLPolicyError):
                validate_url("https://" + HOST + path, rules=RULES)

    def test_whitespace_controls_and_backslashes_are_not_stripped(self):
        for character in (" ", "\t", "\r", "\n", "\x00", "\x1f", "\x7f", "\u00a0", "\\"):
            for url in (character + URL, URL + character, "https://" + HOST + character + PATH):
                with self.subTest(character=repr(character)), self.assertRaises(URLPolicyError):
                    validate_url(url, rules=RULES)

    def test_even_empty_queries_and_fragments_are_rejected(self):
        for suffix in ("?", "?download=1", "#", "#fragment", "?#"):
            with self.subTest(suffix=suffix), self.assertRaises(URLPolicyError):
                validate_url(URL + suffix, rules=RULES)

    def test_empty_rules_and_wrong_rule_types_fail_closed(self):
        for rules in (URLRules(), (), None, RULES.destinations):
            with self.subTest(rules=rules), self.assertRaises(URLPolicyError):
                validate_url(URL, rules=rules)

    def test_nontext_urls_rejected(self):
        for value in (None, b"https://example.test/file", 443, True):
            with self.subTest(value=value), self.assertRaises(URLPolicyError):
                validate_url(value, rules=RULES)


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.rules = URLRules((URLRule(HOST, PATH), URLRule(HOST, "/target.parquet"),
                               URLRule("cdn.example.test", "/target.parquet")))
        self.current = validate_url(URL, rules=self.rules)

    def test_permitted_relative_dot_root_absolute_and_scheme_relative(self):
        for location, expected in (
            ("../target.parquet", "https://" + HOST + "/target.parquet"),
            ("./stats_player_week_2025.parquet", URL),
            ("/target.parquet", "https://" + HOST + "/target.parquet"),
            ("https://cdn.example.test/target.parquet", "https://cdn.example.test/target.parquet"),
            ("//cdn.example.test:443/target.parquet", "https://cdn.example.test/target.parquet"),
        ):
            with self.subTest(location=location):
                self.assertEqual(resolve_redirect(self.current, location, rules=self.rules).url, expected)

    def test_unapproved_targets_never_inherit_source_permission(self):
        for location in ("other.parquet", "../other.parquet", "/other.parquet",
                         "https://evil.example.test/target.parquet",
                         "//evil.example.test/target.parquet",
                         "//cdn.example.test/other.parquet"):
            with self.subTest(location=location), self.assertRaises(RedirectPolicyError):
                resolve_redirect(self.current, location, rules=self.rules)

    def test_malformed_and_ambiguous_references_are_rejected_before_joining(self):
        for location in ("", None, b"/target.parquet", "http://" + HOST + "/target.parquet",
                         "https:../target.parquet", "https:/target.parquet", "///target.parquet",
                         "////cdn.example.test/target.parquet", "//:443/target.parquet",
                         "//user@cdn.example.test/target.parquet", "//cdn.example.test:/target.parquet",
                         "https://cdn.example.test/a/../target.parquet",
                         "../a//../target.parquet", "/bad;segment/../target.parquet",
                         "/bad|segment/../target.parquet", "/%74arget.parquet", "/target.parquet?",
                         "#fragment", " /target.parquet", "/target.parquet\n", "\\target.parquet"):
            with self.subTest(location=location), self.assertRaises(RedirectPolicyError):
                resolve_redirect(self.current, location, rules=self.rules)

    def test_current_url_must_match_current_rules(self):
        for current in (URL, None, ValidatedURL("unlisted.example.test", PATH)):
            with self.subTest(current=current), self.assertRaises(RedirectPolicyError):
                resolve_redirect(current, "/target.parquet", rules=self.rules)


class AddressTests(unittest.TestCase):
    def setUp(self):
        self.url = validate_url(URL, rules=RULES)
        self.policy = AddressRules()

    def test_native_public_answers_form_deterministic_plan_without_resolution(self):
        # Numeric fixture values only: these addresses are never contacted.
        answers = ("2606:4700:4700::1111", "8.8.8.8", "1.1.1.1", "8.8.8.8")
        plan = validate_addresses(self.url, answers, policy=self.policy)
        self.assertEqual(plan.addresses, ("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"))
        self.assertEqual(plan.selected_address, "1.1.1.1")
        self.assertEqual(plan.tls_hostname, HOST)
        self.assertEqual(plan.url, self.url)
        self.assertEqual(plan, validate_addresses(self.url, tuple(reversed(answers)), policy=self.policy))

    def test_native_ipv6_normalization(self):
        plan = validate_addresses(self.url, ("2001:4860:4860:0000:0000:0000:0000:8888",), policy=self.policy)
        self.assertEqual(plan.selected_address, "2001:4860:4860::8888")

    def test_ipv4_denied_categories_and_boundaries(self):
        for address in ("0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.0", "100.127.255.255",
                        "127.0.0.1", "169.254.169.254", "172.16.0.0", "172.31.255.255",
                        "192.0.0.9", "192.0.0.10", "192.0.2.1", "192.88.99.1", "192.168.1.1",
                        "198.18.0.0", "198.19.255.255", "198.51.100.1", "203.0.113.1",
                        "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255"):
            with self.subTest(address=address), self.assertRaises(AddressPolicyError):
                validate_addresses(self.url, (address,), policy=self.policy)
        for address in ("100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0"):
            with self.subTest(address=address):
                self.assertEqual(validate_addresses(self.url, (address,), policy=self.policy).selected_address, address)

    def test_ipv6_local_reserved_documentation_and_transition_ranges(self):
        for address in ("::", "::1", "fc00::1", "fdff::1", "fe80::1", "ff02::1", "fec0::1",
                        "2001:db8::1", "3fff::1", "3ffe::1", "4000::1", "100::1",
                        "::ffff:8.8.8.8", "::ffff:127.0.0.1", "::8.8.8.8",
                        "64:ff9b::808:808", "64:ff9b:1::808:808", "2002:0808:0808::1",
                        "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:20::1",
                        "2001:4860:1:2:0:5efe:808:808", "2001:4860:1:2:200:5efe:808:808"):
            with self.subTest(address=address), self.assertRaises(AddressPolicyError):
                validate_addresses(self.url, (address,), policy=self.policy)

    def test_empty_malformed_and_nonstring_answers(self):
        for answers in ((), [], ["8.8.8.8"], "8.8.8.8", None, (None,), (True,), (1,),
                        (b"8.8.8.8",), ("",), ("example.test",), ("8.8.8.8 ",),
                        ("8.8.8.8/32",), ("008.8.8.8",), ("2130706433",), ("1.2.3.256",),
                        ("[2001:4860::1]",), ("2001:4860::1%scope",), ("\u0661.1.1.1",)):
            with self.subTest(answers=answers), self.assertRaises(AddressPolicyError):
                validate_addresses(self.url, answers, policy=self.policy)

    def test_mixed_answers_are_rejected_in_either_order(self):
        for unsafe in ("127.0.0.1", "100.64.0.1", "2001:db8::1", "::ffff:8.8.8.8", "malformed"):
            for answers in (("8.8.8.8", unsafe), (unsafe, "8.8.8.8")):
                with self.subTest(answers=answers), self.assertRaises(AddressPolicyError):
                    validate_addresses(self.url, answers, policy=self.policy)

    def test_additional_denials_only_tighten_baseline(self):
        policy = AddressRules(("8.8.8.0/24", "2001:4860::/32"))
        for address in ("8.8.8.8", "2001:4860:4860::8888", "127.0.0.1"):
            with self.subTest(address=address), self.assertRaises(AddressPolicyError):
                validate_addresses(self.url, (address,), policy=policy)
        self.assertEqual(validate_addresses(self.url, ("1.1.1.1",), policy=policy).selected_address, "1.1.1.1")

    def test_wrong_contract_types_fail_closed(self):
        for url, policy in ((URL, self.policy), (self.url, None), (self.url, ())):
            with self.subTest(url=url, policy=policy), self.assertRaises(AddressPolicyError):
                validate_addresses(url, ("8.8.8.8",), policy=policy)


class ContractAndSafetyTests(unittest.TestCase):
    def test_candidate_metadata_never_confers_live_permission(self):
        candidate = ArtifactDefinition(
            "nflverse.stats_player.week.2025", "nflverse",
            "https://github.com/nflverse/nflverse-data/releases/download/"
            "stats_player/stats_player_week_2025.parquet", "parquet", "season=2025; summary_level=week")
        self.assertEqual(candidate.endpoint_status, "source_derived_unverified")
        for rules in (URLRules(), candidate):
            with self.subTest(rules=rules), self.assertRaises(URLPolicyError):
                validate_url(candidate.candidate_url, rules=rules)
        self.assertFalse(hasattr(candidate, "live_authorization"))
        self.assertFalse(hasattr(candidate, "allow_network"))

    def test_every_contract_is_frozen_and_hashable(self):
        candidate = ArtifactDefinition("fixture", "synthetic", URL, "parquet", "invented")
        url = validate_url(URL, rules=RULES)
        plan = validate_addresses(url, ("8.8.8.8",), policy=AddressRules())
        for value, name in ((candidate, "scope"), (RULES.destinations[0], "path"),
                            (RULES, "destinations"), (AddressRules(), "additional_denied_networks"),
                            (url, "hostname"), (plan, "addresses")):
            with self.subTest(contract=type(value).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, name, "changed")
                self.assertIsInstance(hash(value), int)

    def test_rule_order_and_duplicates_have_explicit_semantics(self):
        other = URLRule("cdn.example.test", "/target.parquet")
        self.assertEqual(URLRules((RULES.destinations[0], other)), URLRules((other, RULES.destinations[0])))
        with self.assertRaises(DefinitionError):
            URLRules((other, other))
        self.assertEqual(AddressRules(("8.8.8.0/24", "1.1.1.0/24", "8.8.8.0/24")),
                         AddressRules(("1.1.1.0/24", "8.8.8.0/24")))

    def test_invalid_contract_construction(self):
        factories = (
            lambda: URLRule(HOST.upper(), PATH), lambda: URLRule("*.example.test", PATH),
            lambda: URLRule("xn--bcher-kva.test", PATH), lambda: URLRule(HOST, "/%61"),
            lambda: URLRules([URLRule(HOST, PATH)]), lambda: URLRules((URL,)),
            lambda: AddressRules(["8.8.8.0/24"]), lambda: AddressRules((None,)),
            lambda: AddressRules(("8.8.8.1/24",)), lambda: AddressRules(("8.8.8.8",)),
            lambda: AddressRules(("2001:4860::%x/32",)),
            lambda: AddressRules(("2001:4860:0000::/32",)),
            lambda: ValidatedURL(HOST, "/a/../b"),
            lambda: ArtifactDefinition("", "synthetic", URL, "parquet", "scope"),
            lambda: ArtifactDefinition("fixture", "synthetic", URL, "parquet", " scope"),
            lambda: ArtifactDefinition("fixture", "synthetic", "http://example.test/file", "parquet", "scope"),
        )
        for factory in factories:
            with self.subTest(factory=factory), self.assertRaises(DefinitionError):
                factory()
        with self.assertRaises(AddressPolicyError):
            ValidatedConnectionPlan(ValidatedURL(HOST, PATH), ("127.0.0.1",), AddressRules())

    def test_replace_revalidates_instead_of_bypassing_policy(self):
        with self.assertRaises(DefinitionError):
            replace(RULES.destinations[0], path="/%2f")
        plan = validate_addresses(validate_url(URL, rules=RULES), ("8.8.8.8",), policy=AddressRules())
        with self.assertRaises(AddressPolicyError):
            replace(plan, addresses=("127.0.0.1",))

    def test_errors_are_typed_and_do_not_echo_url_credentials(self):
        with self.assertRaises(URLPolicyError) as caught:
            validate_url("https://user:synthetic-secret@" + HOST + PATH, rules=RULES)
        self.assertIsInstance(caught.exception, PolicyError)
        self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_import_surface_contains_only_expected_pure_dependencies(self):
        allowed = {"dataclasses", "ipaddress", "re", "urllib.parse", "contracts"}
        for module in (contracts, policy):
            tree = ast.parse(inspect.getsource(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module]
                else:
                    continue
                self.assertTrue(set(names) <= allowed, names)

    def test_policy_calls_emit_no_network_dns_import_or_file_events(self):
        # Audit hook remains installed but becomes inert after this test.
        state = {"active": True}
        attempts = []

        def audit(event, args):
            if state["active"] and (event == "open" or event == "import"
                                    or event.startswith(("socket.", "subprocess.", "os."))):
                attempts.append(event)
                raise AssertionError("Unexpected I/O/import during pure policy evaluation")

        sys.addaudithook(audit)
        try:
            candidate = ArtifactDefinition("fixture", "synthetic", URL, "parquet", "invented")
            url = validate_url(candidate.candidate_url, rules=RULES)
            self.assertEqual(resolve_redirect(url, "./stats_player_week_2025.parquet", rules=RULES), url)
            self.assertEqual(validate_addresses(url, ("8.8.8.8",), policy=AddressRules()).tls_hostname, HOST)
            with self.assertRaises(AddressPolicyError):
                validate_addresses(url, ("127.0.0.1",), policy=AddressRules())
            with self.assertRaises(URLPolicyError):
                validate_url(URL + "?", rules=RULES)
        finally:
            state["active"] = False
        self.assertEqual(attempts, [])


if __name__ == "__main__":
    unittest.main()
