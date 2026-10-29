"""                                                                        

                                                                          
                                                                            
                                                                                

                                                                           
"""

from copy import deepcopy
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import word_reference as model


DEMO_PSL = """// Synthetic PSL subset, not a production suffix list.
com
net
co.uk
*.ck
!www.ck
// ===BEGIN PRIVATE DOMAINS===
blogspot.com
"""


def exact_config(**overrides):
    config = {
        "mode": "exact_distinct_diagnostic",
        "window_seconds": 10,
        "window_anchor_ns": 0,
        "heavy_domains": [],
        "heavy_domains_provenance": "Explicit synthetic test list only",
        "input_capture_scope": "Synthetic query and actual-response-shaped events",
        "seed": "demonstration-test-seed-not-production",
        "domain_mapping_provenance": "Synthetic PSL subset in this test file",
        "psl_private_rules": "include",
        "comparison_status": "assumption_bound_reconstruction",
        "exact_threshold": 2,
    }
    config.update(overrides)
    return config


def coupon_demo_config(**overrides):
                                                                          
    config = exact_config(
        mode="coupon_reconstruction", coupon_types=1, coupon_threshold=1,
        inverse_coupon_probability=1, first_coupon_keep_probability=1.0,
    )
    config.pop("exact_threshold")
    config.update(overrides)
    return config


def event(name="a.example.com", *, second=0, response=False, rcode=0,
          client="192.0.2.1", server="198.51.100.53", client_port=53000,
          dns_id=7, qtype=1, qclass=1, frame_no=1):
    result = {
        "time_ns": second * model.NS,
        "kind": "response" if response else "query",
        "qname": name,
        "src": server if response else client,
        "dst": client if response else server,
        "sport": 53 if response else client_port,
        "dport": client_port if response else 53,
        "transport": "udp",
        "dns_id": dns_id,
        "qtype": qtype,
        "qclass": qclass,
        "frame_no": frame_no,
    }
    if response:
        result["rcode"] = rcode
    return result


def reference(config=None):
    config = config or exact_config()
    return model.Reference(config, model.PublicSuffix(DEMO_PSL,
                                                     private_rules=config["psl_private_rules"]))


def summary(ref, *, domain="example.com", window=0):
    return next(item for item in ref.result()["domains"]
                if item["domain"] == domain and item["window_index"] == window)


class ReferenceBehaviorTests(unittest.TestCase):
    def test_ordinary_domain_counts_queries_not_response_names(self):
        ref = reference()
        ref.consume(event("a.example.com", second=0))
        ref.consume(event("response-only.example.com", second=1,
                          response=True, rcode=3))
        ref.consume(event("another-response.example.com", second=2,
                          response=True, rcode=0))
        self.assertEqual(ref.result()["alert_count"], 0)
        self.assertEqual(summary(ref)["eligible_distinct_subdomains"], 1)
        ref.consume(event("b.example.com", second=3, frame_no=4))
        result = ref.result()
        self.assertEqual(result["alert_count"], 1)
        self.assertEqual(result["alerts"][0]["time_ns"], 3 * model.NS)
        self.assertEqual(result["alerts"][0]["domain_query_ordinal"], 2)
        self.assertEqual(summary(ref)["query_events"], 2)
        self.assertEqual(summary(ref)["response_events"], 2)
        self.assertEqual(summary(ref)["eligible_events"], 2)

    def test_heavy_domain_uses_only_actual_full_rcode_three(self):
        ref = reference(exact_config(heavy_domains=["example.com"]))
        for index in range(3):
            ref.consume(event(f"query{index}.example.com", second=index))
        # SERVFAIL, NOERROR, and extended RCODE 19 must not become NXDOMAIN.
        for second, rcode in enumerate((2, 0, 19), start=3):
            ref.consume(event(f"non-nx{second}.example.com", second=second,
                              response=True, rcode=rcode))
        self.assertEqual(summary(ref)["eligible_events"], 0)
        self.assertEqual(ref.result()["alert_count"], 0)
        ref.consume(event("nx1.example.com", second=6, response=True, rcode=3))
        self.assertEqual(ref.result()["alert_count"], 0)
        ref.consume(event("nx2.example.com", second=7, response=True, rcode=3))
        result = ref.result()
        self.assertEqual(result["alert_count"], 1)
        self.assertTrue(result["alerts"][0]["heavy"])
        self.assertEqual(summary(ref)["nxdomain_response_events"], 2)
        self.assertEqual(summary(ref)["eligible_distinct_subdomains"], 2)
        self.assertEqual(result["audit"]["response_rcode_19"], 1)
        self.assertEqual(result["audit"]["response_rcode_2"], 1)

    def test_future_responses_never_change_an_earlier_prefix(self):
        ref = reference(exact_config(heavy_domains=["example.com"]))
        ref.consume(event("a.example.com", second=0))
        ref.consume(event("b.example.com", second=1))
        prefix = deepcopy(ref.result())
        self.assertEqual(prefix["alert_count"], 0)
        self.assertEqual(prefix["domains"][0]["nxdomain_response_events"], 0)
        ref.consume(event("a.example.com", second=4, response=True, rcode=3))
        self.assertEqual(ref.result()["alert_count"], 0)
        ref.consume(event("b.example.com", second=5, response=True, rcode=3,
                          frame_no=4))
        alert = ref.result()["alerts"][0]
        self.assertEqual(alert["time_ns"], 5 * model.NS)
        self.assertEqual(alert["event_ordinal"], 4)
        self.assertEqual(alert["frame_no"], 4)
        self.assertEqual(prefix["alerts"], [])

    def test_unanswered_queries_are_not_errors_or_nxdomain(self):
        ref = reference(exact_config(heavy_domains=["example.com"]))
        for index in range(3):
            ref.consume(event(f"unanswered{index}.example.com", second=index))
        result = ref.result()
        self.assertEqual(result["unmatched_query_observations_at_end"], 3)
        self.assertEqual(result["alert_count"], 0)
        self.assertEqual(result["audit"].get("response_events", 0), 0)
        self.assertEqual(summary(ref)["nxdomain_response_events"], 0)
        self.assertEqual(summary(ref)["response_evidence_status"],
                         "no_responses_observed_not_evidence_of_NOERROR")
        self.assertTrue(any("No DNS responses" in note for note in result["limitations"]))

    def test_tumbling_window_resets_distinct_and_alert_state(self):
        ref = reference()
        ref.consume(event("a.example.com", second=0))
        ref.consume(event("b.example.com", second=9))
        self.assertEqual(ref.result()["alert_count"], 1)
        ref.consume(event("a.example.com", second=10))
        self.assertEqual(ref.result()["alert_count"], 1)
        self.assertEqual(summary(ref, window=1)["eligible_distinct_subdomains"], 1)
        ref.consume(event("b.example.com", second=11))
        alerts = ref.result()["alerts"]
        self.assertEqual([item["window_index"] for item in alerts], [0, 1])
        self.assertEqual([item["time_ns"] for item in alerts], [9 * model.NS, 11 * model.NS])
        self.assertEqual(summary(ref, window=0)["query_events"], 2)
        self.assertEqual(summary(ref, window=1)["query_events"], 2)

    def test_response_counts_at_arrival_window_and_matches_earlier_query(self):
        ref = reference(exact_config(heavy_domains=["example.com"], exact_threshold=1))
        ref.consume(event("a.example.com", second=9))
        ref.consume(event("a.example.com", second=10, response=True, rcode=3))
        self.assertEqual(summary(ref, window=0)["eligible_events"], 0)
        self.assertEqual(summary(ref, window=1)["eligible_events"], 1)
        self.assertEqual(ref.result()["alerts"][0]["window_index"], 1)
        self.assertEqual(ref.result()["audit"]["responses_with_unique_preceding_query"], 1)

    def test_explicit_window_anchor_and_clock_reversal(self):
        ref = reference(exact_config(window_anchor_ns=5 * model.NS))
        ref.consume(event("a.example.com", second=5))
        ref.consume(event("b.example.com", second=14))
        self.assertEqual(ref.result()["alerts"][0]["window_index"], 0)
        ref.consume(event("a.example.com", second=15))
        before = deepcopy(ref.result())
        with self.assertRaisesRegex(ValueError, "out of time order"):
            ref.consume(event("b.example.com", second=14))
        self.assertEqual(ref.result(), before)
        with self.assertRaisesRegex(ValueError, "window anchor"):
            reference(exact_config(window_anchor_ns=5 * model.NS)).consume(event(second=4))

    def test_repeated_names_count_observations_but_not_new_distinct_names(self):
        ref = reference()
        for second in range(3):
            ref.consume(event("SAME.Example.COM", second=second))
        self.assertEqual(ref.result()["alert_count"], 0)
        self.assertEqual(summary(ref)["eligible_events"], 3)
        self.assertEqual(summary(ref)["eligible_distinct_subdomains"], 1)
        ref.consume(event("new.example.com", second=3))
        self.assertEqual(ref.result()["alert_count"], 1)
        self.assertEqual(ref.result()["alerts"][0]["eligible_ordinal"], 4)

    def test_source_ip_count_does_not_change_domain_detection(self):
        single = reference()
        distributed = reference()
        for index in range(4):
            single.consume(event(f"name{index}.example.com", second=index,
                                 client="192.0.2.1", frame_no=index + 1))
            distributed.consume(event(f"name{index}.example.com", second=index,
                                      client=f"192.0.2.{index + 1}", frame_no=index + 1))
        self.assertEqual(single.result()["alerts"], distributed.result()["alerts"])
        self.assertEqual(single.result()["domains"], distributed.result()["domains"])

    def test_apex_and_public_suffix_events_do_not_add_subdomain_diversity(self):
        ref = reference(exact_config(exact_threshold=1))
        ref.consume(event("example.com", second=0))
        ref.consume(event("com", second=1))
        ref.consume(event(".", second=2))
        self.assertEqual(ref.result()["alert_count"], 0)
        self.assertEqual(summary(ref)["eligible_events"], 0)
        self.assertEqual(ref.result()["audit"]["apex_events_excluded_from_distinct_count"], 1)
        self.assertEqual(ref.result()["audit"]["no_registrable_domain"], 2)


class DomainMappingTests(unittest.TestCase):
    def test_psl_exact_wildcard_exception_private_and_default_rules(self):
        psl = model.PublicSuffix(DEMO_PSL)
        cases = {
            "a.example.com": "example.com",
            "a.example.co.uk": "example.co.uk",
            "a.b.ck": "a.b.ck",
            "b.ck": None,
            "www.ck": "www.ck",
            "a.www.ck": "www.ck",
            "a.owner.blogspot.com": "owner.blogspot.com",
            "blogspot.com": None,
            "a.internal": "a.internal",
            "internal": None,
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                domain = psl.domain(model.name_labels(name))
                self.assertEqual(None if domain is None else model.presentation(domain), expected)

    def test_private_suffix_keeps_tenants_separate(self):
        ref = reference(exact_config(exact_threshold=2))
        ref.consume(event("a.one.blogspot.com", second=0))
        ref.consume(event("a.two.blogspot.com", second=1))
        self.assertEqual(ref.result()["alert_count"], 0)
        self.assertEqual({item["domain"] for item in ref.result()["domains"]},
                         {"one.blogspot.com", "two.blogspot.com"})

    def test_explicit_private_exclusion_groups_below_icann_suffix(self):
        ref = reference(exact_config(psl_private_rules="exclude"))
        ref.consume(event("a.one.blogspot.com", second=0))
        ref.consume(event("a.two.blogspot.com", second=1))
        self.assertEqual([item["domain"] for item in ref.result()["domains"]],
                         ["blogspot.com"])
        self.assertEqual(ref.result()["alert_count"], 1)

    def test_psl_private_policy_must_match_loaded_rules(self):
        with self.assertRaisesRegex(ValueError, "policy does not match"):
            model.Reference(exact_config(psl_private_rules="exclude"),
                            model.PublicSuffix(DEMO_PSL, private_rules="include"))

    def test_heavy_private_suffix_requires_explicit_grouping_override(self):
        config = exact_config(heavy_domains=["blogspot.com"], exact_threshold=1)
        with self.assertRaisesRegex(ValueError, "cannot be selected"):
            reference(config)
        config["domain_overrides"] = ["blogspot.com"]
        ref = reference(config)
        ref.consume(event("a.tenant.blogspot.com", second=0))
        self.assertEqual(ref.result()["alert_count"], 0)
        ref.consume(event("a.tenant.blogspot.com", second=1, response=True, rcode=3))
        self.assertEqual(ref.result()["alerts"][0]["domain"], "blogspot.com")
        self.assertTrue(ref.result()["alerts"][0]["heavy"])

    def test_heavy_private_suffix_can_use_explicit_private_exclusion(self):
        ref = reference(exact_config(heavy_domains=["blogspot.com"],
                                     psl_private_rules="exclude", exact_threshold=1))
        ref.consume(event("a.tenant.blogspot.com", second=0, response=True, rcode=3))
        self.assertEqual(ref.result()["alerts"][0]["domain"], "blogspot.com")
        self.assertTrue(ref.result()["alerts"][0]["heavy"])

    def test_escaped_label_dot_is_not_a_domain_separator(self):
        labels = model.name_labels(r"A\046B.Example.COM")
        self.assertEqual(labels, (b"a.b", b"example", b"com"))
        self.assertEqual(model.presentation(labels), r"a\046b.example.com")
        ref = reference()
        ref.consume(event(r"a\046b.example.com", second=0))
        ref.consume(event("a.b.example.com", second=1))
        self.assertEqual(summary(ref)["eligible_distinct_subdomains"], 2)
        self.assertEqual(ref.result()["alert_count"], 1)

    def test_malformed_presentation_names_are_rejected(self):
        for name in ("a..example.com", r"a\999.example.com", r"a\x.example.com",
                     "é.example.com", "a" * 64 + ".example.com"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                model.name_labels(name)


class CouponDemonstrationTests(unittest.TestCase):
    def test_first_coupon_probability_zero_never_starts_tracking(self):
        ref = reference(coupon_demo_config(first_coupon_keep_probability=0.0))
        for second in range(3):
            ref.consume(event("repeat.example.com", second=second))
        state = summary(ref)
        self.assertEqual(ref.result()["alert_count"], 0)
        self.assertEqual(state["coupons"], 0)
        self.assertEqual(state["eligible_events"], 3)
        self.assertEqual(state["eligible_distinct_subdomains"], 1)
        self.assertEqual(state["post_first_coupon"],
                         {"applicable": True, "start_ns": None,
                          "queries": 0, "responses": 0, "nxdomain": 0})
        self.assertEqual(ref.result()["audit"]["first_coupon_rejections"], 3)

    def test_first_coupon_probability_one_starts_on_eligible_packet(self):
        ref = reference(coupon_demo_config())
        ref.consume(event("untracked.example.com", second=0, response=True, rcode=0))
        ref.consume(event("first.example.com", second=1))
        ref.consume(event("first.example.com", second=2, response=True, rcode=3))
        ref.consume(event("second.example.com", second=3))
        result = ref.result()
        self.assertEqual(result["alert_count"], 1)
        self.assertEqual(result["alerts"][0]["time_ns"], model.NS)
        self.assertEqual(result["alerts"][0]["coupon_count"], 1)
        self.assertEqual(summary(ref)["post_first_coupon"],
                         {"applicable": True, "start_ns": model.NS,
                          "queries": 2, "responses": 1, "nxdomain": 1})

    def test_probability_one_keeps_maximum_digest_without_float_rounding(self):
        ref = reference(coupon_demo_config())
        def extreme_digest(purpose, value):
            return b"\xff" * 32 if purpose == b"first-coupon-coin" else b"\x00" * 32
        with patch.object(ref, "digest", side_effect=extreme_digest):
            ref.consume(event())
        self.assertEqual(ref.result()["alert_count"], 1)
        self.assertEqual(ref.result()["audit"].get("first_coupon_rejections", 0), 0)

    def test_repeated_subdomain_does_not_collect_additional_coupon_types(self):
        cfg = coupon_demo_config(coupon_types=2, coupon_threshold=2,
                                 inverse_coupon_probability=2)
        ref = reference(cfg)
        first = "repeated"
        first_coupon = ref.coupon(model.name_labels(first))
        other = next(f"candidate{index}" for index in range(100)
                     if ref.coupon(model.name_labels(f"candidate{index}")) != first_coupon)
        for second in range(3):
            ref.consume(event(first + ".example.com", second=second))
        self.assertEqual(summary(ref)["coupons"], 1)
        self.assertEqual(ref.result()["alert_count"], 0)
        ref.consume(event(other + ".example.com", second=3))
        self.assertEqual(summary(ref)["coupons"], 2)
        self.assertEqual(ref.result()["alert_count"], 1)

    def test_coupon_state_and_first_coupon_tracking_reset_by_window(self):
        ref = reference(coupon_demo_config())
        ref.consume(event("same.example.com", second=0))
        ref.consume(event("same.example.com", second=10))
        self.assertEqual([item["window_index"] for item in ref.result()["alerts"]], [0, 1])
        self.assertEqual(summary(ref, window=0)["post_first_coupon"]["queries"], 1)
        self.assertEqual(summary(ref, window=1)["post_first_coupon"]["start_ns"], 10 * model.NS)


class ResponseMatchingTests(unittest.TestCase):
    def test_dns_id_collision_does_not_match_another_question_name(self):
        ref = reference()
        ref.consume(event("a.example.com", second=0, dns_id=99))
        ref.consume(event("b.example.com", second=1, dns_id=99))
        ref.consume(event("c.example.com", second=2, dns_id=99, response=True))
        self.assertEqual(ref.result()["unmatched_query_observations_at_end"], 2)
        ref.consume(event("b.example.com", second=3, dns_id=99, response=True))
        ref.consume(event("a.example.com", second=4, dns_id=99, response=True))
        audit = ref.result()["audit"]
        self.assertEqual(audit["responses_without_preceding_query"], 1)
        self.assertEqual(audit["responses_with_unique_preceding_query"], 2)
        self.assertEqual(ref.result()["unmatched_query_observations_at_end"], 0)

    def test_matching_includes_endpoint_question_type_and_class(self):
        for changed_field, changed_value in (("client", "192.0.2.2"),
                                             ("server", "198.51.100.54"),
                                             ("client_port", 53001),
                                             ("qtype", 28), ("qclass", 3)):
            with self.subTest(field=changed_field):
                ref = reference()
                ref.consume(event(second=0))
                ref.consume(event(second=1, response=True, **{changed_field: changed_value}))
                self.assertEqual(ref.result()["unmatched_query_observations_at_end"], 1)
                self.assertEqual(ref.result()["audit"]["responses_without_preceding_query"], 1)

    def test_repeated_query_key_is_ambiguous_and_repeated_response_is_unmatched(self):
        ref = reference()
        ref.consume(event(second=0))
        ref.consume(event(second=1))
        ref.consume(event(second=2, response=True, rcode=0))
        ref.consume(event(second=3, response=True, rcode=0))
        result = ref.result()
        audit = result["audit"]
        self.assertEqual(audit["repeated_outstanding_query_key"], 1)
        self.assertEqual(audit["responses_with_ambiguous_preceding_queries"], 1)
        self.assertEqual(audit["query_observations_in_ambiguous_groups"], 2)
        self.assertEqual(audit["responses_without_preceding_query"], 1)
        self.assertEqual(audit.get("responses_with_unique_preceding_query", 0), 0)
        self.assertEqual(result["unmatched_query_observations_at_end"], 0)
        self.assertEqual(audit["query_events"], 2)
        self.assertEqual(audit["response_events"], 2)
        self.assertEqual(summary(ref)["nxdomain_response_events"], 0)

    def test_response_before_query_is_not_retroactively_matched(self):
        ref = reference()
        ref.consume(event(second=0, response=True, rcode=0))
        ref.consume(event(second=1))
        self.assertEqual(ref.result()["audit"]["responses_without_preceding_query"], 1)
        self.assertEqual(ref.result()["unmatched_query_observations_at_end"], 1)


class ConfigurationAndApiTests(unittest.TestCase):
    def test_missing_explicit_config_fields_are_rejected(self):
        required = ("mode", "window_seconds", "window_anchor_ns", "heavy_domains",
                    "heavy_domains_provenance", "input_capture_scope", "seed",
                    "domain_mapping_provenance", "psl_private_rules", "comparison_status")
        for key in required:
            with self.subTest(missing=key):
                config = exact_config()
                del config[key]
                with self.assertRaisesRegex(ValueError, "Explicit config required"):
                    model.Reference(config, model.PublicSuffix(DEMO_PSL))

    def test_malformed_configuration_is_rejected(self):
        invalid = (
            {"mode": "original_word"}, {"window_seconds": 0},
            {"window_seconds": True}, {"window_anchor_ns": 0.0},
            {"heavy_domains": "example.com"}, {"seed": 7},
            {"heavy_domains_provenance": " "}, {"input_capture_scope": ""},
            {"domain_mapping_provenance": None}, {"comparison_status": "validated"},
            {"psl_private_rules": "guess"},
            {"exact_threshold": 0}, {"exact_threshold": True},
        )
        for override in invalid:
            with self.subTest(override=override), self.assertRaises(ValueError):
                model.Reference(exact_config(**override), model.PublicSuffix(DEMO_PSL))

    def test_malformed_coupon_demonstration_settings_are_rejected(self):
        invalid = (
            {"coupon_types": 0}, {"coupon_threshold": 2},
            {"inverse_coupon_probability": 3},
            {"inverse_coupon_probability": 2**257},
            {"first_coupon_keep_probability": -0.1},
            {"first_coupon_keep_probability": 1.1},
            {"first_coupon_keep_probability": "1"},
            {"first_coupon_keep_probability": float("nan")},
        )
        for override in invalid:
            with self.subTest(override=override), self.assertRaises(ValueError):
                model.Reference(coupon_demo_config(**override), model.PublicSuffix(DEMO_PSL))
        config = coupon_demo_config()
        del config["first_coupon_keep_probability"]
        with self.assertRaises(ValueError):
            model.Reference(config, model.PublicSuffix(DEMO_PSL))

    def test_query_rcode_and_missing_or_malformed_response_rcode_are_rejected(self):
        manufactured = event()
        manufactured["rcode"] = 3
        missing_response_rcode = event(response=True)
        del missing_response_rcode["rcode"]
        invalid = [manufactured, missing_response_rcode]
        invalid.extend(event(response=True, rcode=value)
                       for value in (None, "3", True, -1, 4096))
        for item in invalid:
            with self.subTest(event=item), self.assertRaises(ValueError):
                reference().consume(item)

    def test_result_api_is_repeatable_and_marks_scope(self):
        ref = reference()
        ref.consume(event())
        first = deepcopy(ref.result())
        self.assertEqual(ref.result(), first)
        self.assertEqual(first["model_label"], model.LABEL)
        self.assertEqual(first["status"], "OFFLINE_REFERENCE_COMPLETE_NOT_DATASET_VALIDATION")
        self.assertIn("response counted at its arrival", first["window_semantics"])
        self.assertIn("not DNS errors", first["matching_note"])
        self.assertTrue(any("No packet suppression" in note for note in first["limitations"]))
        self.assertTrue(any("No DNS responses" in note for note in first["limitations"]))
        self.assertTrue(any("empty heavy-domain list" in note for note in first["limitations"]))
        self.assertNotIn("suppression", first)
        self.assertFalse(first["domains"][0]["post_first_coupon"]["applicable"])
        json.dumps(first)                                                    

    def test_cli_reads_gzip_events_and_records_input_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            events_path = directory / "synthetic.events.jsonl.gz"
            config_path = directory / "synthetic.config.json"
            psl_path = directory / "synthetic.psl.txt"
            output_path = directory / "result.json"
            events_text = "\n".join(json.dumps(item) for item in
                                    (event("a.example.com", second=0),
                                     event("b.example.com", second=1))) + "\n"
            events_path.write_bytes(gzip.compress(events_text.encode()))
            config_path.write_text(json.dumps(exact_config()), encoding="utf-8")
            psl_path.write_text(DEMO_PSL, encoding="utf-8")
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            process = subprocess.run(
                [sys.executable, str(Path(model.__file__).resolve()),
                 "--events", str(events_path), "--config", str(config_path),
                 "--psl", str(psl_path), "--out", str(output_path)],
                text=True, capture_output=True, env=environment,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(result["audit"]["query_events"], 2)
            self.assertEqual(result["alert_count"], 1)
            self.assertEqual(result["input_sha256"]["events"],
                             hashlib.sha256(events_path.read_bytes()).hexdigest())
            self.assertEqual(set(result["input_sha256"]),
                             {"events", "config", "psl", "reference_source"})


if __name__ == "__main__":
    unittest.main()
