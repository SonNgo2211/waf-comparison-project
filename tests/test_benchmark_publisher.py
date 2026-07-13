import json
import os
import unittest
from unittest.mock import patch

from benchmark_publisher import (
    build_evaluation_payload,
    normalize_attack_category,
    prepare_benchmark_session,
    runtime_identity_matches,
)


class BenchmarkPublisherTests(unittest.TestCase):
    @patch("benchmark_publisher.urllib.request.urlopen")
    def test_session_is_requested_from_training_server(self, urlopen):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps({
                    "session": {
                        "session_id": "session-a",
                        "candidate_version": "shadow-v2",
                        "identity": {"model_version": "active-v1"},
                    }
                }).encode("utf-8")

        urlopen.return_value = Response()
        previous = os.environ.get("TRAINING_SERVER_URL")
        os.environ["TRAINING_SERVER_URL"] = "http://training.test"
        try:
            session = prepare_benchmark_session()
        finally:
            if previous is None:
                os.environ.pop("TRAINING_SERVER_URL", None)
            else:
                os.environ["TRAINING_SERVER_URL"] = previous
        self.assertEqual(session["session_id"], "session-a")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://training.test/api/v1/benchmark/sessions")
        self.assertNotIn("runtime-bundle", request.full_url)

    def test_maps_wcp_categories_to_gate_categories(self):
        self.assertEqual(normalize_attack_category("cmdexe"), "rce")
        self.assertEqual(normalize_attack_category("shellshock"), "rce")
        self.assertEqual(normalize_attack_category("traversal"), "path_traversal")
        self.assertEqual(normalize_attack_category("sqli"), "sqli")

    def test_aggregates_multiple_rce_corpora(self):
        payload = build_evaluation_payload(
            identity={
                "model_version": "v2",
                "active_bundle_id": "bundle-a",
                "runtime_content_id": "content-a",
                "runtime_policy_sha256": "policy-a",
                "benchmark_session_id": "session-a",
                "candidate_version": "shadow-v3",
                "namespace": "default",
                "app": "dvwa",
            },
            waf_name="Whackers NginxWAF",
            db_sha256="a" * 64,
            counts={"tp": 20, "fp": 1, "tn": 99, "fn": 5},
            category_rows=[("cmdexe", 4, 1), ("shellshock", 5, 2), ("xss", 11, 2)],
            latency={"p95_ms": 12.0, "p99_ms": 20.0},
            evaluated_at=1000,
        )
        self.assertEqual(payload["attack_types"]["rce"], {"tp": 9, "fn": 3})
        self.assertEqual(payload["attack_types"]["xss"], {"tp": 11, "fn": 2})
        self.assertEqual(payload["metadata"]["runtime_content_id"], "content-a")
        self.assertEqual(payload["metadata"]["runtime_policy_sha256"], "policy-a")
        self.assertEqual(payload["benchmark_session_id"], "session-a")
        self.assertEqual(payload["metadata"]["candidate_version"], "shadow-v3")
        self.assertTrue(payload["independent_labels"])

    def test_rejects_identity_change_during_long_run(self):
        start = {
            "model_version": "v1",
            "active_bundle_id": "a",
            "runtime_content_id": "content-a",
            "semantic_model_version": "s1",
            "runtime_policy_sha256": "policy-a",
        }
        self.assertTrue(runtime_identity_matches(start, dict(start)))
        self.assertTrue(runtime_identity_matches(start, {**start, "active_bundle_id": "b"}))
        self.assertFalse(runtime_identity_matches(start, {**start, "runtime_content_id": "content-b"}))
        self.assertFalse(runtime_identity_matches(start, {**start, "model_version": "v2"}))
        self.assertFalse(runtime_identity_matches(start, {**start, "runtime_policy_sha256": "policy-b"}))


if __name__ == "__main__":
    unittest.main()
