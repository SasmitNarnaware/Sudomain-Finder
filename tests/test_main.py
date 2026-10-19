import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main


class ScopeTests(unittest.TestCase):
    def test_default_scope_allows_root_subdomains(self):
        self.assertTrue(main.host_in_scope("API.Example.com.", "example.com"))
        self.assertFalse(main.host_in_scope("example.net", "example.com"))

    def test_deny_wins_and_allow_narrows(self):
        allow = ["*.example.com"]
        deny = ["admin.example.com"]
        self.assertTrue(main.host_in_scope("api.example.com", "example.com", allow, deny))
        self.assertFalse(main.host_in_scope("admin.example.com", "example.com", allow, deny))
        self.assertFalse(main.host_in_scope("example.com", "example.com", allow, deny))

    def test_scope_file_accepts_string_or_list(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.json"
            path.write_text(json.dumps({"allow": "*.example.com", "deny": ["internal.example.com"]}), encoding="utf-8")
            self.assertEqual(
                main.load_scope_file(path, "example.com"),
                {"allow": ["*.example.com"], "deny": ["internal.example.com"]},
            )


class UrlTests(unittest.TestCase):
    def test_normalize_url_removes_fragment_and_default_port(self):
        self.assertEqual(
            main.normalize_url("HTTPS://Example.COM:443/a/../users/42/?id=42#fragment"),
            "https://example.com/users/42/?id=42",
        )

    def test_endpoint_data_is_normalized_and_deduplicated(self):
        endpoints, parameters = main.extract_endpoint_data([
            "https://EXAMPLE.com/api/users/1?user_id=1",
            "https://example.com/api/users/1?other=2#ignored",
            "not a url",
        ])
        self.assertEqual(endpoints, ["https://example.com/api/users/1"])
        self.assertEqual(parameters, ["other", "user_id"])


class CandidateTests(unittest.TestCase):
    def test_candidate_extraction_detects_path_uuid_query_and_api_signals(self):
        candidates = main.extract_idor_candidates([
            "https://api.example.com/api/v1/users/123?account_id=456",
            "https://api.example.com/projects/550e8400-e29b-41d4-a716-446655440000",
            "https://api.example.com/search?q=hello",
        ], "example.com")
        self.assertEqual(len(candidates), 2)
        self.assertGreaterEqual(candidates[0]["confidence_score"], 0.6)
        self.assertTrue(any(item["location"] == "path" for item in candidates[0]["identifiers"]))
        self.assertIn("api path", candidates[0]["api_resource_signals"])
        self.assertIn("manual authorized verification", candidates[0]["manual_verification"])

    def test_out_of_scope_urls_are_not_candidates(self):
        self.assertEqual(
            main.extract_idor_candidates(["https://other.example.net/users/123"], "example.com"),
            [],
        )


class RunTests(unittest.TestCase):
    def test_mocked_low_noise_run_writes_expected_artifacts(self):
        httpx_line = json.dumps({
            "host": "api.example.com",
            "url": "https://api.example.com",
            "status_code": 200,
            "a": ["192.0.2.10"],
            "tech": ["Example"],
        })
        with tempfile.TemporaryDirectory() as directory:
            args = main.parse_args([
                "example.com",
                "--run-dir",
                str(Path(directory) / "run"),
                "--no-katana",
                "--no-gau",
            ])
            with patch.object(main, "tool_preflight", return_value={
                "available": {"subfinder": "subfinder", "httpx": "httpx"},
                "missing_optional": [],
            }), patch.object(main, "subfinder_subdomains", return_value={"api.example.com"}), \
                    patch.object(main, "crtsh_subdomains", return_value=set()), \
                    patch.object(main, "_run_command", return_value=subprocess.CompletedProcess(
                        ["httpx"], 0, httpx_line + "\n", "")):
                run_dir, results = main.run_recon(args)

            self.assertEqual(results["domain"], "example.com")
            self.assertTrue((run_dir / "manifest.json").is_file())
            self.assertTrue((run_dir / "results.json").is_file())
            self.assertTrue((run_dir / "idor_candidates.json").is_file())
            self.assertIn("finished_at", json.loads((run_dir / "manifest.json").read_text()))


if __name__ == "__main__":
    unittest.main()
