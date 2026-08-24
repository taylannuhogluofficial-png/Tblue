"""Tests for ExposedBackupFilesScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.exposed_backup_files import ExposedBackupFilesScanner

URL = "https://example.com"


class TestExposedBackupFiles(unittest.TestCase):
    def _make(self):
        s = ExposedBackupFilesScanner.__new__(ExposedBackupFilesScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = {}
        return r

    # ── No backup files ───────────────────────────────────────────────────────

    def test_no_backup_files_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("", status=404)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── .bak file accessible ──────────────────────────────────────────────────

    def test_bak_file_accessible_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.endswith(".bak") or u.endswith("~"):
                    return self._resp("<html>backup content here</html>")
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── PHP backup with credentials fails ────────────────────────────────────

    def test_php_bak_with_credentials_fails(self):
        php_content = "<?php\n$password = 'super_secret_pass';\n$db_host = 'localhost';\n?>"
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "config.php.bak" in u or "wp-config.php.bak" in u:
                    return self._resp(php_content)
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("credential" in r["type"].lower() or "backup" in r["type"].lower() for r in fails))

    # ── SQL dump accessible warns ─────────────────────────────────────────────

    def test_sql_dump_accessible_warns(self):
        sql_content = "-- MySQL dump\nCREATE TABLE users (id INT, email VARCHAR(255));"
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "dump.sql" in u or "backup.sql" in u:
                    return self._resp(sql_content)
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("backup" in r["type"].lower() or "sql" in r["type"].lower() or "dump" in r["type"].lower() for r in warns_or_fails))

    # ── .git/config accessible warns ─────────────────────────────────────────

    def test_git_config_accessible_warns(self):
        git_content = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/org/repo"
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if ".git/config" in u:
                    return self._resp(git_content)
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── Empty body (soft 404) is skipped ─────────────────────────────────────

    def test_empty_body_skipped(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.endswith(".bak"):
                    return self._resp("", status=200)  # soft 404 with empty body
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        # Empty bodies are filtered out — should pass
        self.assertTrue(any(r["status"] == "PASS" for r in results))
