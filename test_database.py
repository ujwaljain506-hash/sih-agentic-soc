"""Unit tests for database layer — run with: python3 -m unittest discover -s tests

Tests run against a throwaway SQLite DB in a temp directory (database.py uses a
relative path, so we chdir) and never touch the real soc_events.db.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database


class DatabaseTestCase(unittest.TestCase):
    def setUp(self):
        self._old_cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="soc_test_")
        os.chdir(self._tmp)
        database.setup_database()

    def tearDown(self):
        os.chdir(self._old_cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _make_event(self, **overrides):
        event = {
            "timestamp": "Oct  2 01:36:38", "event_id": "uuid-1", "log_source": "linux-auth",
            "event_type": "authentication", "source_ip": "10.0.0.88", "user": "root",
            "action": "failure", "severity": "high", "raw_log": "raw line",
        }
        event.update(overrides)
        return event

    def test_setup_creates_tables(self):
        import sqlite3
        conn = sqlite3.connect("soc_events.db")
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        self.assertIn("logs", tables)
        self.assertIn("ingestion_state", tables)

    def test_schema_migration_is_idempotent(self):
        database.setup_database()
        database.upgrade_schema()  # must not raise even when columns already exist

    def test_insert_log_returns_new_id(self):
        log_id = database.insert_log(self._make_event())
        self.assertIsInstance(log_id, int)
        self.assertGreater(log_id, 0)
        self.assertEqual(database.insert_log(self._make_event()), log_id + 1)

    def test_update_agent_results_roundtrip(self):
        log_id = database.insert_log(self._make_event())
        database.update_agent_results(
            log_id=log_id, threat_level="CRITICAL", analysis_reasoning="brute force",
            response_actions="iptables -A INPUT -s 10.0.0.88 -j DROP",
            mitre_technique="T1110 - Brute Force", risk_score=85, correlated_event_count=7,
        )
        import sqlite3
        row = sqlite3.connect("soc_events.db").execute(
            "SELECT threat_level, risk_score FROM logs WHERE id=?", (log_id,)).fetchone()
        self.assertEqual(row[0], "CRITICAL")
        self.assertEqual(int(row[1]), 85)  # coerced: legacy DBs store this column as TEXT

    def test_correlation_counts_related_events(self):
        for i in range(3):
            database.insert_log(self._make_event(event_id=f"uuid-{i}"))
        count = database.get_recent_related_count(source_ip="10.0.0.88", exclude_log_id=2)
        self.assertEqual(count, 2)  # logs 1 and 3, log 2 excluded

    def test_correlation_requires_a_filter(self):
        database.insert_log(self._make_event())
        self.assertEqual(database.get_recent_related_count(), 0)

    def test_correlation_respects_window(self):
        ids = [database.insert_log(self._make_event(event_id=f"uuid-{i}")) for i in range(5)]
        # window=2 -> only rows with id > exclude-2 are considered
        count = database.get_recent_related_count(
            source_ip="10.0.0.88", exclude_log_id=ids[-1], window=2)
        self.assertLess(count, 4)

    def test_ingestion_cursor_tracks_progress(self):
        self.assertEqual(database.get_last_line_read("auth.log"), 0)
        database.update_last_line_read("auth.log", 42)
        self.assertEqual(database.get_last_line_read("auth.log"), 42)
        database.update_last_line_read("auth.log", 99)  # upsert, not duplicate
        self.assertEqual(database.get_last_line_read("auth.log"), 99)


if __name__ == "__main__":
    unittest.main()
