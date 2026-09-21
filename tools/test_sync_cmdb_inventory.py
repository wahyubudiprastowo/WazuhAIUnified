import importlib.util
import stat
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("sync_cmdb_inventory", Path(__file__).with_name("sync_cmdb_inventory.py"))
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


class CmdbSyncTests(unittest.TestCase):
    def test_merge_excludes_samples_and_preserves_verified_business_context(self):
        current = [
            {"agent_id": "001", "owner": "Example", "purpose": "SAMPLE - replace"},
            {"agent_id": "005", "owner": "Platform", "criticality": "high", "verified": True},
        ]
        agents = [
            {"id": "005", "name": "app-1", "ip": "10.0.0.5", "os": {"name": "Linux"}},
            {"id": "006", "name": "db-1", "ip": "10.0.0.6", "os": {"name": "Linux"},
             "labels": {"owner": "Database team", "criticality": "critical"}},
        ]
        rows = sync.merge_agents(agents, current, "2026-09-24T00:00:00+00:00")
        self.assertEqual(len(rows), 2)
        app = next(row for row in rows if row["agent_id"] == "005")
        self.assertEqual(app["owner"], "Platform")
        self.assertEqual(app["criticality"], "high")
        self.assertEqual(app["source"], "Wazuh agent inventory")
        db = next(row for row in rows if row["agent_id"] == "006")
        self.assertEqual(db["owner"], "Database team")
        self.assertEqual(db["criticality"], "critical")
        self.assertTrue(db["verified"])

    def test_atomic_write_remains_readable_by_container_root_group(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "assets.json"
            sync.atomic_write(target, [{"agent_id": "001", "verified": True}])
            mode = stat.S_IMODE(target.stat().st_mode)
            self.assertEqual(mode, 0o640)
            self.assertEqual(sync.existing_assets(target)[0]["agent_id"], "001")


if __name__ == "__main__":
    unittest.main()
