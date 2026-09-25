import concurrent.futures
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

from soc_workflows import (
    APPROVAL_TOOLS, AUTOMATIC_TOOLS, CASE_LIFECYCLE_TOOLS,
    BINDINGS,
    FINDING_TOOLS,
    MENU_TOOLS,
    WorkflowBusy,
    Workflows,
    policy,
)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.call = Mock(return_value={'ok': True, 'json': {'count': 3}, 'text': 'result'})
        self.lookup = lambda source, name: {'name': name, 'required_fields': [], 'schema_fields': []}
        self.path = Path(self.temp.name) / 'workflows.db'
        self.worker = Workflows(self.path, self.lookup, self.call)

    def submit(self, **args):
        return self.worker.submit('gensecai', 'get_wazuh_alerts', args)

    def test_catalog_mappings_are_unique_and_case_lifecycle_is_approval_gated(self):
        names = [name for group in MENU_TOOLS.values() for name in group.split()]
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual(len(BINDINGS), len(names))
        self.assertTrue(APPROVAL_TOOLS <= set(BINDINGS))
        self.assertTrue(FINDING_TOOLS <= set(BINDINGS))
        self.assertTrue(all('findings' in policy({'name': name})['surfaces'] for name in FINDING_TOOLS))
        self.assertEqual(policy({'name': 'future_unknown_tool'})['mode'], 'approval')
        self.assertTrue(AUTOMATIC_TOOLS <= set(BINDINGS))
        self.assertTrue(all(policy({'name': name})['automatic'] for name in AUTOMATIC_TOOLS))
        self.assertEqual(policy({'name': 'blueteam_attack_chain'})['execution_class'], 'guided')
        self.assertEqual(policy({'name': 'otx_lookup'})['execution_class'], 'on_demand')
        self.assertEqual(policy({'name': 'wazuh_block_ip'})['execution_class'], 'approval_required')
        self.assertEqual(BINDINGS['blueteam_asset_resolve'], 'assets')
        self.assertEqual(policy({'name': 'blueteam_asset_resolve'})['execution_class'], 'on_demand')
        self.assertEqual(CASE_LIFECYCLE_TOOLS, APPROVAL_TOOLS & CASE_LIFECYCLE_TOOLS)
        for name in CASE_LIFECYCLE_TOOLS:
            self.assertEqual(BINDINGS[name], 'incidents')
            self.assertEqual(policy({'name': name})['execution_class'], 'approval_required')

    def test_atomic_deduplication_and_persistent_cache(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            jobs = list(pool.map(lambda _: self.submit(limit=10), range(16)))
        self.assertEqual(len({job['id'] for job in jobs}), 1)
        self.call.assert_not_called()
        self.assertTrue(self.worker.run_once())
        self.assertFalse(self.worker.run_once())
        cached = Workflows(self.path, self.lookup, self.call).submit('gensecai', 'get_wazuh_alerts', {'limit': 10})
        self.assertTrue(cached['cached'])
        self.assertEqual(cached['result']['json']['count'], 3)
        self.call.assert_called_once()

    def test_error_cooldown_and_previous_success_retained(self):
        first = self.submit()
        self.worker.run_once()
        with self.worker.db() as db:
            db.execute('UPDATE workflow_jobs SET expires=0')
        self.call.side_effect = RuntimeError('Provider rate limited')
        second = self.submit()
        self.worker.run_once()
        self.assertEqual(self.submit()['id'], second['id'])
        self.assertEqual(self.worker.get(first['id'])['status'], 'completed')
        self.assertEqual(self.worker.get(second['id'])['status'], 'failed')
        self.assertEqual(self.call.call_count, 2)

    def test_reads_never_execute_providers_and_history_filters(self):
        job = self.submit()
        self.worker.history('l1', 0, time.time() + 5)
        self.worker.get(job['id'])
        self.assertEqual(self.worker.history('l2')['jobs'], [])
        self.assertEqual(self.worker.history('l1', 0, 1)['jobs'], [])
        self.call.assert_not_called()

    def test_limits_and_approval_exclusion(self):
        for name in ['wazuh_block_ip', 'blueteam_case_create', 'new_tool', 'blueteam_capture_traffic']:
            with self.assertRaises(ValueError):
                self.worker.submit('infokom', name, {})
        with self.assertRaises(ValueError):
            self.submit(bypass_redaction=True)
        with self.assertRaises(ValueError):
            self.worker.submit('infokom', 'otx_lookup_bulk', {'indicators': ['a'] * 11})
        self.worker.MAX_PENDING = 2
        self.submit(limit=1)
        self.submit(limit=2)
        with self.assertRaises(WorkflowBusy):
            self.submit(limit=3)

    def test_external_budget_includes_failed_and_queued_runs(self):
        for i in range(4):
            self.worker.submit('infokom', 'crowdsec_ip_reputation', {'ip': f'1.1.1.{i}'})
        with self.assertRaises(WorkflowBusy):
            self.worker.submit('infokom', 'otx_lookup', {'indicator': '8.8.8.8'})
        self.assertEqual(self.worker.submit('infokom', 'crowdsec_ip_reputation', {'ip': '1.1.1.0'})['status'], 'queued')

    def test_wazuh_budget_prevents_query_fanout(self):
        for i in range(self.worker.LOCAL_RUNS_PER_HOUR):
            self.submit(limit=i + 1)
        with self.assertRaises(WorkflowBusy):
            self.submit(limit=99)

    def test_restart_does_not_replay_running_tool(self):
        job = self.submit()
        with self.worker.db() as db:
            db.execute("UPDATE workflow_jobs SET status='running'")
        self.worker.start()
        self.worker.stop()
        self.assertEqual(self.worker.get(job['id'])['status'], 'failed')
        self.call.assert_not_called()

    def test_output_limit_and_retention(self):
        self.worker.MAX_RESULT_BYTES = 20
        job = self.submit()
        self.worker.run_once()
        self.assertEqual(self.worker.get(job['id'])['status'], 'failed')
        with self.worker.db() as db:
            db.execute('UPDATE workflow_jobs SET created=0,expires=0')
        self.submit(limit=2)
        self.worker.run_once()
        self.assertEqual(len(self.worker.history()['jobs']), 1)

    def test_required_params_wrapper_and_cap(self):
        self.worker.lookup = lambda s, n: {'name': n, 'required_fields': ['agent_id'],
            'schema_fields': [{'name': 'limit', 'default': 1000}]}
        with self.assertRaises(ValueError):
            self.submit()
        self.submit(params={'agent_id': '001', 'limit': 10000})
        self.worker.run_once()
        self.assertEqual(self.call.call_args.args[2], {'agent_id': '001', 'limit': 100})


if __name__ == '__main__':
    unittest.main()
