"""Read-only storage and service verification, with no secret-bearing output."""
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import time

import importlib.util

spec = importlib.util.spec_from_file_location('storage_cutover', Path(__file__).with_name('storage-cutover.py'))
cutover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cutover)


def output(*args):
    return subprocess.check_output(args, text=True).strip()

def run_text(*args):
    proc = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout.strip()


def main():
    assert os.geteuid() == 0
    expected_uuid = '1c166263-3587-48e4-8098-9f9b9456003b'
    paths = [str(cutover.BASE), str(cutover.BASE / 'containerd')]
    paths += [str(cutover.ROOT / name) for name in cutover.PATHS]
    for path in paths:
        uuid = output('findmnt', '-n', '-o', 'UUID', '--target', path)
        assert uuid == expected_uuid, (path, uuid)
        print(path, '-> /dev/sdb1')
    names = json.loads((cutover.BACKUP / 'running-containers.json').read_text())
    for name in names:
        states = json.loads(output('docker', 'inspect', '--format', '{{json .State}}', name))
        assert states['Running'], name
        health = states.get('Health', {}).get('Status', 'no healthcheck')
        assert health in ('healthy', 'no healthcheck'), (name, health)
        print(name, 'running;', health)
    assert output('docker', 'info', '--format', '{{.DockerRootDir}}') == str(cutover.BASE / 'docker')
    overlays = output('findmnt', '-rn', '-t', 'overlay', '-o', 'OPTIONS')
    assert '/var/lib/containerd/' not in overlays, 'An overlay still references old containerd data'
    for service in ('docker', 'containerd', 'wazuh-device-splitter'):
        assert output('systemctl', 'is-active', service) == 'active'
        dependencies = output('systemctl', 'show', service, '-p', 'RequiresMountsFor')
        assert str(cutover.BASE) in dependencies
        print(service, dependencies)
    with urllib.request.urlopen('http://127.0.0.1:8088', timeout=30) as response:
        assert response.status == 200
    request = urllib.request.Request('http://127.0.0.1:8088/api/pipeline/status', data=b'{}',
                                     headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        pipeline = json.load(response)
    assert pipeline.get('checkpoint'), pipeline
    assert pipeline.get('enabled') and pipeline.get('active'), pipeline
    assert not pipeline.get('error'), pipeline
    baseline = json.loads((cutover.BACKUP / 'pipeline-before.json').read_text())
    assert pipeline['started_at'] == baseline['started_at'], 'Collector state was reset'
    assert pipeline['scanned_including_replay'] >= baseline['scanned_including_replay']
    print('SOC pipeline:', json.dumps(pipeline))
    # Resolve credentials only inside the container; never print them.
    code = """
import base64, json, os, ssl, urllib.request
url = os.environ['WAZUH_INDEXER_URL']
auth = base64.b64encode((os.environ['WAZUH_INDEXER_USER'] + ':' + os.environ['WAZUH_INDEXER_PASSWORD']).encode()).decode()
for path in ['/_cluster/health', '/wazuh-alerts-*/_count']:
    request = urllib.request.Request(url + path, headers={'Authorization': 'Basic ' + auth})
    with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=45) as response:
        data = json.load(response)
    if path.endswith('health'):
        assert data['status'] != 'red', data['status']
        print('Indexer status:', data['status'], 'active shards:', data['active_shards'])
    else:
        assert data['count'] > 0
        print('Indexed alerts:', data['count'])
"""
    print(output('docker', 'exec', 'wazuh-mcp-dashboard', 'python', '-c', code))
    _, manager = run_text('docker', 'exec', 'single-node-wazuh.manager-1',
                          '/var/ossec/bin/wazuh-control', 'status')
    for process in ('wazuh-analysisd', 'wazuh-remoted', 'wazuh-db'):
        assert process + ' is running' in manager, manager
    print('Manager:', manager)
    print(output('df', '-h', '/', str(cutover.BASE)))
    (cutover.BACKUP / 'verification.json').write_text(json.dumps({
        'verified_at': time.time(), 'pipeline': pipeline, 'containers': names,
    }, indent=2))


if __name__ == '__main__':
    main()
