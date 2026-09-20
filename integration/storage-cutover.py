"""One-time, host-specific storage cutover after storage-precopy.sh succeeds.

Does not delete originals. Run as root during the announced maintenance window.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request

BASE = Path('/data/wazuh-storage')
ROOT = Path('/opt/wazuh-mcp-unified')
CONFIG = ROOT / 'integration/storage'
BACKUP = BASE / 'migration-backups/cutover-20260911'
PATHS = ['syslog-ingest', 'infokom-analysis/runtime', 'hld-platform/runtime',
         'hld-platform/soar-audit', 'hld-platform/pam-audit']


def run(*args, capture=False):
    print(' '.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def install(source, target):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o644)


def main():
    assert os.geteuid() == 0
    assert run('findmnt', '-n', '-o', 'UUID', '--target', BASE, capture=True).strip() == '1c166263-3587-48e4-8098-9f9b9456003b'
    assert not BACKUP.exists(), 'Cutover already started; inspect before resuming'
    assert not Path('/etc/containerd/config.toml').exists(), 'Review existing containerd configuration'
    for name in PATHS:
        assert (BASE / 'app-data' / name).is_dir()
        assert not (ROOT / (name + '.pre-sdb-migration')).exists()
    BACKUP.mkdir(mode=0o700)
    shutil.copy2('/etc/fstab', BACKUP / 'fstab')
    shutil.copy2('/etc/docker/daemon.json', BACKUP / 'docker-daemon.json')
    containers = run('docker', 'ps', '--format', '{{.Names}}', capture=True).splitlines()
    (BACKUP / 'running-containers.json').write_text(json.dumps(containers))
    request = urllib.request.Request('http://127.0.0.1:8088/api/pipeline/status', data=b'{}',
                                     headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        baseline = json.load(response)
    (BACKUP / 'pipeline-before.json').write_text(json.dumps(baseline))
    run('docker', 'stop', '--time', '90', 'single-node-wazuh.manager-1')
    # Allow the splitter to persist the final reader position before stopping it.
    state = ROOT / 'syslog-ingest/.device-splitter-state.json'
    archive = ROOT / 'syslog-ingest/archives/archives.json'
    for _ in range(30):
        saved = json.loads(state.read_text())
        if saved.get('offset', 0) >= archive.stat().st_size:
            break
        time.sleep(1)
    run('systemctl', 'stop', 'wazuh-device-splitter.service')
    remaining = [name for name in containers if name != 'single-node-wazuh.manager-1']
    run('docker', 'stop', '--time', '90', *remaining)
    run('systemctl', 'stop', 'docker.service', 'docker.socket')
    run('systemctl', 'stop', 'containerd.service')
    for name in PATHS:
        run('rsync', '-aHAX', '--no-whole-file', '--inplace', '--numeric-ids', '--delete', '--stats',
            str(ROOT / name) + '/', str(BASE / 'app-data' / name) + '/')
        changes = run('rsync', '-naiHAX', '--numeric-ids', '--delete',
                      str(ROOT / name) + '/', str(BASE / 'app-data' / name) + '/', capture=True)
        assert not changes.strip(), changes
    run('rsync', '-aHAXx', '--numeric-ids', '--delete', '--stats',
        '/var/lib/containerd/', str(BASE / 'containerd') + '/')
    assert not run('rsync', '-naiHAXx', '--numeric-ids', '--delete',
                   '/var/lib/containerd/', str(BASE / 'containerd') + '/', capture=True).strip()
    # The data is unchanged, but the new filesystem assigns different inodes.
    # Preserve the reader offset so migration is not mistaken for log rotation.
    new_state = BASE / 'app-data/syslog-ingest/.device-splitter-state.json'
    saved = json.loads(new_state.read_text())
    if saved.get('inode') != archive.stat().st_ino or saved.get('offset', 0) > archive.stat().st_size:
        saved['offset'] = 0
    saved['inode'] = (BASE / 'app-data/syslog-ingest/archives/archives.json').stat().st_ino
    new_state.write_text(json.dumps(saved))
    for name in PATHS:
        source = ROOT / name
        mode = source.stat().st_mode & 0o7777
        source.rename(ROOT / (name + '.pre-sdb-migration'))
        source.mkdir(mode=mode)
    install(CONFIG / 'fstab', '/etc/fstab')
    install(CONFIG / 'containerd.toml', '/etc/containerd/config.toml')
    for service in ('docker', 'containerd'):
        install(CONFIG / (service + '-storage.conf'),
                '/etc/systemd/system/' + service + '.service.d/storage.conf')
    install(CONFIG / 'splitter-storage.conf',
            '/etc/systemd/system/wazuh-device-splitter.service.d/storage.conf')
    run('systemctl', 'daemon-reload')
    run('findmnt', '--verify', '--tab-file', '/etc/fstab')
    for name in PATHS:
        run('mount', ROOT / name)
        assert run('findmnt', '-n', '-o', 'UUID', '--target', ROOT / name, capture=True).strip() == '1c166263-3587-48e4-8098-9f9b9456003b'
    run('systemctl', 'start', 'containerd.service', 'docker.service')
    order = ['single-node-wazuh.indexer-1', 'single-node-wazuh.manager-1']
    order += [name for name in containers if name not in order]
    for name in order:
        run('docker', 'start', name)
    run('systemctl', 'start', 'wazuh-device-splitter.service')
    originals = [ROOT / (name + '.pre-sdb-migration') for name in PATHS]
    originals.append(Path('/var/lib/containerd'))
    (BACKUP / 'cutover-complete.json').write_text(json.dumps({
        'completed_at': time.time(),
        'originals': [{'path': str(path), 'dev': path.stat().st_dev, 'ino': path.stat().st_ino}
                      for path in originals],
    }, indent=2))
    print('Cutover complete. Verify services and validated copies before cleanup.', flush=True)


if __name__ == '__main__':
    main()
