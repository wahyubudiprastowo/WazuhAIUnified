"""Remove ONLY verified pre-migration copies after successful service checks."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

spec = importlib.util.spec_from_file_location('storage_cutover', Path(__file__).with_name('storage-cutover.py'))
cutover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cutover)


def main():
    assert os.geteuid() == 0
    verified = json.loads((cutover.BACKUP / 'verification.json').read_text())
    assert time.time() - verified['verified_at'] < 600, 'Rerun service verification first'
    completed = json.loads((cutover.BACKUP / 'cutover-complete.json').read_text())
    assert verified['verified_at'] >= completed['completed_at']
    uuid = subprocess.check_output(['findmnt', '-n', '-o', 'UUID', '--target', str(cutover.BASE)], text=True).strip()
    assert uuid == '1c166263-3587-48e4-8098-9f9b9456003b'
    allowed = {str(cutover.ROOT / (name + '.pre-sdb-migration')) for name in cutover.PATHS}
    allowed.add('/var/lib/containerd')
    assert {entry['path'] for entry in completed['originals']} == allowed
    for entry in completed['originals']:
        path = Path(entry['path'])
        assert not path.is_symlink() and not path.is_mount()
        stat = path.stat()
        assert (stat.st_dev, stat.st_ino) == (entry['dev'], entry['ino'])
        assert stat.st_dev != cutover.BASE.stat().st_dev
    # Refuse cleanup while any process still holds a file in an old directory.
    for fd in Path('/proc').glob('[0-9]*/fd/*'):
        try:
            target = os.readlink(fd)
        except (FileNotFoundError, PermissionError):
            continue
        assert not any(target == old or target.startswith(old + '/') for old in allowed), (str(fd), target)
    for entry in completed['originals']:
        print('Removing verified old copy:', entry['path'], flush=True)
        shutil.rmtree(entry['path'])
    # Preserve the earlier Docker backup on sdb1; remove its old root-disk copy
    # only after a metadata/hardlink comparison reports no differences.
    old = '/var/lib/docker.bak-20260907-080607/'
    new = str(cutover.BASE / 'migration-backups/docker.bak-20260907-080607') + '/'
    changes = subprocess.check_output(['rsync', '-naiHAXx', '--numeric-ids', '--delete', old, new], text=True)
    assert not changes.strip(), changes
    assert not Path(old).is_symlink() and not Path(old).is_mount()
    assert Path(old).stat().st_dev != cutover.BASE.stat().st_dev
    print('Removing relocated inactive backup from root:', old, flush=True)
    shutil.rmtree(old)
    (cutover.BACKUP / 'cleanup-complete.json').write_text(json.dumps({'completed_at': time.time()}))


if __name__ == '__main__':
    main()
