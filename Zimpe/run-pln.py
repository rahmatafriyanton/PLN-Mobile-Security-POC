#!/usr/bin/env python3
"""Cold launch, bootstrap the patch plan from pln-test.js, then attach Frida."""
import argparse
import json
import struct
import subprocess
import tempfile
import threading
import time
import zipfile
from pathlib import Path
import frida

ROOT = Path(__file__).resolve().parent
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--device', default='0A091FDD4009ZQ')
ap.add_argument('--remote', default='127.0.0.1:27043', help='Frida endpoint for the validated neutral-label server')
ap.add_argument('--clear', action='store_true', help='Clear PLN application data before launch')
ap.add_argument('--settle', type=float, default=45)
ap.add_argument('--log', default='diagnostics/final-run.jsonl')
args = ap.parse_args()
if frida.__version__ != '16.5.2':
    raise SystemExit('Run with PYENV_VERSION=frida-16.5.2 pyenv exec python run-pln.py')
pkg = 'com.app.plnmobile'
script_path = ROOT / 'pln-test.js'
plan = json.loads(subprocess.check_output(['node', str(script_path), '--patch-plan']))
started = time.monotonic()
log_path = ROOT / args.log
log_path.parent.mkdir(parents=True, exist_ok=True)
log_file = log_path.open('w')
def record(event, **fields):
    row = dict(elapsed=round(time.monotonic()-started, 3), event=event, **fields)
    line = json.dumps(row, default=str)
    print(line, flush=True)
    log_file.write(line+'\n'); log_file.flush()
def adb(*cmd, timeout=20):
    r = subprocess.run(['adb', '-s', args.device, *cmd], capture_output=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors='replace') or r.stdout.decode(errors='replace'))
    return r.stdout
def root(command):
    # exec-out passes this argument directly; shell quoting would become literal.
    return adb('exec-out', 'su', '-c', command)
def pidof():
    r = subprocess.run(['adb','-s',args.device,'shell','pidof',pkg],capture_output=True,timeout=5)
    return r.stdout.decode().strip()
def read_memory(pid, address, size):
    return root(f'dd if=/proc/{pid}/mem bs=1 skip={address} count={size} 2>/dev/null')

with zipfile.ZipFile(ROOT/'eK1tY8mL4w.apk') as archive:
    entry = archive.getinfo(plan['apkEntry'])
    if entry.compress_type != zipfile.ZIP_STORED:
        raise SystemExit('Expected uncompressed APK native library')
    with (ROOT/'eK1tY8mL4w.apk').open('rb') as f:
        f.seek(entry.header_offset+26)
        name_len, extra_len = struct.unpack('<HH',f.read(4))
    apk_offset = entry.header_offset+30+name_len+extra_len
patches = plan['patches']
blob = b''.join(bytes.fromhex(p['replacement']) for p in patches)
with tempfile.NamedTemporaryFile() as f:
    f.write(blob); f.flush()
    adb('push', f.name, '/data/local/tmp/pln-bootstrap.bin')
adb('shell','am','force-stop',pkg)
if args.clear:
    record('clear', result=adb('shell','pm','clear',pkg).decode().strip())
time.sleep(.7)
record('launch', result=adb('shell','am','start','-W','-n',pkg+'/.MainActivity').decode())
pid = pidof()
if not pid:
    raise SystemExit('No process after launch; see Android logcat before retrying')
pid = int(pid)
base = None
for _ in range(60):
    maps = root(f'cat /proc/{pid}/maps').decode()
    if not any('/' in line and len(line.split()) >= 5 and '-' in line.split()[0] for line in maps.splitlines()):
        raise SystemExit('Cannot read target mappings: ' + maps.strip())
    for line in maps.splitlines():
        fields = line.split()
        if len(fields)>5 and fields[-1].endswith('/base.apk') and int(fields[2],16)==apk_offset:
            base = int(fields[0].split('-')[0],16); break
    if base is not None: break
    time.sleep(.03)
if base is None:
    raise SystemExit('Target core mapping was not found')
root(f'kill -STOP {pid}')
try:
    reads = [f'dd if=/proc/{pid}/mem bs=1 skip={base+p["offset"]} count={len(p["expected"])//2} 2>/dev/null' for p in patches]
    before = root('; '.join(reads))
    if before != b''.join(bytes.fromhex(p['expected']) for p in patches):
        raise RuntimeError('Native signature mismatch: refusing to patch this build')
    commands = []; position = 0
    for p in patches:
        size = len(p['replacement'])//2
        commands.append(f'dd if=/data/local/tmp/pln-bootstrap.bin of=/proc/{pid}/mem bs=1 skip={position} count={size} seek={base+p["offset"]} conv=notrunc 2>/dev/null')
        position += size
    root(' && '.join(commands))
    after = root('; '.join(reads))
    if after != blob:
        raise RuntimeError('Native patch readback failed')
    record('bootstrap-verified', pid=pid, module=plan['module'], count=len(patches), source='pln-test.js')
finally:
    root(f'kill -CONT {pid}')
record('settling', seconds=args.settle)
time.sleep(args.settle)
if pidof() != str(pid):
    raise SystemExit('Target exited during startup settling')
session = frida.get_device_manager().add_remote_device(args.remote).attach(pid)
done = threading.Event()
def detached(reason, crash):
    record('detached', reason=reason, crash=crash.report if crash else None)
    done.set()
session.on('detached', detached)
agent = session.create_script(script_path.read_text())
errors = []
def message(m, data):
    record('agent', message=m)
    if m['type']=='error': errors.append(m)
agent.on('message', message)
agent.load()
if errors:
    session.detach(); raise SystemExit('Agent failed to load')
record('attached', pid=pid, frida=frida.__version__)
try:
    while not done.wait(5):
        current = pidof()
        record('alive', pid=pid, current=current, attached=not session.is_detached)
        if current != str(pid): break
except KeyboardInterrupt:
    record('user-detach')
    session.detach()
