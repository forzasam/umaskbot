"""Tests fixed-time scheduling and daily SQLite snapshot idempotence."""
import ast
import os
import re
import sqlite3
import tempfile
from datetime import datetime, time as clock_time, timezone
from pathlib import Path
from gatekeeper.privacy import backup_sqlite
source = Path(__file__).parent.joinpath('gatekeeper', 'bot.py').read_text()
tree = ast.parse(source)
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'backup_schedule_utc')
ns = {'os': os, 're': re, 'clock_time': clock_time, 'timezone': timezone}
exec(compile(ast.Module(body=[fn], type_ignores=[]), '<schedule>', 'exec'), ns)
get_schedule = ns['backup_schedule_utc']
prior = os.environ.get('BACKUP_TIME_UTC')
try:
    for value, expected in [(None, '04:00'), ('00:00', '00:00'), ('23:59', '23:59')]:
        if value is None: os.environ.pop('BACKUP_TIME_UTC', None)
        else: os.environ['BACKUP_TIME_UTC'] = value
        assert get_schedule().strftime('%H:%M') == expected
        assert get_schedule().tzinfo == timezone.utc
    for invalid in ['24:00', '12:60', '4:00', 'tomorrow', '']:
        os.environ['BACKUP_TIME_UTC'] = invalid
        try: get_schedule()
        except ValueError: pass
        else: raise AssertionError(f'Accepted invalid time {invalid!r}')
finally:
    if prior is None: os.environ.pop('BACKUP_TIME_UTC', None)
    else: os.environ['BACKUP_TIME_UTC'] = prior
with tempfile.TemporaryDirectory() as tmp:
    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE important (id INTEGER PRIMARY KEY, v TEXT)')
    conn.execute("INSERT INTO important(v) VALUES ('saved')")
    conn.commit()
    class FakeStore: pass
    store = FakeStore(); store.conn = conn
    now = int(datetime(2026, 11, 11, 4, tzinfo=timezone.utc).timestamp())
    first = backup_sqlite(store, tmp, now=now)
    assert first.name == 'umask-2026-11-11.sqlite3'
    conn.execute("INSERT INTO important(v) VALUES ('changed-after-backup')")
    second = backup_sqlite(store, tmp, now=now+3600)
    assert first == second
    with sqlite3.connect(first) as snapshot:
        assert snapshot.execute('SELECT COUNT(*) FROM important').fetchone()[0] == 1
assert '@tasks.loop(time=BACKUP_SCHEDULE_UTC)' in source
print('Fixed UTC scheduling and daily SQLite snapshot tests passed')
