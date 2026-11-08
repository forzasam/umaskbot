"""Operator-approved erasure ledger and consistent SQLite snapshots.

This file never accepts requests directly from Discord users or the website.
The application owner manually verifies/reviews requests before recording one.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _secure_directory(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        folder.chmod(0o700)
    except OSError:
        pass


class PrivacyLedger:
    """Append-before-apply erasure decisions in a file excluded from DB backups.

    Preserve this file separately when restoring an old DB. It is *not* a
    guarantee if the hosting account, backup AND ledger are all lost.
    """

    def __init__(self, path: str, *, require_existing: bool = False):
        self.path = Path(path)
        _secure_directory(self.path.parent)
        if not self.path.exists():
            if require_existing:
                raise RuntimeError('Privacy erasure ledger is missing. Refusing to start; restore the current ledger before using a database backup.')
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def events(self) -> list[dict[str, Any]]:
        result = []
        with self.path.open('r', encoding='utf-8') as f:
            for number, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    kind = event.get('type')
                    if (kind not in {'erase_user', 'erase_guild', 'erase_history'}
                            or not isinstance(event.get('created_at'), int)
                            or not isinstance(event.get('case_ref'), str)
                            or (kind in {'erase_user', 'erase_history'} and
                                (type(event.get('user_id')) is not int or event['user_id'] <= 0))
                            or (kind == 'erase_guild' and
                                (type(event.get('guild_id')) is not int or event['guild_id'] <= 0))
                            or (event.get('guild_id') is not None and
                                (type(event['guild_id']) is not int or event['guild_id'] <= 0))):
                        raise ValueError('invalid event')
                except (ValueError, TypeError) as ex:
                    # Fail closed: never skip an ambiguous erasure instruction.
                    raise RuntimeError(f'Privacy ledger is damaged on line {number}; do not start against this database') from ex
                result.append(event)
        return result

    def append(self, kind: str, *, guild_id: int | None = None,
               user_id: int | None = None, case_ref: str, now: int | None = None) -> dict:
        if kind not in {'erase_user', 'erase_guild', 'erase_history'}:
            raise ValueError('unsupported privacy action')
        if kind == 'erase_guild' and not guild_id:
            raise ValueError('guild required')
        if kind in {'erase_user', 'erase_history'} and not user_id:
            raise ValueError('user required')
        if not case_ref or len(case_ref) > 64 or any(c in case_ref for c in '\r\n'):
            raise ValueError('A short, private case reference is required')
        event = {'type': kind, 'created_at': int(time.time()) if now is None else int(now),
                 'guild_id': guild_id, 'user_id': user_id, 'case_ref': case_ref}
        # Single-process deployment; append and fsync BEFORE mutating the database.
        with self.path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(event, separators=(',', ':')) + '\n')
            f.flush()
            os.fsync(f.fileno())
        return event

    def apply(self, store, *, now: int | None = None) -> None:
        when = int(time.time()) if now is None else int(now)
        for event in self.events():
            store.apply_erasure_event(event, when)

    def guild_pending_erasure(self, guild_id: int, config_updated_at: int) -> bool:
        """Reject new access using a configuration approved for server-wide deletion."""
        return any(event['type'] == 'erase_guild'
                   and event.get('guild_id') == guild_id
                   and config_updated_at <= event['created_at']
                   for event in self.events())

    def rotate(self, store, *, now: int | None = None, retention_days: int = 365) -> int:
        """Keep only recent erasure entries; NEVER prune pending revocations.

        Safe restoration procedure forbids snapshots older than 30 days.
        This ledger must be backed up separately from the SQLite snapshots.
        """
        when = int(time.time()) if now is None else int(now)
        original = self.events()
        keep = [event for event in original
                if event['created_at'] >= when - retention_days * 86400
                or store.erasure_pending(event)]
        if len(keep) == len(original):
            return 0
        fd, tmp_name = tempfile.mkstemp(prefix='.ledger-', suffix='.partial', dir=self.path.parent)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                for event in keep:
                    f.write(json.dumps(event, separators=(',', ':')) + '\n')
                f.flush(); os.fsync(f.fileno())
            os.replace(tmp, self.path)
        finally:
            tmp.unlink(missing_ok=True)
        return len(original) - len(keep)


def backup_sqlite(store, folder: str, *, now: int | None = None, keep_days: int = 7) -> Path:
    """Create an integrity-tested, atomic snapshot; then rotate local snapshots.

    Does not download, encrypt, or upload copies off-server.
    """
    if not hasattr(store, 'conn') or not isinstance(store.conn, sqlite3.Connection):
        raise TypeError('SQLite backup requires SQLite store')
    when = int(time.time()) if now is None else int(now)
    day = datetime.fromtimestamp(when, timezone.utc).strftime('%Y-%m-%d')
    directory = Path(folder)
    _secure_directory(directory)
    destination = directory / f'umask-{day}.sqlite3'
    if not destination.exists():
        temporary = directory / f'.umask-{day}-{os.getpid()}.partial'
        try:
            with sqlite3.connect(str(temporary)) as output:
                store.conn.backup(output)
                ok = output.execute('PRAGMA integrity_check').fetchone()[0]
                if ok != 'ok':
                    raise RuntimeError(f'Snapshot integrity check failed: {ok}')
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    # Keep 7 full UTC calendar days, including today; do not touch unrelated files.
    for item in directory.glob('umask-????-??-??.sqlite3'):
        try:
            date = datetime.strptime(item.stem.removeprefix('umask-'), '%Y-%m-%d').replace(tzinfo=timezone.utc)
            age = (datetime.fromtimestamp(when, timezone.utc).date() - date.date()).days
            if age >= keep_days and age >= 0:
                item.unlink()
        except ValueError:
            continue
    return destination
