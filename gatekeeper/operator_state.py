"""Persistent maintenance gate and small pure helpers for the owner dashboard.

The maintenance flag lives outside the SQLite snapshots deliberately: restoring
an old database must not silently turn a planned maintenance window off.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse


class MaintenanceState:
    """Durable gate. Invalid/missing existing state fails closed, not open.

    The initial installation starts active, but after the first state file has
    been created, losing it must be treated as an operational incident. Operators
    should set MAINTENANCE_REQUIRE_EXISTING=1 after the initial deployment.
    """

    def __init__(self, path: str, *, require_existing: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        if not self.path.is_file():
            if require_existing:
                raise RuntimeError('Maintenance state file missing; restore it or review manually before startup.')
            self._write(False, None)
        self.enabled, self.activated_at = self._read()

    def _read(self) -> tuple[bool, int | None]:
        try:
            doc = json.loads(self.path.read_text('utf-8'))
            if (type(doc) is not dict or type(doc.get('enabled')) is not bool
                    or doc.get('version') != 1):
                raise ValueError('invalid shape')
            enabled = doc['enabled']
            activated = doc.get('activated_at')
            if activated is not None and (type(activated) is not int or activated < 0):
                raise ValueError('invalid timestamp')
            if enabled and activated is None:
                raise ValueError('enabled without timestamp')
            return enabled, activated
        except (OSError, ValueError, TypeError) as exc:
            raise RuntimeError('Invalid maintenance state; refusing to start rather than re-enable access.') from exc

    def _write(self, enabled: bool, activated_at: int | None) -> None:
        doc = {'version': 1, 'enabled': enabled, 'activated_at': activated_at}
        fd, tmp_name = tempfile.mkstemp(prefix='.maintenance-', suffix='.tmp', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(doc, f, separators=(',', ':'))
                f.write('\n')
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass
            os.replace(tmp_name, self.path)
            if os.name == 'posix':
                # Some managed-volume filesystems do not support fsync on a
                # directory. The atomic replace has already succeeded; don't
                # leave the in-memory gate inactive if this durability hint
                # fails after the new state is visible on disk.
                try:
                    fd_dir = os.open(self.path.parent, os.O_RDONLY)
                    try:
                        os.fsync(fd_dir)
                    finally:
                        os.close(fd_dir)
                except OSError:
                    pass
        finally:
            Path(tmp_name).unlink(missing_ok=True)

    def activate(self, *, now: int | None = None) -> bool:
        if self.enabled:
            return False
        stamp = int(time.time()) if now is None else int(now)
        self._write(True, stamp)
        self.enabled, self.activated_at = True, stamp
        return True

    def deactivate(self) -> bool:
        if not self.enabled:
            return False
        self._write(False, None)
        self.enabled, self.activated_at = False, None
        return True


def human_uptime(seconds: float) -> str:
    total = max(0, int(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f'{days}d {hours}h {minutes}m'
    if hours:
        return f'{hours}h {minutes}m'
    return f'{minutes}m'


def support_invite(raw: str) -> str | None:
    """Only embed an actual HTTPS Discord invite, never arbitrary URLs."""
    try:
        url = urlparse(raw.strip())
        host = (url.hostname or '').lower()
        if (url.scheme != 'https' or url.username or url.password or url.port
                or host not in {'discord.gg', 'discord.com', 'discordapp.com'}):
            return None
        if host in {'discord.com', 'discordapp.com'} and not url.path.startswith('/invite/'):
            return None
        if not url.path.strip('/') or url.path.endswith('/'):
            return None
        return raw.strip()
    except (ValueError, AttributeError):
        return None


def maintenance_announcement(custom_message: str = '', *, outstanding: int = 0) -> str:
    """Text sent under the Umask bot identity, never as a guild owner."""
    note = ' '.join(custom_message.strip().split())[:500]
    message = ('**Umask service notice — planned maintenance**\n'
               'New elevated sessions have been disabled. Umask has attempted to revoke '
               'tracked elevated roles; server owners should verify staff roles manually if needed. '
               'Umask will not automatically resume access after a host restart.')
    if outstanding:
        message += (f'\n**Warning:** {outstanding} tracked session(s) across the service still need '
                    'role-removal confirmation. Please check privileged roles in your server.')
    if note:
        message += '\n\n**Message from the Umask operator:**\n' + note
    return message
