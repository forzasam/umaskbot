"""Small durable SQLite state store. One process; no member-list intent needed."""
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path: str):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(p), isolation_level=None, timeout=15)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA busy_timeout=15000")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS guild_config (
              guild_id INTEGER PRIMARY KEY, staff_role_id INTEGER NOT NULL,
              elevated_role_id INTEGER NOT NULL, durations TEXT NOT NULL,
              alert_channel_id INTEGER, updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS credentials (
              guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
              phrase_hash TEXT NOT NULL, pending_secret BLOB, pending_until INTEGER,
              issued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
              locked_until INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (guild_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
              guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
              role_id INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              started_at INTEGER NOT NULL, state TEXT NOT NULL,
              PRIMARY KEY (guild_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS session_history (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
              role_id INTEGER NOT NULL, started_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL, ended_at INTEGER NOT NULL,
              end_reason TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS session_history_guild_ended
              ON session_history(guild_id, ended_at DESC, id DESC);
            CREATE TABLE IF NOT EXISTS departed_guilds (
              guild_id INTEGER PRIMARY KEY, removed_at INTEGER NOT NULL
            );
        """)
        # In-place upgrade for databases created by Gatekeeper v0.1.
        # Existing active sessions and credentials are preserved.
        columns = {row['name'] for row in self.conn.execute("PRAGMA table_info(sessions)")}
        if 'termination_reason' not in columns:
            self.conn.execute("ALTER TABLE sessions ADD COLUMN termination_reason TEXT")
        # v0.5: distinguish newly collected phrases from expired one-time
        # collection windows. The historical collection state cannot be inferred
        # for records issued in older versions, so NULL means 'unknown'.
        credential_columns = {row['name'] for row in self.conn.execute("PRAGMA table_info(credentials)")}
        if 'collected_at' not in credential_columns:
            self.conn.execute("ALTER TABLE credentials ADD COLUMN collected_at INTEGER")
        # Versioned, credential-scoped monitoring state is deleted automatically
        # when credentials are revoked or erased. No extra member-list intent.
        for column, ddl in (
            ('staff_missing_since', 'INTEGER'),
            ('staff_loss_notified_at', 'INTEGER'),
            ('permission_warning_key', 'TEXT'),
        ):
            if column not in credential_columns:
                self.conn.execute(f"ALTER TABLE credentials ADD COLUMN {column} {ddl}")
        history_columns = {r['name'] for r in self.conn.execute("PRAGMA table_info(session_history)")}
        if 'hold_until' not in history_columns:
            self.conn.execute("ALTER TABLE session_history ADD COLUMN hold_until INTEGER")
        if 'hold_reference' not in history_columns:
            self.conn.execute("ALTER TABLE session_history ADD COLUMN hold_reference TEXT")

    @contextmanager
    def tx(self):
        # sqlite3 isolation_level=None is autocommit; an explicit transaction
        # makes read/modify/write and multi-statement updates crash-atomic.
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def close(self):
        self.conn.close()

    def config(self, guild_id):
        return self.conn.execute("SELECT * FROM guild_config WHERE guild_id=?", (guild_id,)).fetchone()

    def configured_guild_ids(self) -> set[int]:
        return {int(row[0]) for row in self.conn.execute('SELECT guild_id FROM guild_config')}

    def set_config(self, guild_id, staff_role_id, elevated_role_id, durations, alert_channel_id):
        existing = self.config(guild_id)
        change = bool(existing and (existing['staff_role_id'] != staff_role_id or existing['elevated_role_id'] != elevated_role_id))
        if change and self.count_sessions(guild_id):
            raise ValueError("Sign out or revoke all active sessions before changing protected roles.")
        with self.tx():
            if change:
                self.conn.execute("DELETE FROM credentials WHERE guild_id=?", (guild_id,))
            self.conn.execute("""INSERT INTO guild_config VALUES (?,?,?,?,?,?)
              ON CONFLICT(guild_id) DO UPDATE SET staff_role_id=excluded.staff_role_id,
              elevated_role_id=excluded.elevated_role_id, durations=excluded.durations,
              alert_channel_id=excluded.alert_channel_id, updated_at=excluded.updated_at""",
              (guild_id, staff_role_id, elevated_role_id, ','.join(map(str, durations)), alert_channel_id, int(time.time())))
        return change

    def count_sessions(self, guild_id):
        return self.conn.execute("SELECT COUNT(*) FROM sessions WHERE guild_id=?",(guild_id,)).fetchone()[0]

    def sessions_for_guild(self, guild_id, limit=8, offset=0):
        return self.conn.execute("""SELECT * FROM sessions WHERE guild_id=?
            ORDER BY started_at DESC, user_id ASC LIMIT ? OFFSET ?""",
            (guild_id, limit, offset)).fetchall()

    def count_history(self, guild_id):
        return self.conn.execute("SELECT COUNT(*) FROM session_history WHERE guild_id=?", (guild_id,)).fetchone()[0]

    def history_for_guild(self, guild_id, limit=8, offset=0):
        return self.conn.execute("""SELECT * FROM session_history WHERE guild_id=?
            ORDER BY ended_at DESC, id DESC LIMIT ? OFFSET ?""",
            (guild_id, limit, offset)).fetchall()

    def credential(self, guild_id, user_id):
        return self.conn.execute("SELECT * FROM credentials WHERE guild_id=? AND user_id=?",(guild_id,user_id)).fetchone()

    def count_credentials(self, guild_id):
        """Number of currently valid issued phrases (claimed or unclaimed)."""
        return self.conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE guild_id=?", (guild_id,)
        ).fetchone()[0]

    def credentials_for_guild(self, guild_id, limit=10, offset=0):
        """Read-only owner inventory. Never SELECT phrase hashes or escrow ciphertext."""
        return self.conn.execute("""SELECT user_id, issued_at, pending_until,
                 CASE WHEN pending_secret IS NOT NULL THEN 1 ELSE 0 END AS has_pending_copy,
                 collected_at, staff_missing_since, staff_loss_notified_at, permission_warning_key
            FROM credentials WHERE guild_id=?
            ORDER BY issued_at DESC, user_id ASC LIMIT ? OFFSET ?""",
            (guild_id, limit, offset)
        ).fetchall()

    def issue(self, guild_id, user_id, hash_value, encrypted, valid_until):
        with self.tx():
            self.conn.execute("""INSERT INTO credentials
              (guild_id,user_id,phrase_hash,pending_secret,pending_until,issued_at,attempts,locked_until,collected_at)
              VALUES (?,?,?,?,?,?,0,0,0) ON CONFLICT(guild_id,user_id) DO UPDATE SET
              phrase_hash=excluded.phrase_hash,pending_secret=excluded.pending_secret,
              pending_until=excluded.pending_until,issued_at=excluded.issued_at,
              collected_at=0,attempts=0,locked_until=0,
              staff_missing_since=NULL,staff_loss_notified_at=NULL,
              permission_warning_key=NULL""",
              (guild_id,user_id,hash_value,encrypted,valid_until,int(time.time())))

    def monitor_credential_batch(self, limit: int = 40, offset: int = 0):
        """Bounded scan of credential holders, never all guild members."""
        return self.conn.execute('''SELECT guild_id,user_id,staff_missing_since,
                staff_loss_notified_at,permission_warning_key FROM credentials
                ORDER BY guild_id,user_id LIMIT ? OFFSET ?''', (limit,offset)).fetchall()

    def mark_staff_role_state(self, guild_id: int, user_id: int,
                              missing_since: int | None, notified_at: int | None):
        self.conn.execute('''UPDATE credentials SET staff_missing_since=?,staff_loss_notified_at=?
            WHERE guild_id=? AND user_id=?''', (missing_since,notified_at,guild_id,user_id))

    def mark_permission_warning(self, guild_id: int, user_id: int, warning_key: str | None):
        self.conn.execute('''UPDATE credentials SET permission_warning_key=?
            WHERE guild_id=? AND user_id=?''', (warning_key,guild_id,user_id))

    def consume_pending(self, guild_id, user_id, now):
        # Atomic one-time reveal: a failure while sending cannot be retried.
        with self.tx():
            row = self.credential(guild_id,user_id)
            if not row or not row['pending_secret'] or row['pending_until'] <= now:
                return None
            self.conn.execute("UPDATE credentials SET pending_secret=NULL, pending_until=NULL, collected_at=? WHERE guild_id=? AND user_id=?",(now,guild_id,user_id))
        return row['pending_secret']

    def purge_pending(self, now):
        with self.tx():
            self.conn.execute("UPDATE credentials SET pending_secret=NULL,pending_until=NULL WHERE pending_until<=?", (now,))

    def failed_attempt(self, guild_id, user_id, now):
        row = self.credential(guild_id,user_id)
        if not row:
            return 0
        attempts = row['attempts'] + 1
        # 5 failed attempts -> 15 minute lockout; owner can reissue.
        lock_until = now + 900 if attempts >= 5 else 0
        with self.tx():
            self.conn.execute("UPDATE credentials SET attempts=?,locked_until=? WHERE guild_id=? AND user_id=?",(0 if lock_until else attempts,lock_until,guild_id,user_id))
        return lock_until

    def reset_attempts(self, guild_id, user_id):
        self.conn.execute("UPDATE credentials SET attempts=0, locked_until=0 WHERE guild_id=? AND user_id=?",(guild_id,user_id))

    def revoke_credential(self, guild_id, user_id):
        self.conn.execute("DELETE FROM credentials WHERE guild_id=? AND user_id=?",(guild_id,user_id))

    def session(self, guild_id, user_id):
        return self.conn.execute("SELECT * FROM sessions WHERE guild_id=? AND user_id=?",(guild_id,user_id)).fetchone()

    def all_sessions(self):
        return self.conn.execute("SELECT * FROM sessions").fetchall()

    def put_session(self, guild_id,user_id,role_id,expires_at,started_at,state="granting"):
        with self.tx():
            self.conn.execute("""INSERT INTO sessions
                (guild_id,user_id,role_id,expires_at,started_at,state,termination_reason)
                VALUES (?,?,?,?,?,?,NULL) ON CONFLICT(guild_id,user_id)
                DO UPDATE SET role_id=excluded.role_id,expires_at=excluded.expires_at,
                started_at=excluded.started_at,state=excluded.state,
                termination_reason=NULL""",
                (guild_id,user_id,role_id,expires_at,started_at,state))

    def mark_granted(self,guild_id,user_id):
        self.conn.execute("UPDATE sessions SET state='active' WHERE guild_id=? AND user_id=?",(guild_id,user_id))

    def force_expire(self,guild_id,user_id,reason="revocation_pending"):
        # Remember why removal was requested, including across crashes/restarts.
        # Preserve the original planned expiry for the audit trail.
        self.conn.execute("""UPDATE sessions SET termination_reason=?
            WHERE guild_id=? AND user_id=?""",(reason,guild_id,user_id))

    def end_session(self, guild_id, user_id, reason, ended_at=None):
        """Atomically archive and remove a session, only after role revocation
        succeeded or there is no longer any role to revoke. Safe on retries.
        """
        ended_at = int(time.time()) if ended_at is None else int(ended_at)
        with self.tx():
            row = self.session(guild_id, user_id)
            if row is None:
                return False
            self.conn.execute("""INSERT INTO session_history
                (guild_id,user_id,role_id,started_at,expires_at,ended_at,end_reason)
                VALUES (?,?,?,?,?,?,?)""",
                (guild_id,user_id,row['role_id'],row['started_at'],row['expires_at'],ended_at,reason))
            self.conn.execute("DELETE FROM sessions WHERE guild_id=? AND user_id=?",(guild_id,user_id))
            return True

    def delete_session(self,guild_id,user_id):
        # Compatibility with v0.1 call sites. Prefer explicit reasons in new code.
        return self.end_session(guild_id,user_id,"removed")

    # Retention and case-specific privacy decisions. Background cleanup never
    # removes active sessions or authentication credentials.
    def purge_history(self, cutoff: int, now: int) -> int:
        with self.tx():
            cur = self.conn.execute('''DELETE FROM session_history
                WHERE ended_at < ? AND (hold_until IS NULL OR hold_until <= ?)''',
                (cutoff, now))
            return cur.rowcount

    def hold_history(self, row_id: int, guild_id: int, user_id: int,
                     until: int, reference: str) -> bool:
        if not reference or len(reference) > 64:
            raise ValueError('case reference required')
        with self.tx():
            cur = self.conn.execute('''UPDATE session_history
                SET hold_until=?,hold_reference=? WHERE id=? AND guild_id=? AND user_id=?''',
                (until, reference, row_id, guild_id, user_id))
            return cur.rowcount == 1

    def release_history(self, row_id: int, guild_id: int, user_id: int) -> bool:
        with self.tx():
            cur = self.conn.execute('''UPDATE session_history
                SET hold_until=NULL,hold_reference=NULL
                WHERE id=? AND guild_id=? AND user_id=?''', (row_id, guild_id, user_id))
            return cur.rowcount == 1

    def privacy_counts(self, *, guild_id: int | None = None,
                       user_id: int | None = None) -> dict:
        filters = []
        args = []
        if guild_id is not None:
            filters.append('guild_id=?'); args.append(int(guild_id))
        if user_id is not None:
            filters.append('user_id=?'); args.append(int(user_id))
        where = (' WHERE ' + ' AND '.join(filters)) if filters else ''
        return {table: self.conn.execute('SELECT COUNT(*) FROM ' + table + where, args).fetchone()[0]
                for table in ('credentials', 'sessions', 'session_history')}

    def history_rows_for_review(self, guild_id: int, user_id: int, limit: int = 8):
        return self.conn.execute('''SELECT id,started_at,ended_at,end_reason,hold_until
            FROM session_history WHERE guild_id=? AND user_id=?
            ORDER BY ended_at DESC LIMIT ?''',(guild_id,user_id,limit)).fetchall()

    def apply_erasure_event(self, event: dict, now: int):
        """Reapply after restoring a snapshot, retaining unreconciled sessions.

        Only data from before the approved request is affected: if a server is
        reconfigured or new access is issued later, that isn't silently erased.
        """
        scope = event['type']
        at = int(event['created_at'])
        gid = event.get('guild_id')
        uid = event.get('user_id')
        terms, vals = [], []
        if gid is not None:
            terms.append('guild_id=?'); vals.append(int(gid))
        if scope in {'erase_user', 'erase_history'}:
            terms.append('user_id=?'); vals.append(int(uid))
        selector = ' AND '.join(terms)
        with self.tx():
            if scope != 'erase_history':
                self.conn.execute(f'DELETE FROM credentials WHERE {selector} AND issued_at<=?', (*vals,at))
                self.conn.execute(f'''UPDATE sessions SET termination_reason='privacy_erasure'
                    WHERE {selector} AND started_at<=?''', (*vals,at))
            self.conn.execute(f'''DELETE FROM session_history WHERE {selector} AND started_at<=?
                AND (hold_until IS NULL OR hold_until<=?)''', (*vals,at,now))
            if scope == 'erase_guild':
                # Keep config if a revocation still requires the role IDs.
                pending = self.conn.execute('''SELECT COUNT(*) FROM sessions
                    WHERE guild_id=? AND started_at<=?''', (int(gid), at)).fetchone()[0]
                if not pending:
                    self.conn.execute('''DELETE FROM guild_config
                        WHERE guild_id=? AND updated_at<=?''', (int(gid),at))

    def erasure_pending(self, event: dict) -> bool:
        if event['type'] == 'erase_history':
            return False
        terms, values = ['started_at<=?'], [int(event['created_at'])]
        if event.get('guild_id') is not None:
            terms.append('guild_id=?'); values.append(int(event['guild_id']))
        if event.get('user_id') is not None:
            terms.append('user_id=?'); values.append(int(event['user_id']))
        return bool(self.conn.execute(
            'SELECT 1 FROM sessions WHERE '+' AND '.join(terms)+' LIMIT 1',values).fetchone())

    def mark_guild_removed(self, guild_id: int, now: int) -> None:
        self.conn.execute('''INSERT INTO departed_guilds(guild_id,removed_at) VALUES (?,?)
            ON CONFLICT(guild_id) DO UPDATE SET removed_at=excluded.removed_at''', (guild_id,now))

    def mark_guild_joined(self, guild_id: int) -> None:
        self.conn.execute('DELETE FROM departed_guilds WHERE guild_id=?',(guild_id,))

    def purge_departed_guilds(self, cutoff: int, now: int) -> int:
        """Seven-day grace; never discard unresolved role revocations or held history."""
        count=0
        with self.tx():
            for row in self.conn.execute('SELECT guild_id FROM departed_guilds WHERE removed_at<?',(cutoff,)).fetchall():
                gid=row['guild_id']
                if self.conn.execute('SELECT 1 FROM sessions WHERE guild_id=? LIMIT 1',(gid,)).fetchone():
                    continue
                if self.conn.execute('''SELECT 1 FROM session_history
                    WHERE guild_id=? AND hold_until>? LIMIT 1''',(gid,now)).fetchone():
                    continue
                self.conn.execute('DELETE FROM credentials WHERE guild_id=?',(gid,))
                self.conn.execute('DELETE FROM session_history WHERE guild_id=?',(gid,))
                self.conn.execute('DELETE FROM guild_config WHERE guild_id=?',(gid,))
                self.conn.execute('DELETE FROM departed_guilds WHERE guild_id=?',(gid,))
                count+=1
        return count
