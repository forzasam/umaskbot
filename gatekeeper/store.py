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
                 collected_at
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
              collected_at=0,attempts=0,locked_until=0""",
              (guild_id,user_id,hash_value,encrypted,valid_until,int(time.time())))

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
