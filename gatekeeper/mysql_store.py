"""MySQL/MariaDB storage backend for Umask.

Implements the same public interface as gatekeeper.store.Store (SQLite).  All
read-modify-write operations that control credentials and sessions use InnoDB
transactions.  SQLite remains available for development and local tests.

Production requirement: run only ONE Umask bot process against this database.
"""
from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager


class MySQLStore:
    def __init__(self, *, host: str, user: str, password: str, database: str,
                 port: int = 3306, ssl_ca: str | None = None):
        try:
            import pymysql
            from pymysql.cursors import DictCursor
        except ImportError as e:
            raise RuntimeError('MySQL backend requires PyMySQL: pip install -r requirements.txt') from e
        if not all([host, user, password, database]):
            raise ValueError('MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD and MYSQL_DATABASE are required')
        kwargs = dict(host=host, port=int(port), user=user, password=password,
                      database=database, charset='utf8mb4', cursorclass=DictCursor,
                      connect_timeout=10, read_timeout=15, write_timeout=15,
                      autocommit=True)
        if ssl_ca:
            # Verify the DB server certificate and hostname if the provider
            # supplies an appropriate CA certificate (not just encryption).
            kwargs.update(ssl_ca=ssl_ca, ssl_verify_cert=True, ssl_verify_identity=True)
        self.conn = pymysql.connect(**kwargs)
        self._lock = threading.RLock()
        self._init_schema()

    @classmethod
    def from_env(cls):
        return cls(host=os.getenv('MYSQL_HOST', ''), user=os.getenv('MYSQL_USER', ''),
                   password=os.getenv('MYSQL_PASSWORD', ''),
                   database=os.getenv('MYSQL_DATABASE', ''),
                   port=int(os.getenv('MYSQL_PORT', '3306')),
                   ssl_ca=os.getenv('MYSQL_SSL_CA') or None)

    def _init_schema(self):
        statements = [
            '''CREATE TABLE IF NOT EXISTS guild_config (
                guild_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
                staff_role_id BIGINT UNSIGNED NOT NULL,
                elevated_role_id BIGINT UNSIGNED NOT NULL,
                durations VARCHAR(160) NOT NULL,
                alert_channel_id BIGINT UNSIGNED NULL,
                updated_at BIGINT NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''',
            '''CREATE TABLE IF NOT EXISTS credentials (
                guild_id BIGINT UNSIGNED NOT NULL,
                user_id BIGINT UNSIGNED NOT NULL,
                phrase_hash VARCHAR(512) NOT NULL,
                pending_secret BLOB NULL,
                pending_until BIGINT NULL,
                issued_at BIGINT NOT NULL,
                attempts INT NOT NULL DEFAULT 0,
                locked_until BIGINT NOT NULL DEFAULT 0,
                collected_at BIGINT NULL,
                PRIMARY KEY (guild_id, user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''',
            '''CREATE TABLE IF NOT EXISTS sessions (
                guild_id BIGINT UNSIGNED NOT NULL,
                user_id BIGINT UNSIGNED NOT NULL,
                role_id BIGINT UNSIGNED NOT NULL,
                expires_at BIGINT NOT NULL,
                started_at BIGINT NOT NULL,
                state VARCHAR(32) NOT NULL,
                termination_reason VARCHAR(80) NULL,
                PRIMARY KEY (guild_id, user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''',
            '''CREATE TABLE IF NOT EXISTS session_history (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                guild_id BIGINT UNSIGNED NOT NULL,
                user_id BIGINT UNSIGNED NOT NULL,
                role_id BIGINT UNSIGNED NOT NULL,
                started_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                ended_at BIGINT NOT NULL,
                end_reason VARCHAR(80) NOT NULL,
                hold_until BIGINT NULL,
                hold_reference VARCHAR(64) NULL,
                INDEX session_history_guild_ended (guild_id, ended_at, id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''',
            '''CREATE TABLE IF NOT EXISTS departed_guilds (
                guild_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
                removed_at BIGINT NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''',
        ]
        with self._lock:
            self.conn.ping(reconnect=True)
            with self.conn.cursor() as cur:
                for stmt in statements:
                    cur.execute(stmt)
                cur.execute('SHOW COLUMNS FROM session_history')
                fields = {r['Field'] for r in cur.fetchall()}
                if 'hold_until' not in fields:
                    cur.execute('ALTER TABLE session_history ADD COLUMN hold_until BIGINT NULL')
                if 'hold_reference' not in fields:
                    cur.execute('ALTER TABLE session_history ADD COLUMN hold_reference VARCHAR(64) NULL')

    @contextmanager
    def tx(self):
        """One transaction protected against other threads using our connection."""
        with self._lock:
            self.conn.ping(reconnect=True)
            self.conn.begin()
            try:
                with self.conn.cursor() as cur:
                    yield cur
            except BaseException:
                self.conn.rollback()
                raise
            else:
                self.conn.commit()

    def _one(self, sql, args=()):
        with self._lock:
            self.conn.ping(reconnect=True)
            with self.conn.cursor() as cur:
                cur.execute(sql, args)
                return cur.fetchone()

    def _all(self, sql, args=()):
        with self._lock:
            self.conn.ping(reconnect=True)
            with self.conn.cursor() as cur:
                cur.execute(sql, args)
                return list(cur.fetchall())

    def _write(self, sql, args=()):
        with self.tx() as cur:
            cur.execute(sql, args)

    def close(self):
        with self._lock:
            self.conn.close()

    def config(self, guild_id):
        return self._one('SELECT * FROM guild_config WHERE guild_id=%s', (guild_id,))

    def configured_guild_ids(self) -> set[int]:
        return {int(row['guild_id']) for row in self._all('SELECT guild_id FROM guild_config')}

    def set_config(self, guild_id, staff_role_id, elevated_role_id, durations, alert_channel_id):
        with self.tx() as cur:
            cur.execute('SELECT * FROM guild_config WHERE guild_id=%s FOR UPDATE', (guild_id,))
            existing = cur.fetchone()
            change = bool(existing and (existing['staff_role_id'] != staff_role_id or
                                       existing['elevated_role_id'] != elevated_role_id))
            if change:
                cur.execute('SELECT COUNT(*) AS n FROM sessions WHERE guild_id=%s', (guild_id,))
                if cur.fetchone()['n']:
                    raise ValueError('Sign out or revoke all active sessions before changing protected roles.')
                cur.execute('DELETE FROM credentials WHERE guild_id=%s', (guild_id,))
            cur.execute('''INSERT INTO guild_config
                  (guild_id,staff_role_id,elevated_role_id,durations,alert_channel_id,updated_at)
                  VALUES (%s,%s,%s,%s,%s,%s)
                  ON DUPLICATE KEY UPDATE staff_role_id=VALUES(staff_role_id),
                    elevated_role_id=VALUES(elevated_role_id), durations=VALUES(durations),
                    alert_channel_id=VALUES(alert_channel_id), updated_at=VALUES(updated_at)''',
                        (guild_id,staff_role_id,elevated_role_id,','.join(map(str,durations)),
                         alert_channel_id,int(time.time())))
        return change

    def count_sessions(self, guild_id):
        return self._one('SELECT COUNT(*) AS n FROM sessions WHERE guild_id=%s', (guild_id,))['n']

    def sessions_for_guild(self, guild_id, limit=8, offset=0):
        return self._all('''SELECT * FROM sessions WHERE guild_id=%s
            ORDER BY started_at DESC, user_id ASC LIMIT %s OFFSET %s''',
                         (guild_id, int(limit), int(offset)))

    def count_history(self, guild_id):
        return self._one('SELECT COUNT(*) AS n FROM session_history WHERE guild_id=%s', (guild_id,))['n']

    def history_for_guild(self, guild_id, limit=8, offset=0):
        return self._all('''SELECT * FROM session_history WHERE guild_id=%s
            ORDER BY ended_at DESC,id DESC LIMIT %s OFFSET %s''',
                         (guild_id,int(limit),int(offset)))

    def credential(self, guild_id, user_id):
        return self._one('SELECT * FROM credentials WHERE guild_id=%s AND user_id=%s',
                         (guild_id,user_id))

    def count_credentials(self, guild_id):
        return self._one('SELECT COUNT(*) AS n FROM credentials WHERE guild_id=%s', (guild_id,))['n']

    def credentials_for_guild(self, guild_id, limit=10, offset=0):
        # Do not expose either verifier hashes or escrow ciphertext in dashboard queries.
        return self._all('''SELECT user_id, issued_at, pending_until,
                 CASE WHEN pending_secret IS NOT NULL THEN 1 ELSE 0 END AS has_pending_copy,
                 collected_at FROM credentials WHERE guild_id=%s
                 ORDER BY issued_at DESC, user_id ASC LIMIT %s OFFSET %s''',
                         (guild_id,int(limit),int(offset)))

    def issue(self, guild_id, user_id, hash_value, encrypted, valid_until):
        with self.tx() as cur:
            cur.execute('''INSERT INTO credentials
              (guild_id,user_id,phrase_hash,pending_secret,pending_until,issued_at,attempts,locked_until,collected_at)
              VALUES (%s,%s,%s,%s,%s,%s,0,0,0)
              ON DUPLICATE KEY UPDATE phrase_hash=VALUES(phrase_hash),
              pending_secret=VALUES(pending_secret),pending_until=VALUES(pending_until),
              issued_at=VALUES(issued_at),attempts=0,locked_until=0,collected_at=0''',
                        (guild_id,user_id,hash_value,encrypted,valid_until,int(time.time())))

    def consume_pending(self, guild_id, user_id, now):
        with self.tx() as cur:
            cur.execute('''SELECT pending_secret,pending_until FROM credentials
                        WHERE guild_id=%s AND user_id=%s FOR UPDATE''', (guild_id,user_id))
            row = cur.fetchone()
            if not row or not row['pending_secret'] or row['pending_until'] <= now:
                return None
            cur.execute('''UPDATE credentials SET pending_secret=NULL,pending_until=NULL,collected_at=%s
                        WHERE guild_id=%s AND user_id=%s''', (now,guild_id,user_id))
            return row['pending_secret']

    def purge_pending(self, now):
        self._write('''UPDATE credentials SET pending_secret=NULL,pending_until=NULL
                       WHERE pending_until<=%s''', (now,))

    def failed_attempt(self, guild_id, user_id, now):
        with self.tx() as cur:
            cur.execute('''SELECT attempts FROM credentials
                        WHERE guild_id=%s AND user_id=%s FOR UPDATE''', (guild_id,user_id))
            row = cur.fetchone()
            if not row:
                return 0
            attempts = row['attempts'] + 1
            lock_until = now + 900 if attempts >= 5 else 0
            cur.execute('''UPDATE credentials SET attempts=%s,locked_until=%s
                        WHERE guild_id=%s AND user_id=%s''',
                        (0 if lock_until else attempts,lock_until,guild_id,user_id))
            return lock_until

    def reset_attempts(self, guild_id, user_id):
        self._write('UPDATE credentials SET attempts=0,locked_until=0 WHERE guild_id=%s AND user_id=%s',
                    (guild_id,user_id))

    def revoke_credential(self, guild_id, user_id):
        self._write('DELETE FROM credentials WHERE guild_id=%s AND user_id=%s', (guild_id,user_id))

    def session(self, guild_id, user_id):
        return self._one('SELECT * FROM sessions WHERE guild_id=%s AND user_id=%s', (guild_id,user_id))

    def all_sessions(self):
        return self._all('SELECT * FROM sessions')

    def put_session(self, guild_id,user_id,role_id,expires_at,started_at,state='granting'):
        with self.tx() as cur:
            cur.execute('''INSERT INTO sessions
                 (guild_id,user_id,role_id,expires_at,started_at,state,termination_reason)
                 VALUES (%s,%s,%s,%s,%s,%s,NULL)
                 ON DUPLICATE KEY UPDATE role_id=VALUES(role_id),expires_at=VALUES(expires_at),
                 started_at=VALUES(started_at),state=VALUES(state),termination_reason=NULL''',
                        (guild_id,user_id,role_id,expires_at,started_at,state))

    def mark_granted(self, guild_id, user_id):
        self._write("UPDATE sessions SET state='active' WHERE guild_id=%s AND user_id=%s",
                    (guild_id,user_id))

    def force_expire(self, guild_id, user_id, reason='revocation_pending'):
        self._write('''UPDATE sessions SET termination_reason=%s
                       WHERE guild_id=%s AND user_id=%s''',(reason,guild_id,user_id))

    def end_session(self, guild_id, user_id, reason, ended_at=None):
        ended_at = int(time.time()) if ended_at is None else int(ended_at)
        with self.tx() as cur:
            cur.execute('SELECT * FROM sessions WHERE guild_id=%s AND user_id=%s FOR UPDATE',
                        (guild_id,user_id))
            row = cur.fetchone()
            if row is None:
                return False
            cur.execute('''INSERT INTO session_history
                (guild_id,user_id,role_id,started_at,expires_at,ended_at,end_reason)
                VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                        (guild_id,user_id,row['role_id'],row['started_at'],row['expires_at'],ended_at,reason))
            cur.execute('DELETE FROM sessions WHERE guild_id=%s AND user_id=%s',(guild_id,user_id))
            return True

    def delete_session(self, guild_id, user_id):
        return self.end_session(guild_id,user_id,'removed')

    def purge_history(self, cutoff: int, now: int) -> int:
        with self.tx() as cur:
            cur.execute('''DELETE FROM session_history WHERE ended_at < %s
                AND (hold_until IS NULL OR hold_until <= %s)''', (cutoff,now))
            return cur.rowcount

    def hold_history(self, row_id: int, guild_id: int, user_id: int,
                     until: int, reference: str) -> bool:
        if not reference or len(reference) > 64:
            raise ValueError('case reference required')
        with self.tx() as cur:
            cur.execute('''UPDATE session_history SET hold_until=%s,hold_reference=%s
                WHERE id=%s AND guild_id=%s AND user_id=%s''',
                (until,reference,row_id,guild_id,user_id))
            return cur.rowcount == 1

    def release_history(self, row_id: int, guild_id: int, user_id: int) -> bool:
        with self.tx() as cur:
            cur.execute('''UPDATE session_history SET hold_until=NULL,hold_reference=NULL
                WHERE id=%s AND guild_id=%s AND user_id=%s''',
                (row_id,guild_id,user_id))
            return cur.rowcount == 1

    def privacy_counts(self, *, guild_id: int | None = None,
                       user_id: int | None = None) -> dict:
        terms, vals = [], []
        if guild_id is not None: terms.append('guild_id=%s'); vals.append(int(guild_id))
        if user_id is not None: terms.append('user_id=%s'); vals.append(int(user_id))
        where = (' WHERE ' + ' AND '.join(terms)) if terms else ''
        return {table: self._one('SELECT COUNT(*) AS n FROM '+table+where, vals)['n']
                for table in ('credentials','sessions','session_history')}

    def history_rows_for_review(self, guild_id: int, user_id: int, limit: int = 8):
        return self._all('''SELECT id,started_at,ended_at,end_reason,hold_until
            FROM session_history WHERE guild_id=%s AND user_id=%s
            ORDER BY ended_at DESC LIMIT %s''',(guild_id,user_id,limit))

    def apply_erasure_event(self, event: dict, now: int):
        scope = event['type']; at = int(event['created_at'])
        gid = event.get('guild_id'); uid = event.get('user_id')
        terms, vals = [], []
        if gid is not None: terms.append('guild_id=%s'); vals.append(int(gid))
        if scope in {'erase_user', 'erase_history'}: terms.append('user_id=%s'); vals.append(int(uid))
        selector = ' AND '.join(terms)
        with self.tx() as cur:
            if scope != 'erase_history':
                cur.execute(f'DELETE FROM credentials WHERE {selector} AND issued_at<=%s',(*vals,at))
                cur.execute(f'''UPDATE sessions SET termination_reason='privacy_erasure'
                    WHERE {selector} AND started_at<=%s''',(*vals,at))
            cur.execute(f'''DELETE FROM session_history WHERE {selector} AND started_at<=%s
                AND (hold_until IS NULL OR hold_until<=%s)''',(*vals,at,now))
            if scope == 'erase_guild':
                cur.execute('SELECT COUNT(*) AS n FROM sessions WHERE guild_id=%s AND started_at<=%s', (gid,at))
                if cur.fetchone()['n'] == 0:
                    cur.execute('DELETE FROM guild_config WHERE guild_id=%s AND updated_at<=%s',(gid,at))

    def erasure_pending(self, event: dict) -> bool:
        if event['type'] == 'erase_history':
            return False
        terms, values = ['started_at<=%s'], [int(event['created_at'])]
        if event.get('guild_id') is not None:
            terms.append('guild_id=%s'); values.append(int(event['guild_id']))
        if event.get('user_id') is not None:
            terms.append('user_id=%s'); values.append(int(event['user_id']))
        return bool(self._one('SELECT 1 AS found FROM sessions WHERE '+' AND '.join(terms)+' LIMIT 1',values))

    def mark_guild_removed(self, guild_id: int, now: int) -> None:
        self._write('''INSERT INTO departed_guilds(guild_id,removed_at) VALUES (%s,%s)
            ON DUPLICATE KEY UPDATE removed_at=VALUES(removed_at)''',(guild_id,now))

    def mark_guild_joined(self, guild_id: int) -> None:
        self._write('DELETE FROM departed_guilds WHERE guild_id=%s',(guild_id,))

    def purge_departed_guilds(self, cutoff: int, now: int) -> int:
        removed=0
        with self.tx() as cur:
            cur.execute('SELECT guild_id FROM departed_guilds WHERE removed_at<%s FOR UPDATE',(cutoff,))
            for row in cur.fetchall():
                gid=row['guild_id']
                cur.execute('SELECT 1 FROM sessions WHERE guild_id=%s LIMIT 1',(gid,))
                if cur.fetchone(): continue
                cur.execute('''SELECT 1 FROM session_history
                    WHERE guild_id=%s AND hold_until>%s LIMIT 1''',(gid,now))
                if cur.fetchone(): continue
                for table in ('credentials','session_history','guild_config','departed_guilds'):
                    cur.execute(f'DELETE FROM {table} WHERE guild_id=%s',(gid,))
                removed+=1
        return removed
