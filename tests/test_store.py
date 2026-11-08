from gatekeeper.store import Store


def test_setup_and_issuance(tmp_path):
    db = Store(str(tmp_path / 'db.sqlite3'))
    assert db.config(1) is None
    assert not db.set_config(1, 101, 102, [15, 60, 240], None)
    assert db.config(1)['elevated_role_id'] == 102
    assert not db.set_config(1, 101, 102, [60], None)
    db.issue(1, 201, 'testhash', b'encrypted', 2000)
    assert db.credential(1, 201)['phrase_hash'] == 'testhash'
    assert db.consume_pending(1, 201, 1000) == b'encrypted'
    assert db.consume_pending(1, 201, 1000) is None
    assert db.credential(1, 201)['pending_secret'] is None
    assert db.credential(1, 201)['phrase_hash'] == 'testhash'
    db.close()


def test_sessions_restart_and_change_role(tmp_path):
    db_path = str(tmp_path / 'db.sqlite3')
    db = Store(db_path)
    db.set_config(1, 101, 102, [60], None)
    db.put_session(1, 200, 102, 1100, 1000, 'granting')
    assert db.count_sessions(1) == 1
    try:
        db.set_config(1, 101, 103, [60], None)
    except ValueError:
        pass
    else:
        raise AssertionError('Must refuse role changes with active sessions')
    db.close()

    db = Store(db_path)
    assert db.session(1, 200)['state'] == 'granting'
    db.mark_granted(1, 200)
    assert db.session(1, 200)['state'] == 'active'
    db.force_expire(1, 200)
    assert db.session(1, 200)['expires_at'] == 1100
    assert db.session(1, 200)['termination_reason'] == 'revocation_pending'
    db.delete_session(1, 200)
    assert db.count_sessions(1) == 0
    assert db.set_config(1, 101, 103, [60], None)
    db.close()


def test_lockout_and_revocation(tmp_path):
    db = Store(str(tmp_path / 'db.sqlite3'))
    db.issue(1, 2, 'hash', b'encrypted', 3000)
    for i in range(4):
        assert db.failed_attempt(1, 2, 1000) == 0
    assert db.failed_attempt(1, 2, 1000) == 1900
    assert db.credential(1, 2)['locked_until'] == 1900
    db.reset_attempts(1, 2)
    assert db.credential(1, 2)['locked_until'] == 0
    db.revoke_credential(1, 2)
    assert db.credential(1, 2) is None
    db.close()


def test_history_tracks_reason_and_survives_restart(tmp_path):
    db_path = str(tmp_path / 'history.sqlite3')
    db = Store(db_path)
    db.put_session(123, 456, 789, 1600, 1000, 'granting')
    db.mark_granted(123, 456)
    assert db.end_session(123, 456, 'signed_out', ended_at=1400)
    assert not db.end_session(123, 456, 'signed_out', ended_at=1401)
    assert db.count_sessions(123) == 0
    assert db.count_history(123) == 1
    row = db.history_for_guild(123)[0]
    assert (row['user_id'], row['started_at'], row['expires_at'], row['ended_at'], row['end_reason']) == (456, 1000, 1600, 1400, 'signed_out')
    db.close()
    db = Store(db_path)
    assert db.count_history(123) == 1
    assert db.history_for_guild(999) == []
    db.close()


def test_history_pagination_is_per_server(tmp_path):
    db = Store(str(tmp_path / 'per-server.sqlite3'))
    for user_id in range(1, 21):
        guild = 200 if user_id % 2 == 0 else 100
        db.put_session(guild, user_id, 11, 1300, 1000 + user_id, 'active')
        db.end_session(guild, user_id, 'expired', ended_at=1400 + user_id)
    assert db.count_history(100) == 10
    assert db.count_history(200) == 10
    first = db.history_for_guild(100, limit=8, offset=0)
    second = db.history_for_guild(100, limit=8, offset=8)
    assert len(first) == 8 and len(second) == 2
    assert all(r['guild_id'] == 100 for r in first + second)
    assert first[0]['user_id'] == 19
    assert second[-1]['user_id'] == 1
    db.close()


def test_existing_v01_database_is_migrated_in_place(tmp_path):
    import sqlite3
    p = str(tmp_path / 'legacy.sqlite3')
    c = sqlite3.connect(p)
    c.execute('''CREATE TABLE sessions (
        guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        role_id INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        started_at INTEGER NOT NULL, state TEXT NOT NULL,
        PRIMARY KEY (guild_id, user_id))''')
    c.execute("INSERT INTO sessions VALUES (5,6,7,2000,1000,'active')")
    c.commit()
    c.close()
    db = Store(p)
    assert db.session(5, 6)['termination_reason'] is None
    assert db.session(5, 6)['started_at'] == 1000
    db.force_expire(5, 6, 'owner_revoked')
    assert db.session(5, 6)['expires_at'] == 2000
    assert db.session(5, 6)['termination_reason'] == 'owner_revoked'
    assert db.end_session(5, 6, 'owner_revoked', ended_at=1200)
    assert db.history_for_guild(5)[0]['end_reason'] == 'owner_revoked'
    db.close()


def test_setup_edit_preserves_or_revokes_credentials_correctly(tmp_path):
    """Guided setup must keep secrets for cosmetic changes and invalidate on role changes."""
    db = Store(str(tmp_path / 'wizard.sqlite3'))
    db.set_config(1, 101, 102, (15, 60, 240), None)
    db.issue(1, 201, 'hashed-phrase', b'escrow', 9000)
    assert db.set_config(1, 101, 102, (60, 120), 111) is False
    assert db.credential(1, 201)['phrase_hash'] == 'hashed-phrase'
    assert db.set_config(1, 101, 103, (60,), None) is True
    assert db.credential(1, 201) is None
    db.close()


def test_credential_inventory_is_per_server_private_and_paginated(tmp_path):
    db = Store(str(tmp_path / 'credential_inventory.sqlite3'))
    for user in range(25):
        gid = 100 if user < 21 else 200
        db.issue(gid, 1000 + user, f'REDACTED_HASH_{user}', f'REDACTED_CIPHER_{user}'.encode(), 9999999999)
    assert db.count_credentials(100) == 21
    assert db.count_credentials(200) == 4
    assert db.count_credentials(300) == 0
    first = db.credentials_for_guild(100, 10, 0)
    second = db.credentials_for_guild(100, 10, 10)
    third = db.credentials_for_guild(100, 10, 20)
    assert (len(first), len(second), len(third)) == (10, 10, 1)
    assert all(row['user_id'] < 1021 for row in first + second + third)
    assert all('phrase_hash' not in row.keys() and 'pending_secret' not in row.keys() for row in first)
    assert all(row['issued_at'] > 0 for row in first)
    db.revoke_credential(100, 1000)
    assert db.count_credentials(100) == 20
    db.close()


def test_credential_collection_state_and_reissuance(tmp_path):
    db = Store(str(tmp_path / 'state.sqlite3'))
    db.issue(9, 8, 'hashed-first', b'ciphertext-first', 9999999999)
    before = db.credentials_for_guild(9)[0]
    assert before['has_pending_copy'] == 1
    assert before['collected_at'] == 0
    assert db.consume_pending(9, 8, 12345) == b'ciphertext-first'
    collected = db.credentials_for_guild(9)[0]
    assert collected['has_pending_copy'] == 0
    assert collected['collected_at'] == 12345
    assert db.consume_pending(9, 8, 12346) is None
    db.issue(9, 8, 'hashed-replacement', b'ciphertext-replacement', 9999999999)
    replaced = db.credentials_for_guild(9)[0]
    assert replaced['has_pending_copy'] == 1
    assert replaced['collected_at'] == 0
    assert db.count_credentials(9) == 1
    db.close()


def test_v04_credentials_migrate_without_losing_secrets(tmp_path):
    import sqlite3
    path = str(tmp_path / 'v04_credentials.sqlite3')
    conn = sqlite3.connect(path)
    conn.execute('''CREATE TABLE credentials (
        guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        phrase_hash TEXT NOT NULL, pending_secret BLOB, pending_until INTEGER,
        issued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
        locked_until INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (guild_id, user_id)
    )''')
    conn.execute('''INSERT INTO credentials VALUES (7, 8, 'hash', X'0123', 9999999999, 1234, 0, 0)''')
    conn.execute('''INSERT INTO credentials VALUES (7, 9, 'old_hash', NULL, NULL, 1200, 0, 0)''')
    conn.commit()
    conn.close()
    db = Store(path)
    assert db.credential(7, 8)['phrase_hash'] == 'hash'
    assert db.credential(7, 8)['pending_secret'] == b'\x01\x23'
    assert db.count_credentials(7) == 2
    assert db.credentials_for_guild(7)[0]['collected_at'] is None
    assert db.consume_pending(7, 8, 4567) == b'\x01\x23'
    assert db.credentials_for_guild(7)[0]['collected_at'] == 4567
    assert db.credential(7, 9)['phrase_hash'] == 'old_hash'
    db.close()
