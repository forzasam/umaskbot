"""Display regression tests that do not require live Discord/network access.

The project normally imports discord.py. To allow testing status formatting in
minimal CI environments, these tests compile the pure status formatters from
bot.py with minimal stand-ins for Discord's markdown-escaping helpers.
"""
import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace


SOURCE = Path(__file__).resolve().parents[1] / "gatekeeper" / "bot.py"


def status_namespace():
    tree = ast.parse(SOURCE.read_text())
    selected = [
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "resolve_user_label"
        or isinstance(node, ast.FunctionDef)
        and node.name in ("credential_state", "safe_display_label")
    ]
    # Strip annotations; avoid importing discord.py solely to test UI strings.
    for node in selected:
        node.returns = None
        for arg in node.args.args:
            arg.annotation = None
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    def escape_mentions(t):
        return t.replace("@", "@\u200b")
    def escape_markdown(t):
        for c in "\\`*_~|":
            t = t.replace(c, "\\" + c)
        return t
    ns = {"discord": SimpleNamespace(utils=SimpleNamespace(
        escape_mentions=escape_mentions, escape_markdown=escape_markdown),
        NotFound=LookupError, Forbidden=PermissionError, HTTPException=OSError)}
    exec(compile(module, str(SOURCE), "exec"), ns)
    return ns


def test_display_label_never_inserts_raw_user_mention():
    f = status_namespace()["safe_display_label"]
    assert f("Another Account", 340024242332762113) == "Another Account (`340024242332762113`)"
    assert "<@340024242332762113>" not in f("Another Account", 340024242332762113)
    assert "@everyone" not in f("@everyone *oops*", 12)
    assert f(None, 12) == "Unknown user (`12`)"


def test_resolve_names_with_fetch_and_history_fallback():
    ns = status_namespace()
    uid = 340024242332762113

    class Guild:
        def get_member(self, user_id):
            return None
        async def fetch_member(self, user_id):
            assert user_id == uid
            return SimpleNamespace(display_name="Server Nickname")

    ns['bot'] = SimpleNamespace(get_user=lambda user_id: None, fetch_user=lambda user_id: None)
    assert asyncio.run(ns['resolve_user_label'](Guild(), uid)) == f"Server Nickname (`{uid}`)"

    class FormerMemberGuild(Guild):
        async def fetch_member(self, user_id):
            raise LookupError()

    class FormerMemberBot:
        def get_user(self, user_id):
            return None
        async def fetch_user(self, user_id):
            return SimpleNamespace(global_name="Former Member", name="former")

    ns['bot'] = FormerMemberBot()
    assert asyncio.run(ns['resolve_user_label'](FormerMemberGuild(), uid)) == f"Former Member (`{uid}`)"

    class MissingUserBot(FormerMemberBot):
        async def fetch_user(self, user_id):
            raise LookupError()

    ns['bot'] = MissingUserBot()
    assert asyncio.run(ns['resolve_user_label'](FormerMemberGuild(), uid)) == f"Unknown user (`{uid}`)"


def test_personal_credential_collection_states(tmp_path):
    from gatekeeper.store import Store

    db = Store(str(tmp_path / 'status.sqlite3'))
    now = 1_700_000_000
    db.issue(111, 222, 'secret-hash', b'encrypted-only', now + 900)
    state = status_namespace()["credential_state"]
    not_collected = db.credential(111, 222)
    assert "Run `/receive`" in state(not_collected, now, personal=True)
    assert "not yet collected" in state(not_collected, now, personal=True)
    assert "window has expired" in state(not_collected, now + 901, personal=True)
    assert "Not collected" in state(not_collected, now + 901)
    db.consume_pending(111, 222, now + 100)
    collected = db.credential(111, 222)
    assert "Collected" in state(collected, now + 101, personal=True)
    assert "not yet" not in state(collected, now + 101, personal=True)
    db.conn.execute("UPDATE credentials SET collected_at=NULL WHERE guild_id=111 AND user_id=222")
    legacy = db.credential(111, 222)
    assert "status unknown" in state(legacy, now + 101, personal=True)
    db.close()


def test_no_raw_mentions_in_dashboard_output_source():
    source = SOURCE.read_text()
    view_code = source.split('class OwnerStatusView(', 1)[1].split('def credential_state(', 1)[0]
    assert '<@{r[' not in view_code
    assert 'async def render(self)' in view_code
    assert 'await self._labels' in view_code
