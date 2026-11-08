"""Regression tests for least-privilege role assignment policy.

Extract the actual verify_bot_role method to keep these tests runnable without
importing discord.py in this packaging environment. Live Discord integration
still needs checking before production use.
"""
import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "gatekeeper" / "bot.py"


def verify_func():
    tree = ast.parse(SOURCE.read_text())
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Umask")
    method = next(n for n in owner.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "verify_bot_role")
    method.returns = None
    for arg in method.args.args:
        arg.annotation = None
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    env = {"SENSITIVE": 0x10}
    exec(compile(module, str(SOURCE), "exec"), env)
    return env["verify_bot_role"]


class FakeRole:
    def __init__(self, position, permissions, *, managed=False, default=False):
        self.position = position
        self.permissions = permissions
        self.managed = managed
        self._default = default

    def __ge__(self, other):
        return self.position >= other.position

    def is_default(self):
        return self._default


async def check(role, *, manage_roles=True):
    me = SimpleNamespace(
        top_role=FakeRole(10, None),
        guild_permissions=SimpleNamespace(manage_roles=manage_roles, value=0x01),
    )
    bot = SimpleNamespace(bot_member=lambda guild: asyncio.sleep(0, result=me))
    await verify_func()(bot, object(), role)


def test_assignment_does_not_require_target_roles_permissions():
    # The bot has Manage Roles but NOT the permission bit 0x10 in the target.
    role = FakeRole(9, SimpleNamespace(value=0x10, administrator=False, manage_roles=False))
    asyncio.run(check(role))


def test_assignment_needs_manage_roles():
    role = FakeRole(9, SimpleNamespace(value=0x10, administrator=False, manage_roles=False))
    with pytest.raises(ValueError, match="Manage Roles"):
        asyncio.run(check(role, manage_roles=False))


def test_assignment_needs_bot_above_role():
    role = FakeRole(10, SimpleNamespace(value=0x10, administrator=False, manage_roles=False))
    with pytest.raises(ValueError, match="above"):
        asyncio.run(check(role))


def test_unsafe_administrator_role_still_blocked():
    role = FakeRole(9, SimpleNamespace(value=0x10, administrator=True, manage_roles=False))
    with pytest.raises(ValueError, match="Administrator"):
        asyncio.run(check(role))
