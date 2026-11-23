import ast, pathlib, tempfile, sys, importlib.util
src=pathlib.Path('/mnt/data/umask_multi_role/gatekeeper/bot.py').read_text()
tree=ast.parse(src)
for name in ('parse_durations','maximum_duration'):
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
    ns=globals()
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<extracted>','exec'),ns)
assert parse_durations('15,60,240')==(240,)
assert parse_durations('60')==(60,)
assert maximum_duration('15,60,240')==240
for v in ('0','4','1441','hello',''):
    try: maximum_duration(v)
    except ValueError: pass
    else: raise AssertionError(v)
# Run permission checking against synthetic Discord permission bitmasks by
# extracting the pure function with a fake discord.Permissions constructor.
class Perms:
    def __init__(self, **kwargs):
        self.value=sum({'administrator':1,'manage_roles':2}.get(k,0) for k,v in kwargs.items() if v)
class FakeDiscord:
    Permissions=Perms
class Role:
    def __init__(self,id,perms): self.id=id; self.permissions=type('P',(),{'value':perms})()
class Member:
    def __init__(self,roles):self.roles=roles
node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='permissions_issue')
ns={'discord':FakeDiscord,'SENSITIVE':4,'__name__':'test'}
FakeDiscord.Member=Member
FakeDiscord.Role=Role
exec(compile(ast.Module(body=[node],type_ignores=[]),'<permissions>','exec'),ns)
f=ns['permissions_issue']
staff=Role(1,0);old=Role(2,4);new=Role(3,4)
assert f(Member([staff,old]),1,new,tracked_role_id=2) is None
assert 'overlap' in f(Member([staff,old]),1,new).lower()
assert f(Member([staff]),1,Role(4,0)) is None
assert 'permanent' in f(Member([staff,Role(5,1)]),1,new,tracked_role_id=2).lower()
# SQLite compatibility and session rotation records.
sys.path.insert(0,'/mnt/data/umask_multi_role')
from gatekeeper.store import Store
with tempfile.TemporaryDirectory() as tmp:
    store=Store(tmp+'/test.sqlite')
    store.set_config(100,11,(20,21),(240,),None)
    store.issue(100,50,'hash',b'cipher',9999999999,20)
    store.put_session(100,50,20,9999999999,1000,'active')
    store.end_session(100,50,'credential_replaced')
    store.issue(100,50,'newhash',b'new',9999999999,21)
    assert store.session(100,50) is None
    assert store.credential(100,50)['role_id']==21
    assert store.count_history(100)==1
    store.close()
print('PASS: duration conversion, bounds, tracked-session role checks, no-permissions roles, SQLite session rotation')
