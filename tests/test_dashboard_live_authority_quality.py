"""Actual installed Hermes app/middleware on loopback; no lifespan/private services.

Run as a standalone unittest file with HERMES_QUALITY_FIXTURE_RUNNER pointing to
a sealed isolated runner. Set HERMES_QUALITY_PYTHON to its Hermes-enabled
Python interpreter when it differs from the interpreter running this test. This intentionally does not use the plugin's fake
RecordingContext or replace any Dashboard auth/route handler.
"""
import http.client
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

PLUGIN = Path(__file__).resolve().parents[1]
PYTHON = os.environ.get("HERMES_QUALITY_PYTHON", sys.executable)

class LiveDashboard:
    def __init__(self, root=None, port=None):
        self.root = Path(root or tempfile.mkdtemp(prefix='dashboard-', dir=os.environ['HERMES_QUALITY_ARTIFACTS']))
        (self.root / 'home').mkdir(exist_ok=True); home = self.root / 'hermes'; home.mkdir(exist_ok=True)
        shutil.copytree(PLUGIN, home / 'plugins' / 'cozychat', dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', 'tests'))
        self.config = home / 'config.yaml'
        self.config.write_text('plugins:\n  enabled: [cozychat]\n  disabled: []\n  entries:\n    cozychat:\n      settings:\n        relay_url: http://127.0.0.1:9\nlocal_runtime:\n  enabled: false\nsecurity:\n  approval:\n    transport: cozychat\n')
        (home / '.env').write_text('')
        (home / 'cache').mkdir(exist_ok=True)
        (home / 'cache' / 'plugin-catalog.json').write_text(json.dumps(dict(entries=[],removed=[])))
        self.log = (self.root / 'stderr.log').open('a')
        env = dict(HOME=str(self.root / 'home'), HERMES_HOME=str(home), PATH='/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', LANG='en_US.UTF-8')
        self.process = subprocess.Popen([PYTHON, os.environ['HERMES_QUALITY_FIXTURE_RUNNER'], str(self.root)] + ([str(port)] if port else []), cwd=self.root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True)
        self.responses = queue.Queue()
        def read():
            for line in self.process.stdout:
                try: self.responses.put(json.loads(line))
                except ValueError: self.responses.put(dict(unexpected=line))
            self.responses.put(dict(eof=True))
        self.reader = threading.Thread(target=read); self.reader.start()
        ready = self.responses.get(timeout=45)
        if not ready.get('ready'):
            self.process.stdin.close(); self.process.wait(timeout=10); self.reader.join(5); self.process.stdout.close(); self.log.close()
            raise AssertionError((ready, (self.root / 'stderr.log').read_text()))
        self.port, self.token, self.pid = ready['port'], ready['token'], ready['pid']
        self.lock = threading.Lock(); self.consumers = []
    def command(self, op, **args):
        with self.lock:
            self.process.stdin.write(json.dumps(dict(op=op, **args)) + '\n'); self.process.stdin.flush()
            response = self.responses.get(timeout=15)
            if 'result' not in response: raise AssertionError((response, (self.root / 'stderr.log').read_text()))
            return response['result']
    def request(self, method, path, body=None, token='valid'):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=8)
        headers = {'Content-Type': 'application/json'}
        if token: headers['X-Hermes-Session-Token'] = self.token if token == 'valid' else token
        c.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
        response = c.getresponse(); data = response.read(); c.close()
        return response.status, json.loads(data) if data else None
    def writer(self, message):
        home=self.root / 'hermes' / 'profiles' / 'writer'; home.mkdir(parents=True,exist_ok=True)
        if not (home / 'plugins' / 'cozychat').exists():
            shutil.copytree(PLUGIN,home / 'plugins' / 'cozychat',ignore=shutil.ignore_patterns('__pycache__','tests'))
        (home / 'config.yaml').write_bytes(self.config.read_bytes()); (home / '.env').write_text('')
        env=dict(HOME=str(self.root / 'home'),HERMES_HOME=str(home),PATH='/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',LANG='en_US.UTF-8')
        helper=str(Path(os.environ['HERMES_QUALITY_FIXTURE_RUNNER']).with_name('shared-writer.py'))
        result=subprocess.run([PYTHON,helper,str(self.root),message],cwd=self.root,env=env,capture_output=True,text=True,timeout=15)
        (self.root / ('writer-'+message+'.json')).write_text(json.dumps(dict(exit=result.returncode,stdout=result.stdout,stderr=result.stderr)))
        assert result.returncode==0,result.stderr
        return json.loads(result.stdout)
    def finished(self, identity):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            trace = self.command('trace')
            matching = [x for x in trace if x.get('query') == 'quality_id=' + identity]
            if any(x['kind'] == 'disconnect' for x in matching) and any(x['kind'] == 'finished' for x in matching): return
            time.sleep(.01)
        raise AssertionError(('no actual ASGI disconnect/completion', matching))
    def close(self):
        for consumer in self.consumers:
            if consumer.thread.is_alive(): consumer.close()
        if self.process.poll() is None:
            self.process.stdin.write('{"op":"stop"}\n'); self.process.stdin.flush()
        self.process.wait(timeout=15); self.reader.join(5); self.process.stdin.close(); self.process.stdout.close(); self.log.close()
        assert self.process.returncode == 0, (self.root / 'stderr.log').read_text()
        trace = [json.loads(x) for x in (self.root / 'server-trace.jsonl').read_text().splitlines()]
        blocked=[x for x in trace if x['kind'].startswith('blocked-')]
        assert all(x['kind']=='blocked-process' and x.get('argv')==['brv','--version'] for x in blocked),blocked
        assert trace[-1]['kind'] == 'stopped' and not trace[-1]['server_alive']
        (self.root / 'receipt.json').write_text(json.dumps(dict(pid=self.pid, port=self.port, returncode=self.process.returncode, trace_count=len(trace),blocked_metadata_probes=blocked), indent=2))

class Consumer:
    def __init__(self, fixture, identity, since=0):
        self.fixture, self.identity = fixture, identity
        self.connection = http.client.HTTPConnection('127.0.0.1', fixture.port, timeout=8)
        self.connection.request('GET', '/api/plugins/cozychat/events?quality_id=' + identity + '&since=' + str(since), headers={'X-Hermes-Session-Token': fixture.token})
        self.response = self.connection.getresponse(); assert self.response.status == 200
        self.received = []; self.queue = queue.Queue()
        def read():
            try:
                block = []
                while True:
                    line = self.response.readline()
                    if not line: break
                    if line == b'\n':
                        frame = b''.join(block).decode(); block=[]
                        self.received.append(frame); self.queue.put(frame)
                    else: block.append(line)
            except (OSError, ValueError, http.client.HTTPException): pass
            finally: self.queue.put(None)
        self.thread = threading.Thread(target=read); self.thread.start()
        assert self.queue.get(timeout=5) == ': ok\n'
    def event(self):
        frame = self.queue.get(timeout=5); assert frame is not None
        lines = frame.splitlines(); value = json.loads(next(x[6:] for x in lines if x.startswith('data: ')))
        assert int(next(x[4:] for x in lines if x.startswith('id: '))) == value['seq']
        return value
    def close(self):
        self.connection.sock.shutdown(socket.SHUT_RDWR); self.thread.join(5)
        self.response.close(); self.connection.close()
        assert not self.thread.is_alive()
        self.fixture.finished(self.identity + '&since=' + str(self.since))
        (self.fixture.root / ('consumer-'+self.identity+'.json')).write_text(json.dumps(dict(identity=self.identity,since=self.since,received=self.received,reader_completed=not self.thread.is_alive()),indent=2))

@unittest.skipUnless(os.environ.get("HERMES_QUALITY_FIXTURE_RUNNER") and os.environ.get("HERMES_QUALITY_ARTIFACTS"), "requires the sealed disposable real Dashboard fixture")
class DashboardLiveAuthorityQualityTests(unittest.TestCase):
    def setUp(self): self.fixture = LiveDashboard()
    def tearDown(self): self.fixture.close()
    def consumer(self, identity, since=0):
        c = Consumer(self.fixture, identity, since); c.since=since; self.fixture.consumers.append(c); return c
    def test_mounted_real_middleware_auth_and_runtime_disabled_gate(self):
        f=self.fixture
        for token in (None, 'unissued-quality-fixture'):
            for path in ('info', 'events', 'approvals'):
                self.assertEqual(f.request('GET', '/api/plugins/cozychat/' + path, token=token), (401, {'detail':'Unauthorized'}))
        status, info = f.request('GET', '/api/plugins/cozychat/info'); self.assertEqual(status,200)
        self.assertEqual(info['serve_pid'], f.pid); self.assertEqual(info['state'], 'shared-v1'); self.assertTrue(info['approval_transport'])
        c=self.consumer('auth'); c.close()
        original=f.config.read_text(); f.config.write_text(original.replace('disabled: []', 'disabled: [cozychat]'))
        self.assertEqual(f.request('GET', '/api/plugins/cozychat/events'), (404,{'detail':'Plugin not found'}))
        self.assertEqual(f.request('GET', '/api/plugins/cozychat/events', token=None), (401,{'detail':'Unauthorized'}))
        f.config.write_text(original); self.assertEqual(f.request('GET','/api/plugins/cozychat/info')[0],200)
    def test_room_hooks_real_two_consumers_retirement_order_and_cursor_reconnect(self):
        f=self.fixture; a=self.consumer('room-a'); b=self.consumer('room-b')
        history=[]
        for index in range(3):
            f.command('hook',name='on_room_member_activity',args=dict(kind='message.interim', room_id='quality-room', payload=dict(text=f'@user message {index}')))
            first=a.event(); second=b.event(); self.assertEqual(first,second); self.assertEqual(first['payload']['text'],f'@user message {index}'); history.append(first)
        a.close(); retired=list(a.received)
        f.command('hook',name='on_room_member_activity',args=dict(kind='request.opened',room_id='quality-room',payload=dict(request_id='quality-request')))
        next_event=b.event(); self.assertEqual(next_event['seq'], history[-1]['seq']+1); self.assertEqual(a.received,retired)
        c=self.consumer('room-c', history[-1]['seq']); self.assertEqual(c.event(), next_event)
        b.close(); retired_b=list(b.received)
        f.command('hook',name='on_room_member_activity',args=dict(kind='message.interim',room_id='quality-room',payload=dict(text='@user final')))
        last=c.event(); self.assertEqual(last['seq'],next_event['seq']+1); self.assertEqual(b.received,retired_b); self.assertEqual(a.received,retired)
        c.close()
    def test_shared_profile_writer_and_actual_plugin_unload_preserve_live_consumer(self):
        f=self.fixture; a=self.consumer('state-a'); b=self.consumer('state-b')
        writer=f.writer('first'); self.assertNotEqual(writer['pid'],f.pid)
        first=a.event(); self.assertEqual(b.event(),first); self.assertEqual(first['payload']['text'],'first')
        self.assertEqual(f.request('GET','/api/plugins/cozychat/info')[1]['writer_pid'],writer['pid'])
        a.close(); retired=list(a.received)
        writer2=f.writer('second'); second=b.event(); self.assertEqual(second['seq'],first['seq']+1)
        c=self.consumer('state-c',first['seq']); self.assertEqual(c.event(),second)
        b.close(); retired_b=list(b.received)
        before=f.command('state'); unloaded=f.command('unload'); self.assertEqual(unloaded,dict(hooks=0,transport=False))
        f.command('hook',name='on_room_member_activity',args=dict(kind='message.interim',room_id='retired',payload=dict(text='must not emit')))
        self.assertEqual(f.command('state'),before)
        f.writer('third'); third=c.event(); self.assertEqual(third['seq'],second['seq']+1); self.assertEqual(third['payload']['text'],'third')
        self.assertEqual(a.received,retired); self.assertEqual(b.received,retired_b); c.close()
    def test_complete_room_cron_catalog_edges_join_actual_live_hook_receipt(self):
        result=self.fixture.command('room-cron-edges')
        self.assertIn('error',result['no_phone']);self.assertTrue(result['delivery_only'])
        self.assertEqual(len(result['room']),2);self.assertEqual(len(result['cron']),1)
        self.assertEqual(result['muted_replies'],[]);self.assertEqual(result['default_muted_subagent'],[])
        self.assertEqual(result['privacy'][0]['payload']['preview'],'New activity')
    def test_real_host_approval_transport_answer_timeout_and_live_consumers(self):
        f=self.fixture; a=self.consumer('approval-a'); b=self.consumer('approval-b')
        request=f.command('approval',timeout=5)
        deadline=time.monotonic()+3; card=None
        while time.monotonic()<deadline:
            status, listing=f.request('GET','/api/plugins/cozychat/approvals'); self.assertEqual(status,200)
            card=next((x for x in listing['approvals'] if x['request_id']==request['request_id']),None)
            if card is not None: break
            time.sleep(.01)
        self.assertIsNotNone(card)
        self.assertEqual(card['allowed_choices'],['once','deny']); self.assertNotIn('digest',card); self.assertNotIn('command',card)
        route='/api/plugins/cozychat/approvals/'+request['request_id']
        for choice in ('', 'always', {'once':True}): self.assertEqual(f.request('POST',route,dict(choice=choice))[0],400)
        self.assertEqual(f.request('POST',route,dict(choice='once'),token='unissued-quality-fixture')[0],401)
        a.close(); retired=list(a.received)
        self.assertEqual(f.request('POST',route,dict(choice='once'))[0],200)
        result=f.command('approval-result',id=request['request_id']); self.assertEqual(result,dict(choice='once',failure=None))
        self.assertEqual(f.request('POST',route,dict(choice='deny'))[0],404)
        self.assertEqual(f.request('GET','/api/plugins/cozychat/approvals'),(200,{'approvals':[]})); self.assertEqual(a.received,retired)
        # Real immutable host request, actual host deadline and source waiter cleanup.
        timeout=f.command('approval',timeout=.3)
        self.assertEqual(f.command('approval-result',id=timeout['request_id']),dict(choice='deny',failure='timeout'))
        self.assertEqual(f.request('GET','/api/plugins/cozychat/approvals'),(200,{'approvals':[]}))
        self.assertEqual(f.request('POST','/api/plugins/cozychat/approvals/'+timeout['request_id'],dict(choice='once'))[0],404)
        b.close(); self.assertEqual(a.received,retired)

if __name__ == '__main__': unittest.main()
