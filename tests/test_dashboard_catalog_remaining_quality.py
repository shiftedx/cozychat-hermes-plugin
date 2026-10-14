"""Remaining source catalogue branches against the sealed real Dashboard fixture."""
import importlib.util
import json
import os
from pathlib import Path
import concurrent.futures
import subprocess
import tempfile
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location(
    'dashboard_live_quality', Path(__file__).with_name('test_dashboard_live_authority_quality.py'))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)

@unittest.skipUnless(os.environ.get('HERMES_QUALITY_FIXTURE_RUNNER') and os.environ.get('HERMES_QUALITY_ARTIFACTS'),
                     'requires sealed disposable real Dashboard fixture')
class DashboardCatalogRemainingQualityTests(unittest.TestCase):
    def setUp(self): self.fixture = live.LiveDashboard()
    def tearDown(self): self.fixture.close()

    def test_all_source_room_kinds_reach_shared_feed_with_push_disabled(self):
        matrix = []
        for muted in (True, False):
            root = Path(tempfile.mkdtemp(prefix='manager-room-', dir=os.environ['HERMES_QUALITY_ARTIFACTS']))
            if muted: (root/'room-push-disabled').write_text('actual loaded settings push_rooms:false')
            f = live.LiveDashboard(root=root)
            try:
                inventory = f.command('room-matrix-devices')
                known = set(inventory['frame_types'].values()) | set(inventory['request_methods'].values())
                self.assertEqual(len(known), 8)
                kinds = sorted(known) + ['future.room.kind']
                consumer = live.Consumer(f, 'manager-room'); consumer.since = 0; f.consumers.append(consumer)
                frames = []
                for index, kind in enumerate(kinds):
                    f.command('hook', name='on_room_member_activity', args=dict(kind=kind, room_id='room-'+str(index),
                              payload=dict(text='@user marker-'+kind, command='private-not-preview', index=index)))
                    frames.append(consumer.event())
                self.assertEqual([x['kind'] for x in frames], kinds)
                self.assertEqual([x['seq'] for x in frames], list(range(1, len(kinds)+1)))
                for index, frame in enumerate(frames):
                    self.assertEqual(frame['room_id'], 'room-'+str(index))
                    self.assertEqual(frame['payload']['text'], '@user marker-'+kinds[index])
                rows = f.command('room-matrix-outbox')
                if muted:
                    self.assertEqual(rows, [])
                else:
                    self.assertEqual([x['device_id'] for x in rows], ['eligible', 'eligible'])
                    self.assertEqual({x['payload']['preview'] for x in rows},
                                     {'A room member needs your OK.', '@user marker-message.interim'})
                    self.assertTrue(all('command' not in x['payload'] for x in rows))
                consumer.close()
                matrix.append(dict(pid=f.pid, root=str(f.root), muted=muted, inventory=inventory, frames=frames, outbox=rows,
                                   consumer_finished=not consumer.thread.is_alive()))
            finally: f.close()
        (self.fixture.root/'actual-manager-room-matrix-receipt.json').write_text(json.dumps(matrix, indent=2))

    def test_real_approval_route_refusals_and_concurrent_exact_once_answer(self):
        f = self.fixture
        self.assertEqual(f.request('POST', '/api/plugins/cozychat/approvals/unissued', {'choice': 'once'})[0], 404)
        ask = f.command('catalog-ask')
        identity = ask['request_id']; route = '/api/plugins/cozychat/approvals/' + identity
        listing = f.request('GET', '/api/plugins/cozychat/approvals')
        self.assertEqual(listing[0], 200)
        card = next(x for x in listing[1]['approvals'] if x['request_id'] == identity)
        self.assertEqual(card['allowed_choices'], ['once', 'deny'])
        self.assertNotIn('command', card); self.assertNotIn('digest', card)
        for choice in ('', 'always', {'once': True}):
            self.assertEqual(f.request('POST', route, {'choice': choice})[0], 400)
        barrier = threading.Barrier(2)
        def answer(choice):
            barrier.wait(timeout=5)
            return choice, f.request('POST', route, {'choice': choice})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            answers = list(pool.map(answer, ['once', 'deny']))
        self.assertEqual(sorted(x[1][0] for x in answers), [200, 409])
        winner = next(choice for choice, response in answers if response[0] == 200)
        self.assertEqual(f.command('catalog-wait', id=identity), winner)
        self.assertEqual(f.request('POST', route, {'choice': 'once'})[0], 404)
        expired = f.command('catalog-ask', timeout=1, opened_at=time.time()-60)
        self.assertEqual(f.request('GET', '/api/plugins/cozychat/approvals'), (200, {'approvals': []}))
        self.assertEqual(f.request('POST', '/api/plugins/cozychat/approvals/' + expired['request_id'], {'choice': 'once'})[0], 409)
        self.assertIsNone(f.command('catalog-wait', id=expired['request_id'], timeout=0))
        self.assertEqual(f.request('POST', '/api/plugins/cozychat/approvals/' + expired['request_id'], {'choice': 'once'})[0], 404)
        (f.root/'approval-route-catalog-receipt.json').write_text(json.dumps({'answers': answers, 'winner': winner, 'expired': expired['request_id']}, indent=2))

    def test_actual_transport_catalog_and_separate_process_answer(self):
        f = self.fixture
        result = f.command('approval-catalog-edges')
        self.assertEqual(result['observer'], {'count': 256, 'oldest_retired': True})
        self.assertEqual(result['repeated']['observer_absent_fallback'], result['repeated']['id'])
        self.assertIsNone(result['repeated']['second_unanswered'])
        self.assertEqual(result['repeated']['after'], [])
        self.assertEqual(result['timeouts'], [{'timeout': 0, 'removed': True}, {'timeout': -1, 'removed': True}])
        lost = result['lost_notification']
        self.assertEqual(lost['outcome'], {'choice': 'once', 'failure': None})
        self.assertFalse(lost['outbox_created'])
        self.assertEqual(len(lost['write_refusals']), 3)
        self.assertTrue(all(x['error_type'] for x in lost['write_refusals']))
        env = dict(HOME=str(f.root/'home'), HERMES_HOME=str(f.root/'hermes'), PATH='/usr/bin:/bin',
                   PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', LANG='en_US.UTF-8')
        helper = str(Path(os.environ['HERMES_QUALITY_FIXTURE_RUNNER']).with_name('approval-catalog-peer.py'))
        def peer(*args):
            run = subprocess.run([live.PYTHON, helper, str(f.root), *args], cwd=f.root, env=env,
                                 capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stderr)
            value = json.loads(run.stdout)
            self.assertNotEqual(value['pid'], f.pid)
            return value
        answer = peer('answer', result['peer_id'], 'once')
        self.assertEqual([x['request_id'] for x in answer['listing']], [result['peer_id']])
        self.assertEqual(answer['answer'], 'answered')
        self.assertEqual(f.command('approval-catalog-peer-finish', id=result['peer_id']), {'choice':'once', 'listing':[]})
        original = f.config.read_text()
        try:
            f.config.write_text(original.replace('transport: cozychat', 'transport: absent'))
            absent = peer('selection')
            self.assertFalse(absent['selected']); self.assertFalse(absent['read_refused'])
            f.config.write_text(original); f.config.chmod(0)
            unreadable = peer('selection')
            self.assertFalse(unreadable['selected']); self.assertTrue(unreadable['read_refused'])
        finally:
            f.config.chmod(0o600); f.config.write_text(original)
        restored = peer('selection')
        self.assertTrue(restored['selected']); self.assertFalse(restored['read_refused'])
        (f.root/'approval-peer-receipt.json').write_text(json.dumps(dict(answer=answer, absent=absent, unreadable=unreadable, restored=restored), indent=2))

    def test_router_only_discovery_genuinely_missing_hook_package_returns_503(self):
        # The shipping dashboard manifest/router exists; its backend entry point is genuinely
        # absent in this own copied deployment. No module registry or handler is replaced.
        root = Path(tempfile.mkdtemp(prefix='route-only-', dir=os.environ['HERMES_QUALITY_ARTIFACTS']))
        (root/'route-only').write_text('router deployed without plugin hook entry point')
        f = live.LiveDashboard(root=root)
        try:
            for method, route, body in [('GET', 'events', None), ('GET', 'approvals', None),
                                        ('POST', 'approvals/unissued', {'choice': 'once'})]:
                status, detail = f.request(method, '/api/plugins/cozychat/' + route, body)
                self.assertEqual(status, 503)
                self.assertEqual(detail, {'detail': 'cozychat plugin is not loaded in this process'})
            self.assertEqual(f.request('GET', '/api/plugins/cozychat/approvals', token=None)[0], 401)
        finally: f.close()

if __name__ == '__main__': unittest.main()
