import asyncio
import base64
import os
import tempfile
import unittest
from unittest.mock import patch

import aggregator
import check_active
import filter_nodes


class FilterTests(unittest.TestCase):
    def test_default_tls_protocols(self):
        for proto in ('trojan', 'hysteria2', 'hy2', 'tuic'):
            with self.subTest(proto=proto):
                self.assertFalse(filter_nodes.should_filter_node(
                    f'{proto}://secret@server.net:443', ['tls=0']))

    def test_tls_uses_query_not_remark_or_substring(self):
        for suffix in ('#security=tls', '?security=tls-fake', '?tls=10'):
            self.assertTrue(filter_nodes.should_filter_node(
                'vless://secret@server.net:443' + suffix, ['tls=0']))
        self.assertTrue(filter_nodes.should_filter_node(
            'trojan://secret@server.net:443?security=none', ['tls=0']))
        self.assertFalse(filter_nodes.should_filter_node(
            'vless://secret@server.net:443?security=reality', ['tls=0']))

    def test_non_object_vmess_does_not_crash(self):
        link = 'vmess://' + base64.b64encode(b'[]').decode()
        self.assertTrue(filter_nodes.should_filter_node(link, ['tls=0']))

    def test_encoded_remark(self):
        self.assertIn('官网', filter_nodes.extract_searchable_text(
            'trojan://pass@server.net:443#%E5%AE%98%E7%BD%91'))


class AggregatorTests(unittest.TestCase):
    def setUp(self):
        self.agg = aggregator.DynamicNodeAggregator('test-token')
        self.addCleanup(self.agg.session.close)

    def test_download_session_has_no_token(self):
        self.assertNotIn('Authorization', self.agg.session.headers)

    def test_ipv6_shadowsocks(self):
        link = self.agg._build_ss_link(dict(server='2606:4700::1111', port=443,
                                          password='secret', cipher='aes-128-gcm'))
        self.assertIn('@[2606:4700::1111]:443', link)
        self.assertTrue(self.agg._validate_link(link))

    def test_run_drains_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw, sub = os.path.join(tmp, 'nodes'), os.path.join(tmp, 'sub')
            def discover():
                self.agg.url_queue.put('https://server.net/nodes')
            def worker():
                self.agg.url_queue.get()
                self.agg.nodes.update(('z-node', 'a-node'))
                self.agg.url_queue.task_done()
            with patch.object(self.agg, 'discover_active_repositories', discover), \
                 patch.object(self.agg, 'discover_via_code_search'), \
                 patch.object(self.agg, 'fetch_worker', worker), \
                 patch.object(aggregator, 'DOWNLOAD_WORKERS', 1), \
                 patch.object(aggregator, 'RAW_OUTPUT_FILE', raw), \
                 patch.object(aggregator, 'OUTPUT_FILE', sub):
                self.agg.run()
            with open(raw) as f:
                self.assertEqual(f.read(), 'a-node\nz-node')
            with open(sub) as f:
                self.assertEqual(base64.b64decode(f.read()), b'a-node\nz-node')


class CheckerTests(unittest.TestCase):
    def test_unknown_protocol_rejected(self):
        self.assertIsNone(check_active.parse_node('http://public.net:443'))

    def test_password_unquoted(self):
        node = check_active.parse_node('trojan://p%40ss%3Aword@public.net:443')
        self.assertEqual(node.password, 'p@ss:word')

    def test_domain_suffix_boundary(self):
        self.assertIsNotNone(check_active.parse_node('trojan://pass@notpages.dev:443'))
        self.assertIsNone(check_active.parse_node('trojan://pass@a.pages.dev:443'))


class TimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_checks_cancelled_and_awaited(self):
        cancelled = asyncio.Event()
        async def slow_check(*args):
            try:
                await asyncio.sleep(60)
            finally:
                cancelled.set()
        with tempfile.TemporaryDirectory() as tmp:
            raw, sub = os.path.join(tmp, 'nodes'), os.path.join(tmp, 'sub')
            with open(raw, 'w') as f:
                f.write('trojan://pass@public.net:443')
            with patch.object(check_active, 'INPUT_FILE', raw), \
                 patch.object(check_active, 'OUTPUT_FILE', raw), \
                 patch.object(check_active, 'SUB_FILE', sub), \
                 patch.object(check_active, 'MAX_EXECUTION_TIME', 0.02), \
                 patch.object(check_active, 'check_one', slow_check):
                await asyncio.wait_for(check_active.main(), timeout=1)
            self.assertTrue(cancelled.is_set())
