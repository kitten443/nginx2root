import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import n2check


class VersionTests(unittest.TestCase):
    def test_version_affected_boundaries(self):
        cases = [
            ((1, 9, 4), (1, 9, 5), False),
            ((1, 9, 5), (1, 9, 5), True),
            ((1, 30, 6), (1, 9, 5), True),
            ((1, 30, 7), (1, 9, 5), False),
            ((1, 31, 8), (1, 9, 5), True),
            ((1, 31, 9), (1, 9, 5), False),
            ((0, 6, 17), (0, 6, 18), False),
            ((0, 6, 18), (0, 6, 18), True),
            ((1, 19, 6), (1, 19, 7), False),
            ((1, 19, 7), (1, 19, 7), True),
            ((1, 24, 9), (1, 25, 0), False),
            ((1, 25, 0), (1, 25, 0), True),
            ((0, 5, 32), (0, 5, 33), False),
            ((0, 5, 33), (0, 5, 33), True),
        ]
        for version, first, expected in cases:
            with self.subTest(version=version, first=first):
                self.assertEqual(
                    n2check.version_affected(version, first), expected)

    def test_assess_versions(self):
        status, rows = n2check.assess_version((1, 31, 8))
        self.assertEqual(status, 'vulnerable')
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row['version_status'] == 'vulnerable'
                            for row in rows))

        status, rows = n2check.assess_version((1, 30, 7))
        self.assertEqual(status, 'ok')
        self.assertTrue(all(row['version_status'] == 'ok' for row in rows))

        # До 1.9.5 нет HTTP/2, но resolver/mail CVE всё ещё применимы.
        status, rows = n2check.assess_version((1, 9, 4))
        self.assertEqual(status, 'vulnerable')
        by_id = {row['cve']: row for row in rows}
        self.assertEqual(by_id['CVE-2026-123007']['version_status'], 'ok')
        self.assertEqual(by_id['CVE-2026-123634']['version_status'], 'vulnerable')

        status, rows = n2check.assess_version((0, 5, 32))
        self.assertEqual(status, 'ok')

    def test_parse_version(self):
        self.assertEqual(n2check.parse_version('nginx/1.31.8'), (1, 31, 8))
        self.assertEqual(n2check.parse_version('1.18.0-6ubuntu14.22'), (1, 18, 0))
        self.assertIsNone(n2check.parse_version('nginx'))
        self.assertIsNone(n2check.parse_version('1.31.8.1'))

    def test_extract_nginx_version(self):
        self.assertEqual(
            n2check.extract_nginx_version('nginx version: nginx/1.31.8'),
            '1.31.8',
        )
        self.assertEqual(
            n2check.extract_nginx_version('nginx/1.22.1 (Debian)'),
            '1.22.1',
        )
        self.assertIsNone(n2check.extract_nginx_version('Apache/2.4.62'))


class DebianTests(unittest.TestCase):
    def test_compare_debian_versions(self):
        self.assertEqual(
            n2check.compare_debian_versions(
                '1.22.1-9+deb12u11', '1.22.1-9+deb12u11'), 1)
        self.assertEqual(
            n2check.compare_debian_versions(
                '1.22.1-9+deb12u9', '1.22.1-9+deb12u11'), -1)
        self.assertEqual(
            n2check.compare_debian_versions(
                '1.22.1-9+deb12u12', '1.22.1-9+deb12u11'), 1)
        self.assertEqual(
            n2check.compare_debian_versions('1.30.6-4', '1.30.6-3'), 1)

    def test_simple_debian_compare(self):
        self.assertEqual(
            n2check._simple_debian_compare(
                '1.22.1-9+deb12u9', '1.22.1-9+deb12u11'), -1)
        self.assertEqual(
            n2check._simple_debian_compare('1.30.6-4', '1.30.6-3'), 1)
        self.assertEqual(
            n2check._simple_debian_compare('1.22.1-9', '1.22.1-9'), 0)

    def test_debian_package_info(self):
        fixed_bookworm = n2check.debian_package_info(
            'nginx', '1.22.1-9+deb12u11', suite='bookworm')
        self.assertEqual(fixed_bookworm['status'], 'fixed')
        self.assertEqual(fixed_bookworm['advisory'], 'DLA-4918-1')

        vulnerable_bookworm = n2check.debian_package_info(
            'nginx', '1.22.1-9+deb12u9', suite='bookworm')
        self.assertEqual(vulnerable_bookworm['status'], 'vulnerable')

        fixed_trixie = n2check.debian_package_info(
            'nginx', '1.26.3-3+deb13u11', suite='trixie')
        self.assertEqual(fixed_trixie['status'], 'fixed')
        self.assertEqual(fixed_trixie['advisory'], 'DSA-6642-1')

        vulnerable_trixie = n2check.debian_package_info(
            'nginx', '1.26.3-3+deb13u7', suite='trixie')
        self.assertEqual(vulnerable_trixie['status'], 'vulnerable')

        self.assertEqual(
            n2check.debian_package_info(
                'nginx', '1.30.6-4', suite='sid')['status'],
            'fixed',
        )
        self.assertEqual(
            n2check.debian_package_info(
                'nginx', '1.30.6-3', suite='sid')['status'],
            'vulnerable',
        )

        # nginx.org-пакет новее Debian-исправления, но не содержит его.
        self.assertEqual(
            n2check.debian_package_info(
                'nginx', '1.31.8-1~bookworm', suite='bookworm')['status'],
            'unknown',
        )
        self.assertEqual(
            n2check.debian_package_info(
                'nginx', '1.30.7-1~bookworm', suite='bookworm')['status'],
            'unknown',
        )

    def test_debian_suite(self):
        with mock.patch('n2check._os_release', return_value={
                'ID': 'debian', 'VERSION_CODENAME': 'bookworm'}):
            self.assertEqual(n2check.debian_suite(), 'bookworm')
        with mock.patch('n2check._os_release', return_value={
                'ID': 'ubuntu', 'VERSION_CODENAME': 'noble'}):
            self.assertIsNone(n2check.debian_suite())


class ConfigTests(unittest.TestCase):
    CONFIG = r"""
http {
    server {
        listen 443 ssl;
        http2 on;
        resolver 1.1.1.1;
        location / {
            proxy_pass http://$host;
            mirror /mirror;
        }
        location = /mirror {
            internal;
            mirror_request_body off;
            proxy_pass http://backend;
        }
    }
}
mail {
    proxy on;
    auth_http http://auth/check;
}
"""

    def test_parse_config(self):
        features = n2check.parse_config(self.CONFIG)
        self.assertTrue(features['http2'])
        self.assertTrue(features['resolver'])
        self.assertTrue(features['variable_proxy_pass'])
        self.assertTrue(features['upstream'])
        self.assertTrue(features['mirror'])
        self.assertTrue(features['mirror_request_body_off'])
        self.assertTrue(features['mail_block'])
        self.assertTrue(features['mail_proxy_on'])
        self.assertTrue(features['auth_http'])
        self.assertFalse(features['http3'])

    def test_parse_http3(self):
        features = n2check.parse_config(
            'http { server { listen 443 quic reuseport; http3 on; } }')
        self.assertTrue(features['http3'])
        self.assertTrue(features['quic_listen'])

    def test_parse_legacy_http2_listen(self):
        features = n2check.parse_config(
            'http { server { listen 443 ssl http2; } }')
        self.assertTrue(features['http2'])
        self.assertTrue(features['http2_listen'])
        self.assertFalse(features['http2_on'])

    def test_strip_comments(self):
        text = 'http2 on; # выключить\nadd_header X "#keep";\n'
        stripped = n2check.strip_comments(text)
        self.assertNotIn('# выключить', stripped)
        self.assertIn('#keep', stripped)

    def test_build_flags(self):
        flags = n2check.parse_build_flags(
            'configure arguments: --with-http_v2_module '
            '--with-http_v3_module --with-mail'
        )
        self.assertTrue(flags['http_v2_module'])
        self.assertTrue(flags['http_v3_module'])
        self.assertTrue(flags['mail_module'])
        self.assertFalse(n2check.parse_build_flags('')['http_v2_module'])


class ExposureTests(unittest.TestCase):
    def test_remote_exposures(self):
        rows = n2check.assess_version((1, 31, 8))[1]
        n2check.apply_remote_exposures(rows, True, False)
        by_id = {row['cve']: row for row in rows}
        self.assertEqual(by_id['CVE-2026-123007']['exposure'], 'exposed')
        self.assertEqual(by_id['CVE-2026-123633']['exposure'], 'possible')
        self.assertEqual(by_id['CVE-2026-121810']['exposure'], 'unknown')
        self.assertEqual(by_id['CVE-2026-123634']['exposure'], 'unknown')
        self.assertEqual(by_id['CVE-2026-113425']['exposure'], 'unknown')

        rows = n2check.assess_version((1, 31, 8))[1]
        n2check.apply_remote_exposures(rows, False, False)
        by_id = {row['cve']: row for row in rows}
        self.assertEqual(by_id['CVE-2026-123007']['exposure'], 'not_exposed')
        self.assertEqual(by_id['CVE-2026-123633']['exposure'], 'not_exposed')

    def test_local_exposures(self):
        features = n2check.parse_config(ConfigTests.CONFIG)
        flags = {
            'http_v2_module': True,
            'http_v3_module': True,
            'mail_module': True,
        }
        rows = n2check.assess_version((1, 31, 8))[1]
        n2check.apply_local_exposures(rows, features, flags, True)
        by_id = {row['cve']: row for row in rows}
        self.assertEqual(by_id['CVE-2026-123007']['exposure'], 'exposed')
        self.assertEqual(by_id['CVE-2026-123633']['exposure'], 'possible')
        self.assertEqual(by_id['CVE-2026-123634']['exposure'], 'possible')
        self.assertEqual(by_id['CVE-2026-121810']['exposure'], 'not_exposed')
        self.assertEqual(by_id['CVE-2026-113425']['exposure'], 'exposed')


class LocalCheckTests(unittest.TestCase):
    SCRIPT = r"""#!/bin/sh
case "$1" in
  -v) echo "nginx version: nginx/1.22.1" >&2 ;;
  -V) echo "configure arguments: --with-http_v2_module --with-http_v3_module --with-mail" >&2 ;;
  -T) cat <<'EOF'
http {
    server {
        listen 443 ssl;
        http2 on;
        resolver 1.1.1.1;
        location / {
            proxy_pass http://$host;
            mirror /mirror;
        }
    }
}
mail {
    proxy on;
    auth_http http://auth/check;
}
EOF
    ;;
esac
"""

    def _fake_nginx(self, directory):
        path = os.path.join(directory, 'nginx')
        with open(path, 'w', encoding='utf-8') as file:
            file.write(self.SCRIPT)
        os.chmod(path, 0o755)
        return path

    def test_check_local_with_vulnerable_debian_package(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = self._fake_nginx(directory)
            with mock.patch('n2check.local_package',
                            return_value=('nginx', '1.22.1-9+deb12u9')), \
                    mock.patch('n2check.debian_suite', return_value='bookworm'):
                status, version, error, details = n2check.check_local(binary)
        self.assertEqual(status, 'vulnerable')
        self.assertEqual(version, '1.22.1')
        self.assertIsNone(error)
        self.assertEqual(details['package']['status'], 'vulnerable')
        by_id = {row['cve']: row for row in details['cves']}
        self.assertEqual(by_id['CVE-2026-123007']['exposure'], 'exposed')

    def test_check_local_with_fixed_debian_package(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = self._fake_nginx(directory)
            with mock.patch('n2check.local_package',
                            return_value=('nginx', '1.22.1-9+deb12u11')), \
                    mock.patch('n2check.debian_suite', return_value='bookworm'):
                status, version, error, details = n2check.check_local(binary)
        self.assertEqual(status, 'ok')
        self.assertEqual(version, '1.22.1')
        self.assertIsNone(error)
        self.assertEqual(details['package']['status'], 'fixed')
        self.assertTrue(all(row['version_status'] == 'ok'
                            for row in details['cves']))


if __name__ == '__main__':
    unittest.main()
