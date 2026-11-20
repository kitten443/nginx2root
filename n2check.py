#!/usr/bin/env python3
"""
n2check.py — проверка nginx2root (CVE-2026-123007, CVE-2026-123634,
CVE-2026-123633, CVE-2026-121810, CVE-2026-113425).

Проверяет сайт по URL, список сайтов из файла или локальный nginx и
сообщает, уязвима ли версия к nginx2root. В режиме --local дополнительно
разбираются сборочные флаги и конфигурация nginx (`nginx -V`, `nginx -T`),
версия пакета ОС (dpkg/rpm/apk/pacman/pkg) и состояние модуля SCTP в ядре —
без него цепочка не даёт root.

Инструмент только читает версию, заголовки и конфигурацию. Эксплойтов он
не содержит и никаких атакующих запросов не отправляет.

Коды возврата: 0 — OK, 1 — VULNERABLE, 3 — UNKNOWN, 2 — ошибка аргументов.
Для списка сайтов код возврата агрегируется по всем результатам.
"""

import asyncio
import glob
import json
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from itertools import zip_longest

VERSION = '1.4.0'

# Исправленные релизы nginx (18.11.2026): стабильная и mainline-ветки.
FIXED_STABLE = (1, 30, 7)
FIXED_MAINLINE = (1, 31, 9)

# Debian и Ubuntu уже выпустили security-патчи для низких версий nginx.
# Версия nginx при этом не меняется, поэтому сравнивать нужно версию пакета.
DEB_FIXED = {
    # Debian
    'bookworm': '1.22.1-9+deb12u11',
    'trixie': '1.26.3-3+deb13u11',
    'forky': '1.30.6-4',
    'sid': '1.30.6-4',
    # Ubuntu (USN-9159-1)
    'stonking': '1.30.4-7ubuntu1.2',
    'resolute': '1.28.3-2ubuntu1.13',
    'noble': '1.24.0-2ubuntu7.20',
    'jammy': '1.18.0-6ubuntu14.23',
    'focal': '1.18.0-0ubuntu1.7+esm5',
    'bionic': '1.14.0-0ubuntu1.11+esm6',
    'xenial': '1.10.3-0ubuntu0.16.04.5+esm11',
    'trusty': '1.4.6-1ubuntu3.9+esm10',
}
DEB_ADVISORY = {
    'bookworm': 'DLA-4918-1',
    'trixie': 'DSA-6642-1',
    'forky': '',
    'sid': '',
    'stonking': 'USN-9159-1',
    'resolute': 'USN-9159-1',
    'noble': 'USN-9159-1',
    'jammy': 'USN-9159-1',
    'focal': 'USN-9159-1',
    'bionic': 'USN-9159-1',
    'xenial': 'USN-9159-1',
    'trusty': 'USN-9159-1',
}

# Для обратной совместимости с ранними версиями скрипта.
DEBIAN_FIXED = {key: DEB_FIXED[key] for key in
                ('bookworm', 'trixie', 'forky', 'sid')}
DEBIAN_ADVISORY = {key: DEB_ADVISORY[key] for key in
                   ('bookworm', 'trixie', 'forky', 'sid')}

# Alpine: исправленные версии по веткам (secdb.alpinelinux.org).
ALPINE_FIXED = {
    'edge': '1.30.7-r0',
    '3.24': '1.30.7-r0',
    '3.23': '1.28.3-r8',
    '3.22': '1.28.3-r8',
    '3.21': '1.26.3-r4',
}
ALPINE_ADVISORY = {
    'edge': 'Alpine secdb',
    '3.24': 'Alpine secdb',
    '3.23': 'Alpine secdb',
    '3.22': 'Alpine secdb',
    '3.21': 'Alpine secdb',
}

# SUSE: фикс по веткам (Tumbleweed закрывается upstream-версией,
# для SLES 15 пакеты были в QA на 19.11.2026).
SUSE_FIXED = {
    '150400': '1.21.5-150400.3.28.1',
    '150600': '1.21.5-150600.10.30.1',
}

# CVE, по которым определяем, что RPM-пакет собран с исправлениями.
_N2ROOT_CVE_RE = re.compile(
    r'CVE-2026-(?:123007|123634|123633|121810|113425)', re.IGNORECASE)
_N2ROOT_TEXT_RE = re.compile(
    r'nginx2root|flow[- ]control window overflow', re.IGNORECASE)

# Данные nginx.org/en/security_advisories.html: first — первый уязвимый
# релиз, исправление для всех — 1.30.7+ / 1.31.9+.
CVES = (
    {
        'cve': 'CVE-2026-123007',
        'title': 'переполнение в HTTP/2 flow control',
        'first': (1, 9, 5),
    },
    {
        'cve': 'CVE-2026-123634',
        'title': 'use-after-free в DNS resolver',
        'first': (0, 6, 18),
    },
    {
        'cve': 'CVE-2026-123633',
        'title': 'use-after-free в HTTP/2 (upstream)',
        'first': (1, 19, 7),
    },
    {
        'cve': 'CVE-2026-121810',
        'title': 'use-after-free в HTTP/3 (upstream)',
        'first': (1, 25, 0),
    },
    {
        'cve': 'CVE-2026-113425',
        'title': 'use-after-free в mail proxy (auth_http)',
        'first': (0, 5, 33),
    },
)

USAGE = (
    'Использование: python3 n2check.py URL [--timeout СЕКУНДЫ] [--insecure] [--json]\n'
    '               python3 n2check.py --local [--nginx ПУТЬ] [--json]\n'
    '               python3 n2check.py --file ФАЙЛ [--threads N] [--async] '
    '[--timeout СЕКУНДЫ] [--insecure] [--json]\n'
    '               python3 n2check.py --version'
)

EXIT = {'ok': 0, 'vulnerable': 1, 'unknown': 3}

# Метки для человекочитаемого вывода.
EXPOSURE_LABELS = {
    'exposed': 'EXPOSED',
    'possible': 'POSSIBLE',
    'not_exposed': 'NOT EXPOSED',
    'unknown': 'UNKNOWN',
    'not_applicable': 'NOT APPLICABLE',
}

_VERSION_RE = re.compile(r'(?<![\d.])(\d+)\.(\d+)\.(\d+)(?![\d.])')
_NGINX_VERSION_RE = re.compile(r'\bnginx/(\d+\.\d+\.\d+)', re.IGNORECASE)
_H3_RE = re.compile(r'(?:^|,)\s*h3(?:-\d+)?\s*=', re.IGNORECASE)
_LAST_CONFIG_LINE_RE = re.compile(r'^\s*(?:#.*)?$')

# Замок на печать результатов — чтобы строки не перемешивались между потоками.
_print_lock = threading.Lock()


def parse_version(text):
    """Вернуть (major, minor, patch) из строки или None."""
    if not text:
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    try:
        return tuple(int(group) for group in match.groups())
    except ValueError:
        return None


def version_affected(version, first):
    """Уязвима ли версия nginx для CVE с первым уязвимым релизом first.

    True/False — однозначный ответ по официальной ветке nginx,
    None — версия неизвестна. Бэкпорты дистрибутивов могут не менять
    номер версии, поэтому для пакетов из репозиториев это лишь оценка.
    """
    if version is None or first is None:
        return None
    if version < first:
        return False
    if version >= FIXED_MAINLINE:
        return False
    # Стабильная ветка 1.30.x исправлена начиная с 1.30.7; mainline
    # 1.31.x — начиная с 1.31.9 (проверка выше). Всё, что между ними,
    # относится к уязвимому диапазону.
    if FIXED_STABLE <= version < (1, 31, 0):
        return False
    return True


def _simple_debian_compare(left, right):
    """Упрощённое сравнение версий Debian без вызова dpkg.

    Достаточно для версий вида 1.22.1-9+deb12u9 и 1.30.6-3.
    Возвращает 1, -1, 0 или None, если сравнить нельзя.
    """
    left_version = parse_version(left)
    right_version = parse_version(right)
    if left_version is None or right_version is None:
        return None
    if left_version != right_version:
        return 1 if left_version > right_version else -1

    left_update = re.search(r'u(\d+)', left, re.IGNORECASE)
    right_update = re.search(r'u(\d+)', right, re.IGNORECASE)
    if left_update and right_update:
        left_number = int(left_update.group(1))
        right_number = int(right_update.group(1))
        return (left_number > right_number) - (left_number < right_number)

    left_revision = re.search(r'-(\d+)(?:\+|$)', left)
    right_revision = re.search(r'-(\d+)(?:\+|$)', right)
    if left_revision and right_revision:
        left_number = int(left_revision.group(1))
        right_number = int(right_revision.group(1))
        return (left_number > right_number) - (left_number < right_number)
    return 0 if left == right else None


def compare_debian_versions(left, right):
    """Сравнить версии пакетов Debian: 1 если left >= right, -1 если нет.

    Сначала используется dpkg --compare-versions (точные правила Debian),
    затем упрощённый fallback для не-Debian окружений.
    """
    try:
        proc = subprocess.run(
            ['dpkg', '--compare-versions', left, 'ge', right],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return _simple_debian_compare(left, right)
    if proc.returncode == 0:
        return 1
    if proc.returncode == 1:
        return -1
    return None


def _read_text(path):
    """Прочитать текстовый файл ('' при ошибке/отсутствии)."""
    try:
        with open(path, encoding='utf-8', errors='replace') as file:
            return file.read()
    except OSError:
        return ''


def _os_release():
    """Прочитать /etc/os-release в dict (пустой dict при ошибке)."""
    data = {}
    try:
        with open('/etc/os-release', encoding='utf-8', errors='replace') as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                data[key] = value.strip().strip('"\'')
    except OSError:
        pass
    return data


def debian_suite():
    """Кодовое имя Debian/Ubuntu (bookworm/jammy/...) или None."""
    data = _os_release()
    if data.get('ID', '').lower() not in ('debian', 'raspbian', 'ubuntu'):
        return None
    return data.get('VERSION_CODENAME') or data.get('DEBIAN_CODENAME') or None


def os_family():
    """Семейство дистрибутива: debian, ubuntu, rpm, alpine, arch, freebsd."""
    data = _os_release()
    if not data:
        if platform.system() == 'FreeBSD':
            return 'freebsd'
        return None
    identifier = data.get('ID', '').lower()
    like = set(data.get('ID_LIKE', '').lower().split())
    names = {identifier} | like
    if identifier == 'freebsd' or platform.system() == 'FreeBSD':
        return 'freebsd'
    if 'ubuntu' in names:
        return 'ubuntu'
    if names & {'debian', 'raspbian'}:
        return 'debian'
    if 'alpine' in names:
        return 'alpine'
    if 'arch' in names:
        return 'arch'
    if names & {'sles', 'suse', 'opensuse', 'opensuse-leap', 'opensuse-tumbleweed'}:
        return 'suse'
    if names & {'rhel', 'fedora', 'centos', 'rocky', 'almalinux', 'oracle',
                'ol', 'amzn', 'amazon'}:
        return 'rpm'
    return None


def debian_package_info(package, version, suite=None):
    """Оценить, исправлен ли Debian/Ubuntu-пакет nginx для nginx2root.

    Для Debian bookworm/trixie фикс уже выпущен (DLA-4918-1 / DSA-6642-1),
    для Ubuntu — USN-9159-1. При этом `nginx -v` продолжает показывать
    старую upstream-версию.
    """
    suite = suite or debian_suite()
    if suite is None:
        # Иногда кодовое имя можно определить по суффиксу версии пакета.
        if 'deb12' in version:
            suite = 'bookworm'
        elif 'deb13' in version:
            suite = 'trixie'
        elif version.startswith('1.30.6-4'):
            suite = 'sid'
        elif version.startswith('1.30.6-3'):
            suite = 'forky'

    fixed = DEB_FIXED.get(suite)
    info = {
        'package': package,
        'version': version,
        'suite': suite,
        'fixed_version': fixed,
        'advisory': DEB_ADVISORY.get(suite) or None,
        'status': 'unknown',
        'source': 'dpkg',
    }
    if fixed is None:
        return info

    # Сравнивать с Debian-исправлением можно только пакет той же upstream-
    # ветки. Иначе nginx.org-пакет 1.31.8 окажется «новее» 1.22.1-9+deb12u11
    # и получит ложный статус fixed, хотя исправление 1.31.8 не содержит.
    installed_upstream = parse_version(version)
    fixed_upstream = parse_version(fixed)
    if installed_upstream is None or fixed_upstream is None:
        return info
    if installed_upstream < fixed_upstream:
        info['status'] = 'vulnerable'
        return info
    if installed_upstream > fixed_upstream:
        info['note'] = ('пакет не из ветки Debian-исправления; '
                        'вердикт по upstream-версии')
        return info

    comparison = compare_debian_versions(version, fixed)
    if comparison == 1:
        info['status'] = 'fixed'
        info['fixed_cves'] = sorted(applicable_cves(version))
    elif comparison == -1:
        info['status'] = 'vulnerable'
    return info


def assess_version(version):
    """Вернуть (status, rows) для версии nginx.

    status — 'vulnerable', 'ok' или 'unknown'; rows — по одной записи
    на CVE с полями cve, title, version_status, exposure, detail.
    """
    rows = []
    vulnerable = False
    for item in CVES:
        affected = version_affected(version, item['first'])
        if affected:
            vulnerable = True
        rows.append({
            'cve': item['cve'],
            'title': item['title'],
            'version_status': (
                'vulnerable' if affected else
                'ok' if affected is False else 'unknown'
            ),
            'exposure': 'unknown',
            'detail': '' if affected else 'версия вне уязвимого диапазона',
        })
    if version is None:
        status = 'unknown'
    else:
        status = 'vulnerable' if vulnerable else 'ok'
    return status, rows


def extract_nginx_version(text):
    """Достать версию из заголовка Server или вывода `nginx -v`."""
    match = _NGINX_VERSION_RE.search(text or '')
    return match.group(1) if match else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Вернуть ответ 3xx как есть, не следуя редиректу (аналог manual)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_headers(address, timeout, insecure=False):
    """HEAD-запрос к URL (GET при 405/501) и возврат (headers, код)."""
    if re.search(r'[\x00-\x20\x7f]', address):
        raise ValueError('URL содержит пробелы или управляющие символы')
    parts = urllib.parse.urlsplit(address)
    if parts.scheme not in ('http', 'https'):
        raise ValueError('Используйте URL вида http:// или https://')
    if not parts.hostname:
        raise ValueError('URL не содержит хоста')
    if parts.username or parts.password or parts.fragment:
        raise ValueError('Учётные данные и фрагменты в URL не поддерживаются')
    try:
        parts.port
    except ValueError:
        raise ValueError('Некорректный порт в URL')

    handlers = [_NoRedirect()]
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)

    last_error = None
    for method in ('HEAD', 'GET'):
        request = urllib.request.Request(address, method=method)
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            # urllib оборачивает статусы >= 400 в HTTPError; заголовки в нём есть.
            response = exc
        except Exception as exc:
            # Некоторые серверы закрывают соединение на HEAD — пробуем GET.
            last_error = exc
            if method == 'HEAD':
                continue
            raise
        with response:
            headers = response.headers
            code = response.code
        if method == 'GET' or code not in (405, 501):
            return headers, code
    raise last_error or RuntimeError('не удалось получить ответ')


def detect_alpn(parts, timeout, insecure=False):
    """Согласовать ALPN с сервером и вернуть (протокол, ошибка).

    Протокол None при успешном TLS без ALPN — это не ошибка.
    """
    if parts.scheme != 'https':
        return None, 'ALPN проверяется только для https'
    host = parts.hostname
    try:
        port = parts.port or 443
    except ValueError:
        return None, 'некорректный порт'

    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        context.set_alpn_protocols(['h2', 'http/1.1'])
    except (AttributeError, NotImplementedError):
        return None, 'Python/OpenSSL не поддерживает ALPN'

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return tls.selected_alpn_protocol(), None
    except Exception as exc:
        return None, str(exc)


def apply_remote_exposures(rows, http2, http3_advertised, alpn_error=None):
    """Проставить экспозицию CVE по данным, видимым удалённо."""
    for row in rows:
        if row['version_status'] != 'vulnerable':
            row['exposure'] = 'not_applicable'
            row['detail'] = 'версия вне уязвимого диапазона'
            continue

        cve = row['cve']
        if cve == 'CVE-2026-123007':
            if http2 is True:
                row.update(exposure='exposed',
                           detail='сервер согласовал HTTP/2 по ALPN (h2)')
            elif http2 is False:
                row.update(exposure='not_exposed',
                           detail='HTTP/2 не согласован по ALPN')
            else:
                row.update(exposure='unknown',
                           detail=alpn_error or 'HTTP/2 не проверен')
        elif cve == 'CVE-2026-123633':
            if http2 is True:
                row.update(exposure='possible',
                           detail='HTTP/2 включён; наличие upstream проверяется по конфигурации')
            elif http2 is False:
                row.update(exposure='not_exposed',
                           detail='HTTP/2 не согласован по ALPN')
            else:
                row.update(exposure='unknown',
                           detail=alpn_error or 'HTTP/2 не проверен')
        elif cve == 'CVE-2026-121810':
            if http3_advertised is True:
                row.update(exposure='possible',
                           detail='HTTP/3 рекламируется в Alt-Svc; наличие upstream проверяется по конфигурации')
            else:
                row.update(exposure='unknown',
                           detail='HTTP/3 удалённо не подтверждён; отсутствие Alt-Svc ничего не доказывает')
        elif cve == 'CVE-2026-123634':
            row.update(exposure='unknown',
                       detail='нужны resolver, proxy_pass с переменной и subrequest — конфигурация не видна удалённо')
        elif cve == 'CVE-2026-113425':
            row.update(exposure='unknown',
                       detail='нужен mail proxy с proxy on и auth_http — конфигурация не видна удалённо')


def check_url(address, timeout, insecure=False):
    """Проверить URL и вернуть (status, version, error, details)."""
    version = None
    error = None
    status = 'unknown'
    details = {
        'server': None,
        'http_status': None,
        'http2': None,
        'http3_advertised': None,
        'alpn': None,
        'cves': [],
    }
    try:
        headers, code = fetch_headers(address, timeout, insecure)
        server = headers.get('Server') or ''
        alt_svc = headers.get('Alt-Svc') or ''
        details['server'] = server or None
        details['http_status'] = code
        details['http3_advertised'] = bool(_H3_RE.search(alt_svc)) if alt_svc else False

        version = extract_nginx_version(server)
        if version:
            status, rows = assess_version(parse_version(version))
        else:
            rows = []

        parts = urllib.parse.urlsplit(address)
        alpn, alpn_error = detect_alpn(parts, timeout, insecure)
        details['alpn'] = alpn
        if alpn is None and alpn_error is None:
            details['http2'] = False  # TLS есть, ALPN не выбран.
        elif alpn == 'h2':
            details['http2'] = True
        elif alpn is not None:
            details['http2'] = False
        if alpn_error:
            details['alpn_error'] = alpn_error

        apply_remote_exposures(
            rows, details['http2'], details['http3_advertised'], alpn_error,
        )
        details['cves'] = rows
        if status == 'vulnerable':
            details['caveat'] = (
                'Версия из баннера может не учитывать бэкпорт дистрибутива; '
                'для Debian проверьте пакет локально: --local.'
            )

        if version is None:
            if server:
                details['note'] = (
                    'Версия nginx не найдена в заголовке Server '
                    '(server_tokens off, CDN или другой сервер)'
                )
            else:
                details['note'] = 'Заголовок Server отсутствует'
    except Exception as exc:
        error = str(exc)
    return status, version, error, details


def _run_nginx(command, timeout=15):
    """Запустить nginx и вернуть (stdout+stderr, код возврата)."""
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        raise ValueError(f'Не найден исполняемый файл: {command[0]}')
    except subprocess.TimeoutExpired:
        raise ValueError(f'{command[0]} не ответил за {timeout} секунд')
    return (proc.stdout or '') + (proc.stderr or ''), proc.returncode


def parse_build_flags(text):
    """Разобрать `nginx -V`: наличие модулей HTTP/2, HTTP/3 и mail."""
    text = text or ''
    return {
        'http_v2_module': '--with-http_v2_module' in text,
        'http_v3_module': '--with-http_v3_module' in text,
        'mail_module': '--with-mail' in text,
    }


def strip_comments(text):
    """Убрать комментарии nginx (#), не трогая # внутри кавычек."""
    result = []
    quote = None
    i = 0
    while i < len(text):
        char = text[i]
        if quote is not None:
            result.append(char)
            if char == '\\' and i + 1 < len(text):
                result.append(text[i + 1])
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in ('"', "'"):
            quote = char
            result.append(char)
        elif char == '#':
            while i < len(text) and text[i] != '\n':
                i += 1
            continue
        else:
            result.append(char)
        i += 1
    return ''.join(result)


# Начало директивы: начало строки, } или ; (конфиг может быть в одну строку).
_DIRECTIVE_START = r'(?m)(?:^|[;{}])\s*'


def _has_directive(config, pattern):
    return bool(re.search(_DIRECTIVE_START + pattern, config))


def parse_config(text):
    """Эвристически найти в конфигурации nginx опасные директивы."""
    config = strip_comments(text or '')
    http2_on = _has_directive(config, r'http2\s+on\s*;')
    http2_off = _has_directive(config, r'http2\s+off\s*;')
    http2_listen = _has_directive(
        config, r'listen\s+[^;]*\bhttp2\b[^;]*;')
    http3_on = _has_directive(config, r'http3\s+on\s*;')
    http3_off = _has_directive(config, r'http3\s+off\s*;')
    quic_listen = _has_directive(
        config, r'listen\s+[^;]*\bquic\b[^;]*;')

    return {
        # Консервативно: достаточно любого включения, даже если рядом есть off.
        'http2': http2_on or http2_listen,
        'http2_on': http2_on,
        'http2_off': http2_off,
        'http2_listen': http2_listen,
        'http3': http3_on or quic_listen,
        'http3_on': http3_on,
        'http3_off': http3_off,
        'quic_listen': quic_listen,
        'resolver': _has_directive(config, r'resolver\s+[^;]+;'),
        'variable_proxy_pass': _has_directive(
            config, r'proxy_pass\s+[^;]*\$[^;]*;'),
        'upstream': _has_directive(
            config, r'(?:proxy|grpc|fastcgi|uwsgi|scgi)_pass\s+[^;]+;'),
        'mirror': _has_directive(config, r'mirror\s+[^;]+;'),
        'mirror_request_body_off': _has_directive(
            config, r'mirror_request_body\s+off\s*;'),
        'ssi': _has_directive(config, r'ssi\s+on\s*;'),
        'mail_block': _has_directive(config, r'mail\s*\{'),
        'mail_proxy_on': _has_directive(config, r'proxy\s+on\s*;'),
        'auth_http': _has_directive(config, r'auth_http\s+[^;]+;'),
    }


def apply_local_exposures(rows, features, flags, config_read):
    """Проставить экспозицию CVE по локальной сборке и конфигурации."""
    for row in rows:
        if row['version_status'] != 'vulnerable':
            row['exposure'] = 'not_applicable'
            row['detail'] = 'версия вне уязвимого диапазона'
            continue

        cve = row['cve']
        http2 = features.get('http2') if config_read else None
        http3 = features.get('http3') if config_read else None
        upstream = features.get('upstream') if config_read else None

        if cve == 'CVE-2026-123007':
            if flags.get('http_v2_module') is False:
                row.update(exposure='not_exposed',
                           detail='сборка без --with-http_v2_module')
            elif http2 is False:
                row.update(exposure='not_exposed',
                           detail='HTTP/2 не включён в конфигурации')
            elif http2 is True:
                row.update(exposure='exposed',
                           detail='HTTP/2 включён в конфигурации')
            else:
                row.update(exposure='unknown',
                           detail='конфигурация недоступна, модуль HTTP/2 не проверен')
        elif cve == 'CVE-2026-123633':
            if flags.get('http_v2_module') is False:
                row.update(exposure='not_exposed',
                           detail='сборка без --with-http_v2_module')
            elif http2 is False:
                row.update(exposure='not_exposed',
                           detail='HTTP/2 не включён в конфигурации')
            elif http2 is True and upstream is True:
                row.update(exposure='possible',
                           detail='HTTP/2 включён и есть proxy_pass/grpc_pass на upstream')
            elif http2 is True and upstream is False:
                row.update(exposure='not_exposed',
                           detail='HTTP/2 включён, но forwarding на upstream не найден')
            else:
                row.update(exposure='unknown',
                           detail='конфигурация недоступна, HTTP/2/upstream не проверены')
        elif cve == 'CVE-2026-121810':
            if flags.get('http_v3_module') is False:
                row.update(exposure='not_exposed',
                           detail='сборка без --with-http_v3_module')
            elif http3 is False:
                row.update(exposure='not_exposed',
                           detail='HTTP/3/QUIC не включён в конфигурации')
            elif http3 is True and upstream is True:
                row.update(exposure='possible',
                           detail='HTTP/3 включён и есть forwarding на upstream')
            elif http3 is True and upstream is False:
                row.update(exposure='not_exposed',
                           detail='HTTP/3 включён, но forwarding на upstream не найден')
            else:
                row.update(exposure='unknown',
                           detail='конфигурация недоступна, HTTP/3/upstream не проверены')
        elif cve == 'CVE-2026-123634':
            if not config_read:
                row.update(exposure='unknown',
                           detail='конфигурация недоступна')
            elif not features.get('resolver') or not features.get('variable_proxy_pass'):
                row.update(exposure='not_exposed',
                           detail='нет resolver и/или proxy_pass с переменной')
            elif features.get('mirror') or features.get('ssi'):
                row.update(exposure='possible',
                           detail='есть resolver, proxy_pass с переменной и subrequest (mirror/SSI)')
            else:
                row.update(exposure='possible',
                           detail='есть resolver и proxy_pass с переменной; проверьте subrequest-директивы')
        elif cve == 'CVE-2026-113425':
            if flags.get('mail_module') is False:
                row.update(exposure='not_exposed',
                           detail='сборка без --with-mail')
            elif not config_read:
                row.update(exposure='unknown',
                           detail='конфигурация недоступна')
            elif features.get('mail_block') and features.get('mail_proxy_on') \
                    and features.get('auth_http'):
                row.update(exposure='exposed',
                           detail='mail-блок с proxy on и auth_http')
            elif features.get('mail_block'):
                row.update(exposure='not_exposed',
                           detail='mail-блок есть, но proxy on и/или auth_http не найдены')
            else:
                row.update(exposure='not_exposed',
                           detail='mail-блок не найден')


def local_package():
    """Вернуть (имя_пакета, версия) из dpkg/rpm или None."""
    for package in ('nginx', 'nginx-core', 'nginx-full', 'nginx-light'):
        try:
            proc = subprocess.run(
                ['dpkg-query', '-W', '-f=${Version}', package],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            break
        out = (proc.stdout or '').strip()
        if proc.returncode == 0 and out:
            return package, out
    try:
        proc = subprocess.run(
            ['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}', 'nginx'],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    out = (proc.stdout or '').strip()
    return ('nginx', out) if proc.returncode == 0 and out else None


def local_package_version():
    """Версия пакета nginx из dpkg/rpm (для обратной совместимости)."""
    package = local_package()
    return package[1] if package else None


def _command_output(command, timeout=10):
    """Выполнить необязательную команду и вернуть stdout+stderr (или '')."""
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ''
    return ((proc.stdout or '') + (proc.stderr or '')).strip()


def _simple_rpm_compare(left, right):
    """Упрощённое сравнение RPM EVR для известных версий nginx.

    Возвращает 1, -1 или 0. Этого достаточно для версий вида
    1.20.1-32.el9_9.2, 1.26.3-10.module+el9.9.0+... и 1.21.5-150400.3.28.1.
    """
    def split(value):
        value = (value or '').strip()
        epoch = 0
        if ':' in value:
            head, _, value = value.partition(':')
            if head.isdigit():
                epoch = int(head)
        if '-' in value:
            version, release = value.rsplit('-', 1)
        else:
            version, release = value, ''
        return epoch, parse_version(version) or (0, 0, 0), release

    left_epoch, left_version, left_release = split(left)
    right_epoch, right_version, right_release = split(right)
    if left_epoch != right_epoch:
        return 1 if left_epoch > right_epoch else -1
    if left_version != right_version:
        return 1 if left_version > right_version else -1

    def tokens(value):
        return [int(part) if part.isdigit() else part
                for part in re.findall(r'\d+|[A-Za-z]+', value)]

    for left_part, right_part in zip_longest(
            tokens(left_release), tokens(right_release), fillvalue=0):
        if left_part == right_part:
            continue
        if isinstance(left_part, int) and isinstance(right_part, int):
            return 1 if left_part > right_part else -1
        return 1 if str(left_part) > str(right_part) else -1
    return 0


def applicable_cves(version):
    """CVE, применимые к upstream-версии nginx (без учёта конфигурации)."""
    if version is None:
        return set()
    _, rows = assess_version(parse_version(version))
    return {row['cve'] for row in rows
            if row['version_status'] == 'vulnerable'}


def changelog_cves(text):
    """CVE nginx2root, упомянутые в changelog RPM/пакета."""
    return {match.group(0).upper()
            for match in _N2ROOT_CVE_RE.finditer(text or '')}


def _package_info(package, version, suite, status, source,
                  fixed_version=None, advisory=None, fixed_cves=None):
    info = {
        'package': package,
        'version': version,
        'suite': suite,
        'fixed_version': fixed_version,
        'advisory': advisory,
        'status': status,
        'source': source,
    }
    if fixed_cves is not None:
        info['fixed_cves'] = sorted(fixed_cves)
    return info


def upstream_package_status(version):
    """Статус по upstream-версии: fixed, vulnerable или unknown."""
    parsed = parse_version(version)
    if parsed is None:
        return 'unknown'
    return 'fixed' if not version_affected(parsed, (1, 9, 5)) else 'vulnerable'


def rpm_package_info(nginx_bin='nginx'):
    """Проверить RPM-пакет nginx (RHEL, Fedora, SUSE, Alma, Rocky, Oracle, Amazon)."""
    path = shutil.which(nginx_bin) or nginx_bin
    package = None
    version = None

    query = _command_output([
        'rpm', '-q', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n', '-f', path,
    ])
    for line in query.splitlines():
        if '\t' in line:
            package, version = line.split('\t', 1)
            break

    if not package:
        for candidate in ('nginx', 'nginx-core', 'nginx-full', 'nginx-light'):
            output = _command_output([
                'rpm', '-q', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}',
                candidate,
            ])
            if '\t' in output:
                package, version = output.split('\t', 1)
                break
    if not package or not version:
        return None

    data = _os_release()
    suite = ' '.join(filter(None, (data.get('ID'), data.get('VERSION_ID'))))
    suite = suite or 'rpm'
    applicable = applicable_cves(version)
    changelog = _command_output(['rpm', '-q', '--changelog', package])
    found = changelog_cves(changelog)
    if not found and _N2ROOT_TEXT_RE.search(changelog):
        # В changelog может не быть номера CVE — хотя бы ведущий фикс.
        found = {'CVE-2026-123007'}
    fixed_cves = found & applicable

    if applicable and fixed_cves >= applicable:
        status = 'fixed'
        source = 'rpm-changelog'
    elif fixed_cves:
        status = 'partial'
        source = 'rpm-changelog'
    else:
        status = upstream_package_status(version)
        source = 'upstream'
        if status == 'fixed':
            fixed_cves = applicable

    info = _package_info(
        package, version, suite, status, source, fixed_cves=fixed_cves,
    )
    if status != 'fixed' and os_family() == 'suse':
        release = version.rsplit('-', 1)[-1]
        branch = release.split('.', 1)[0]
        candidate = SUSE_FIXED.get(branch)
        if candidate and _simple_rpm_compare(version, candidate) >= 0:
            info.update(status='fixed', source='suse-advisory',
                        fixed_version=candidate,
                        fixed_cves=sorted(applicable))
    if data.get('ID', '').lower() == 'centos' and info['status'] != 'fixed':
        info['note'] = ('CentOS Linux 7/8 EOL и официальных фиксов не получает; '
                        'для CentOS Stream ждите RHEL-сборку или проверьте '
                        'rpm -q --changelog nginx')
    return info


def _alpine_version_key(value):
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-r(\d+))?', value or '')
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def _simple_alpine_compare(left, right):
    left_key = _alpine_version_key(left)
    right_key = _alpine_version_key(right)
    if left_key is None or right_key is None:
        return None
    if left_key == right_key:
        return 0
    return 1 if left_key > right_key else -1


def alpine_package_info():
    """Проверить пакет Alpine Linux (apk)."""
    version = None
    output = _command_output(['apk', 'info', '-v', 'nginx'])
    match = re.search(r'nginx-(\d+\.\d+\.\d+(?:-r\d+)?)', output)
    if match:
        version = match.group(1)
    if not version:
        output = _command_output(['apk', 'list', '--installed', 'nginx'])
        match = re.search(r'nginx-(\d+\.\d+\.\d+(?:-r\d+)?)', output)
        if match:
            version = match.group(1)
    if not version:
        return None

    branch = ''
    release = _read_text('/etc/alpine-release')
    match = re.match(r'^(\d+\.\d+)', release)
    if match:
        branch = match.group(1)
    if not branch and 'edge' in _read_text('/etc/apk/repositories'):
        branch = 'edge'

    fixed = ALPINE_FIXED.get(branch)
    applicable = applicable_cves(version)
    info = _package_info(
        'nginx', version, branch or 'alpine', 'unknown', 'apk',
        fixed_version=fixed, advisory=ALPINE_ADVISORY.get(branch),
    )
    if fixed:
        comparison = _simple_alpine_compare(version, fixed)
        if comparison in (0, 1):
            info.update(status='fixed', fixed_cves=sorted(applicable))
        elif comparison == -1:
            info['status'] = 'vulnerable'
        return info
    status = upstream_package_status(version)
    info.update(status=status, source='upstream')
    if status == 'fixed':
        info['fixed_cves'] = sorted(applicable)
    return info


def pacman_package_info():
    """Проверить пакет Arch Linux (pacman)."""
    package = 'nginx'
    version = None
    for candidate in ('nginx', 'nginx-mainline'):
        output = _command_output(['pacman', '-Q', candidate])
        match = re.match(r'(\S+)\s+(\S+)', output)
        if match:
            package, version = match.group(1), match.group(2)
            break
    if not version:
        return None
    status = upstream_package_status(version)
    info = _package_info(
        package, version, 'Arch Linux', status, 'pacman',
        fixed_version='1.30.7 / 1.31.9',
    )
    if status == 'fixed':
        info['fixed_cves'] = sorted(applicable_cves(version))
    return info


def freebsd_package_info():
    """Проверить пакет FreeBSD (pkg)."""
    version = None
    for package in ('nginx', 'nginx-devel'):
        output = _command_output(['pkg', 'query', '%v', package])
        if output and not output.startswith('pkg:'):
            version = output.splitlines()[0].strip()
            break
    if not version:
        return None
    status = upstream_package_status(version)
    info = _package_info(
        'nginx', version, 'FreeBSD', status, 'pkg',
        fixed_version='1.30.7 / 1.31.9',
    )
    if status == 'fixed':
        info['fixed_cves'] = sorted(applicable_cves(version))
    return info


def package_status(nginx_bin='nginx'):
    """Определить статус установленного пакета nginx для текущей ОС."""
    family = os_family()
    if family in ('debian', 'ubuntu'):
        package = local_package()
        return debian_package_info(*package) if package else None
    if family in ('rpm', 'suse'):
        return rpm_package_info(nginx_bin)
    if family == 'alpine':
        return alpine_package_info()
    if family == 'arch':
        return pacman_package_info()
    if family == 'freebsd':
        return freebsd_package_info()

    # Неизвестная ОС: пробуем dpkg, затем rpm.
    package = local_package()
    if package:
        return debian_package_info(*package)
    return rpm_package_info(nginx_bin)


def kernel_sctp_advisory():
    """Проверить, доступен ли SCTP — усилитель nginx2root до root."""
    item = {
        'id': 'SCTP',
        'title': 'SCTP в ядре (LPE до root)',
        'status': 'unknown',
        'detail': '',
    }
    if platform.system() != 'Linux':
        item.update(status='not_applicable',
                    detail=f'не Linux ({platform.system()})')
        return item

    release = platform.release()
    kernel = parse_version(release)
    if kernel is None:
        match = re.match(r'(\d+)\.(\d+)', release)
        kernel = (int(match.group(1)), int(match.group(2)), 0) if match else None
    if kernel is not None and kernel < (4, 15, 0):
        item.update(status='not_applicable',
                    detail=f'ядро {release} старше 4.15 — цепочка неприменима')
        return item

    loaded = False
    try:
        with open('/proc/modules', encoding='utf-8', errors='replace') as file:
            loaded = bool(re.search(r'(?m)^sctp\s', file.read()))
    except OSError:
        pass

    builtin = False
    try:
        with open('/proc/net/protocols', encoding='utf-8', errors='replace') as file:
            protocols = file.read()
        builtin = not loaded and bool(re.search(r'(?m)^SCTP\s', protocols, re.IGNORECASE))
    except OSError:
        pass

    blocked = False
    blacklisted = False
    for path in glob.glob('/etc/modprobe.d/*.conf'):
        try:
            with open(path, encoding='utf-8', errors='replace') as file:
                text = file.read()
        except OSError:
            continue
        if re.search(r'(?m)^\s*install\s+sctp\s+/bin/false\b', text):
            blocked = True
        if re.search(r'(?m)^\s*blacklist\s+sctp\b', text):
            blacklisted = True

    if builtin:
        item.update(status='warning',
                    detail=f'SCTP встроен в ядро {release}; цепочка nginx2root → root возможна')
    elif loaded:
        item.update(status='warning',
                    detail=f'модуль sctp загружен; цепочка nginx2root → root возможна')
    elif blocked:
        item.update(status='ok',
                    detail='загрузка sctp заблокирована через modprobe.d')
    elif blacklisted:
        item.update(status='warning',
                    detail='sctp только в blacklist: явный modprobe всё равно загрузит модуль; '
                           'надёжнее install sctp /bin/false')
    else:
        item.update(status='warning',
                    detail='модуль sctp не загружен, но может загрузиться автоматически; '
                           'если SCTP не нужен, добавьте install sctp /bin/false')

    item.update(kernel=release, loaded=loaded, builtin=builtin,
                blocked=blocked, blacklisted=blacklisted)
    return item


def check_local(nginx_bin='nginx'):
    """Проверить локальный nginx и вернуть (status, version, error, details)."""
    version = None
    error = None
    status = 'unknown'
    details = {'cves': [], 'advisories': []}
    try:
        text, code = _run_nginx([nginx_bin, '-v'])
        if code != 0:
            raise RuntimeError(text.strip() or f'{nginx_bin} -v завершился с кодом {code}')
        version = extract_nginx_version(text)
        if version is None:
            raise ValueError('не удалось определить версию nginx из `nginx -v`')

        status, rows = assess_version(parse_version(version))
        details['version_source'] = 'nginx -v'

        package_info = package_status(nginx_bin)
        if package_info:
            details['package'] = package_info
            details['package_version'] = package_info['version']

        build_text, build_code = _run_nginx([nginx_bin, '-V'])
        flags = parse_build_flags(build_text) if build_code == 0 else {}
        details['build'] = flags
        if build_code != 0:
            details['build_error'] = build_text.strip() or f'код {build_code}'

        config_text, config_code = _run_nginx([nginx_bin, '-T'])
        config_read = config_code == 0
        if config_read:
            features = parse_config(config_text)
            details['config'] = features
            apply_local_exposures(rows, features, flags, True)
        else:
            details['config'] = None
            details['config_error'] = (
                _last_text_line(config_text)
                or f'`nginx -T` завершился с кодом {config_code}'
            )
            apply_local_exposures(rows, {}, flags, False)

        # Пакет дистрибутива важнее номера upstream-версии: nginx -v
        # продолжает показывать старую версию, хотя пакет уже исправлен.
        # fixed_cves учитывает, какие именно CVE закрыл вендор.
        if package_info:
            fixed_cves = set(package_info.get('fixed_cves') or [])
            if fixed_cves:
                suite = f" ({package_info['suite']})" if package_info.get('suite') else ''
                note = (f"исправлено в пакете {package_info['version']}"
                        f"{suite}")
                if package_info.get('advisory'):
                    note += f", advisory {package_info['advisory']}"
                for row in rows:
                    # CVE, неприменимые к upstream-версии (например, HTTP/3
                    # в 1.22.1), не выдаём за «исправленные пакетом».
                    if row['version_status'] == 'ok':
                        continue
                    if row['cve'] in fixed_cves:
                        row.update(version_status='ok',
                                   exposure='not_applicable', detail=note)
            if package_info['status'] == 'fixed':
                status = 'ok'

        details['cves'] = rows
        details['advisories'] = [kernel_sctp_advisory()]
    except Exception as exc:
        error = str(exc)
    return status, version, error, details


def _last_text_line(text):
    """Последняя непустая строка вывода (для компактной ошибки)."""
    lines = [line.strip() for line in (text or '').splitlines()
             if line.strip() and not _LAST_CONFIG_LINE_RE.match(line)]
    return lines[-1] if lines else ''


def read_urls(path):
    """Прочитать список URL из файла ('-' — stdin).

    Пропускаются пустые строки и комментарии (#), дубликаты убираются.
    """
    if path == '-':
        lines = sys.stdin
        close = False
    else:
        lines = open(path, encoding='utf-8')
        close = True
    try:
        urls = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            urls.append(line.split('#', 1)[0].strip())
    finally:
        if close:
            lines.close()
    return list(dict.fromkeys(urls))


def _reason(status, version, error):
    if error:
        return error
    return f'nginx {version}' if version else 'Версия nginx не найдена'


def _report(status, version, error, details):
    return {
        'patch_status': status,
        'nginx_version': version,
        'reason': _reason(status, version, error),
        'exit_code': EXIT[status],
        **details,
    }


def _print_cve_rows(details):
    for row in details.get('cves', []):
        label = EXPOSURE_LABELS.get(row['exposure'], row['exposure'])
        print(f"  {row['cve']} ({row['title']}): {label} — {row['detail']}")


def _yn(value):
    return 'да' if value is True else 'нет' if value is False else '?'


def _print_url_details(details):
    server = details.get('server')
    if server:
        print(f'  Server: {server}')
    if details.get('http2') is True:
        print('  HTTP/2: да (ALPN h2)')
    elif details.get('http2') is False:
        print('  HTTP/2: нет (ALPN не h2)')
    else:
        suffix = details.get('alpn_error')
        print('  HTTP/2: не проверен' + (f' — {suffix}' if suffix else ''))
    if details.get('http3_advertised') is True:
        print('  HTTP/3: рекламируется в Alt-Svc')
    elif details.get('http3_advertised') is False:
        print('  HTTP/3: не рекламируется (отсутствие Alt-Svc не доказывает отсутствие QUIC)')
    if details.get('caveat'):
        print(f"  Примечание: {details['caveat']}")
    if details.get('note'):
        print(f"  Примечание: {details['note']}")
    _print_cve_rows(details)


def _print_local_details(details):
    flags = details.get('build') or {}
    config = details.get('config') or {}
    if flags:
        print('  Сборка: '
              f"HTTP/2={_yn(flags.get('http_v2_module'))}, "
              f"HTTP/3={_yn(flags.get('http_v3_module'))}, "
              f"mail={_yn(flags.get('mail_module'))}")
    if config:
        print('  Конфигурация: '
              f"HTTP/2={_yn(config.get('http2'))}, "
              f"HTTP/3={_yn(config.get('http3'))}, "
              f"resolver={_yn(config.get('resolver'))}, "
              f"proxy_pass с переменной={_yn(config.get('variable_proxy_pass'))}, "
              f"mirror={_yn(config.get('mirror'))}, "
              f"mail proxy={_yn(config.get('mail_proxy_on'))}")
    if details.get('config_error'):
        print(f"  Конфигурация недоступна: {details['config_error']}")
    if details.get('build_error'):
        print(f"  Сборка не определена: {details['build_error']}")
    _print_cve_rows(details)
    package = details.get('package')
    if package:
        suite = f" ({package['suite']})" if package.get('suite') else ''
        fixed = package.get('fixed_version')
        status = {
            'fixed': 'исправлено',
            'partial': 'исправлено частично',
            'vulnerable': 'уязвимо',
        }.get(package.get('status'), 'не удалось сравнить')
        line = f"  Пакет: {package['package']} {package['version']}{suite} — {status}"
        if fixed:
            line += f"; исправление: {fixed}"
        if package.get('advisory'):
            line += f" ({package['advisory']})"
        if package.get('source'):
            line += f" [{package['source']}]"
        print(line)
        if package.get('note'):
            print(f"  Примечание: {package['note']}")
    for item in details.get('advisories', []):
        print(f"  {item['title']}: {item['status'].upper()} — {item['detail']}")


def _print_result(url, status, version, error, details, json_out, verbose=False):
    """Напечатать результат проверки одного URL."""
    report = _report(status, version, error, details)
    if url is not None:
        report = {'url': url, **report}
    with _print_lock:
        if json_out:
            print(json.dumps(report, ensure_ascii=False))
        else:
            prefix = f'{url} — ' if url is not None else ''
            print(f'{prefix}{status.upper()}: {report["reason"]}')
            if verbose:
                _print_url_details(details)
    return EXIT[status]


async def _run_async(urls, workers, timeout, insecure, handle):
    """Асинхронная оркестрация проверок с ограничением одновременности."""
    semaphore = asyncio.Semaphore(workers)
    loop = asyncio.get_running_loop()

    async def one(url):
        async with semaphore:
            # Сетевой вызов блокирующий — выполняется в пуле потоков.
            await loop.run_in_executor(None, handle, url)

    await asyncio.gather(*(one(url) for url in urls))


def run_bulk(urls, threads, timeout, async_mode, json_out, insecure):
    """Проверить список URL и вернуть агрегированный код возврата."""
    codes = []

    def handle(url):
        status, version, error, details = check_url(url, timeout, insecure)
        codes.append(_print_result(
            url, status, version, error, details, json_out, verbose=False,
        ))

    if async_mode:
        asyncio.run(_run_async(urls, threads, timeout, insecure, handle))
    elif threads > 1:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            list(executor.map(handle, urls))
    else:
        for url in urls:
            handle(url)

    if EXIT['vulnerable'] in codes:
        return EXIT['vulnerable']
    if EXIT['unknown'] in codes:
        return EXIT['unknown']
    return EXIT['ok']


def _usage_error(message):
    print(message + '\n' + USAGE, file=sys.stderr)
    return 2


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv

    opts = {
        'local': False,
        'nginx': 'nginx',
        'nginx_set': False,
        'timeout': '10',
        'file': None,
        'threads': '1',
        'threads_set': False,
        'async': False,
        'json': False,
        'insecure': False,
        'version': False,
        'help': False,
    }
    positionals = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('-h', '--help'):
            opts['help'] = True
        elif arg == '--local':
            opts['local'] = True
        elif arg == '--async':
            opts['async'] = True
        elif arg == '--json':
            opts['json'] = True
        elif arg == '--insecure':
            opts['insecure'] = True
        elif arg == '--version':
            opts['version'] = True
        elif arg in ('--nginx', '--timeout', '--file', '--threads'):
            i += 1
            if i >= len(args):
                return _usage_error(f'Для {arg} требуется значение')
            key = arg[2:]
            opts[key] = args[i]
            if key == 'nginx':
                opts['nginx_set'] = True
            if key == 'threads':
                opts['threads_set'] = True
        elif arg.startswith(('--nginx=', '--timeout=', '--file=', '--threads=')):
            key, _, value = arg.partition('=')
            key = key[2:]
            opts[key] = value
            if key == 'nginx':
                opts['nginx_set'] = True
            if key == 'threads':
                opts['threads_set'] = True
        elif arg.startswith('-') and arg != '-':
            return _usage_error(f'Неизвестная опция: {arg}')
        else:
            positionals.append(arg)
        i += 1

    if opts['version']:
        print(VERSION)
        return 0
    if opts['help']:
        print(USAGE)
        return 0

    address = positionals[0] if positionals else None
    if len(positionals) > 1:
        return _usage_error('Можно указать только один URL')
    modes = sum((
        address is not None,
        opts['file'] is not None,
        opts['local'],
    ))
    if modes != 1:
        return _usage_error('Укажите что-то одно: URL, --file или --local')
    if opts['async'] and not opts['file']:
        return _usage_error('--async можно использовать только вместе с --file')
    if opts['threads_set'] and not opts['file']:
        return _usage_error('--threads можно использовать только вместе с --file')
    if opts['nginx_set'] and not opts['local']:
        return _usage_error('--nginx можно использовать только вместе с --local')
    if opts['insecure'] and opts['local']:
        return _usage_error('--insecure можно использовать только с URL или --file')

    try:
        threads = int(opts['threads'])
    except ValueError:
        threads = 0
    if threads < 1:
        return _usage_error('--threads должен быть целым числом от 1')

    try:
        timeout = float(opts['timeout'])
    except ValueError:
        timeout = float('nan')
    if not opts['local'] and not (0 < timeout <= 60):
        return _usage_error('--timeout должен быть больше 0 и не больше 60 секунд')

    if opts['local']:
        status, version, error, details = check_local(opts['nginx'])
        report = _report(status, version, error, details)
        if opts['json']:
            print(json.dumps(report, ensure_ascii=False))
        else:
            print(f'{status.upper()}: {report["reason"]}')
            _print_local_details(details)
        return EXIT[status]

    if opts['file']:
        try:
            urls = read_urls(opts['file'])
        except OSError as exc:
            return _usage_error(f'Не удалось прочитать файл со списком: {exc}')
        if not urls:
            return _usage_error('Файл не содержит ни одного URL')
        return run_bulk(urls, threads, timeout, opts['async'],
                        opts['json'], opts['insecure'])

    status, version, error, details = check_url(address, timeout, opts['insecure'])
    if opts['json']:
        print(json.dumps(_report(status, version, error, details),
                         ensure_ascii=False))
    else:
        print(f'{status.upper()}: {_reason(status, version, error)}')
        _print_url_details(details)
    return EXIT[status]


if __name__ == '__main__':
    sys.exit(main())
