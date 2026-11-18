#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy_pro.py — SOCKS-прокси менеджер v2 (ProxyGUI).

Новое против прошлой версии:
  • интерфейс: карточка состояния с индикаторами, цветные строки таблицы,
    поиск и фильтры (только живые / без утечек / только SOCKS5),
  • рейтинг прокси: score по скорости, успешности и стабильности,
  • тестирование качества: трёхраундовая проверка с реальным HTTP-запросом
    через прокси, процент успешных соединений и среднее время отклика,
  • защита от утечек: сверка фактического IP/страны выхода (ip-api)
    с заявленной страной, предупреждение при расхождении,
  • надёжное переключение: мост автоматически переходит на следующий
    живой прокси при обрыве (по рейтингу), GUI не блокируется,
  • мониторинг: периодическая проверка активного прокси и статус в карточке.

Сохранено из прошлых версий: поиск с мини-капчей (решается автоматически,
с учётом honeypot-поля), паузы и повторы при «sent too fast» и
«invalid security code», пагинация, режимы «Россия / Все, кроме России»,
ручное переключение, шифрованный кэш, журнал ошибок, трей.

Запуск: python proxy_pro.py
Сборка exe: py -m PyInstaller --onefile --windowed --name ProxyGUI proxy_pro.py
"""

import base64
import concurrent.futures
import gzip
import http.cookiejar
import json
import queue
import re
import socket
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import zlib
from html import unescape as html_unescape
import os
try:
    import certifi
    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
    os.environ.setdefault("REQUESTS_CA_BUNDLE", certifi.where())
except ImportError:
    pass

PAGE_URL = "https://te-home.net/?do=tools&action=socks"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
TIMEOUT = 5            # сек на одно соединение через прокси
TEST_LIMIT = 500       # максимум прокси на проверку
TEST_WORKERS = 20      # потоков параллельной проверки
ROUNDS = 3             # раундов в тесте качества
CACHE_FILE = "proxies_cache.json"
REFRESH_MINUTES = 60   # интервал автообновления списка
BRIDGE_PORT = 10808    # локальный порт моста
WATCH_INTERVAL = 300   # сек между проверками апстрима моста
MONITOR_INTERVAL = 60  # сек между проверками активного прокси в карточке
FORM_WAIT = 4.0        # пауза перед отправкой формы (сайт отвергает быстрые)
RETRY_WAIT = 10.0      # пауза перед повтором после отказа
MAX_ATTEMPTS = 3       # попыток отправки формы
IPAPI_IP = "208.95.112.1"   # ip-api.com (коннект по IP — без DNS)
DUMP_PREFIX = "tehome_"     # префикс диагностических дампов

MODE_RU = "Россия"
MODE_NOT_RU = "Все, кроме России"
MODES = (MODE_RU, MODE_NOT_RU)

if os.environ.get("ANDROID_ARGUMENT") or os.environ.get("ANDROID_DATA"):
    APP_DIR = os.path.expanduser("~")          # доступная приложению папка на Android
elif getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_PATH = os.path.join(APP_DIR, CACHE_FILE)


# ---------------------------------------------------------------- сеть

import ssl

def _ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()

_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ssl_context()),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def fetch(url, data=None):
    headers = {
        "User-Agent": UA,
        "Referer": PAGE_URL,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    req = urllib.request.Request(url, data=data, headers=headers)
    resp = _opener.open(req, timeout=15)
    raw = resp.read()
    enc = (resp.headers.get("Content-Encoding") or "").lower()
    if "gzip" in enc:
        raw = gzip.decompress(raw)
    elif "deflate" in enc:
        try:
            raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        except zlib.error:
            raw = zlib.decompress(raw)
    charset = resp.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, "replace")


# ---------------------------------------------------------------- парсинг

TAG_RE = re.compile(r"<[^>]+>")
IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
ROW_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S | re.I)
CELL_RE = re.compile(r"<t[dh][^>]*>(.*?)</t[dh]>", re.S | re.I)
FORM_BLOCK_RE = re.compile(r"<form[^>]*>.*?</form>", re.S | re.I)


def clean_cell(cell):
    """Декодирует HTML-сущности (сайт прячет цифры IP за ними) и убирает теги."""
    txt = html_unescape(cell)
    txt = TAG_RE.sub(" ", txt)
    return re.sub(r"\s+", " ", txt).strip()


def is_russia(country_text):
    """Строгое сравнение страны (по alt флажка либо по тексту ячейки)."""
    t = (country_text or "").strip().lower()
    return t in ("russia", "russian federation")


def parse_table_proxies(page_html, only_russia=False, exclude_russia=False):
    """Разбирает таблицу результатов: Location | Address | Port | Version | Delay.
    only_russia — оставить только российские, exclude_russia — убрать российские."""
    proxies, seen = [], set()
    for row in ROW_RE.findall(page_html):
        raw_cells = CELL_RE.findall(row)
        if len(raw_cells) < 5:
            continue
        # страна: сначала alt флажка (надёжнее, допускаем одинарные кавычки), иначе текст ячейки
        fm = re.search(r'alt\s*=\s*["\']([^"\']+)["\']', raw_cells[0], re.I)
        country = html_unescape(fm.group(1)).strip() if fm else ""
        location = clean_cell(raw_cells[0])
        country = country or location
        if only_russia and not is_russia(country):
            continue
        if exclude_russia and is_russia(country):
            continue
        address, port_s, version_s, delay_s = (clean_cell(c) for c in raw_cells[1:5])
        m = IPV4_RE.search(address)
        if not m or not port_s.isdigit():
            continue
        port = int(port_s)
        if not 1 <= port <= 65535:
            continue
        if any(int(part) > 255 for part in m.group(1).split(".")):
            continue
        ver = int(version_s) if version_s in ("4", "5") else 5
        dm = re.search(r"(\d[\d\s]*)\s*ms", delay_s)
        delay = int(dm.group(1).replace(" ", "")) if dm else 99999
        if (m.group(1), port) in seen:
            continue
        seen.add((m.group(1), port))
        proxies.append({"ip": m.group(1), "port": port, "version": ver,
                        "delay": delay, "country": country})
    return sorted(proxies, key=lambda p: p["delay"])


def find_search_form(page_html):
    """Ищет форму расширенного поиска (содержит socks_code)."""
    for form_html in FORM_BLOCK_RE.findall(page_html):
        if "socks_code" in form_html:
            tag = re.match(r"<form[^>]*>", form_html).group(0)
            am = re.search(r"action\s*=\s*['\"]([^'\"]*)['\"]", tag)
            mm = re.search(r"method\s*=\s*['\"]([^'\"]*)['\"]", tag, re.I)
            action = html_unescape(urllib.parse.urljoin(
                PAGE_URL, (am.group(1) if am else "")).split("#")[0])
            return form_html, action or PAGE_URL, (mm.group(1).upper() if mm else "POST")
    return None, PAGE_URL, "POST"



def solve_captcha(form_html):
    """Решает арифметическую капчу формы. Сайт пишет пример открытым текстом,
    но между числами и завершителем может стоять honeypot-поле и другие теги
    (реальный вид: 26 &#43; 7<input class="hpot" name="te_hp">: *). Поэтому
    ищем пример, допуская теги и пробелы между любыми токенами; из нескольких
    кандидатов берём тот, что ближе к полю socks_code."""
    raw = html_unescape(form_html)
    pos = raw.find("socks_code")
    tok = r"(?:<[^>]*>|\s)*"
    pat = rf"(\d{{1,3}}){tok}([+\-−x×*·:/]){tok}(\d{{1,3}}){tok}[:=]"
    cands = []
    for m in re.finditer(pat, raw):
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op not in "+-−x×*·:/":
            continue
        if op in ":/" and (b == 0 or a % b != 0):
            continue
        anchor = pos if pos >= 0 else 0
        cands.append((abs(m.start() - anchor), a, op, b))
    if not cands:
        return None
    cands.sort(key=lambda t: t[0])
    _, a, op, b = cands[0]
    if op == "+":
        return a + b
    if op in "-−":
        return a - b
    return a * b if op in "x×*·" else a // b


def select_options(form_html, name):
    """Все (value, text) варианта выпадающего списка с данным именем."""
    m = re.search(rf"<select[^>]*name\s*=\s*[\"']{re.escape(name)}[\"'][^>]*>(.*?)</select>",
                  form_html, re.S | re.I)
    if not m:
        return []
    opts = []
    for om in re.finditer(r"<option([^>]*)>([^<]*)", m.group(1), re.I):
        attrs, text = om.group(1), om.group(2).strip()
        vm = re.search(r'value\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        val = html_unescape(vm.group(1)) if vm else html_unescape(text)
        opts.append((val.strip(), html_unescape(text).strip()))
    return opts


def resolve_location_candidates(form_html, mode):
    """Очередь кандидатов значения поля socks_location: сервер может ждать
    value варианта, полный текст («RU - Russia») или название страны
    («Russia») — пробуем по порядку, каждый на свежей странице.
    Для «Россия»: value варианта с Russia -> полный текст -> «Russia»
    (страны в базе записаны полными названиями, это видно в Random 100).
    Для «Все, кроме России»: сначала поле не отправляется вовсе (браузер
    по умолчанию), затем value первого пункта («Real»)."""
    opts = select_options(form_html, "socks_location")
    if not opts:
        return []
    cands, seen = [], set()

    def add(v):
        if v not in seen:
            seen.add(v)
            cands.append(v)

    if mode == MODE_NOT_RU:
        add(None)                  # без поля location вовсе
        if opts[0][0]:             # непустое значение первого пункта («Real»);
            add(opts[0][0])        # пустое — это «страна пустая», его не шлём
        return cands
    for val, text in opts:
        t = text.lower()
        if "russia" in t and "belarus" not in t or "россия" in t:
            if val:
                add(val)                   # value варианта
            add(text)                      # полный текст («RU - Russia»)
            add("Russia")                  # название страны из базы
            break
    return cands

# совместимость со старым именем
def resolve_location_value(form_html, mode):
    cands = resolve_location_candidates(form_html, mode)
    return cands[0] if cands else None


def collect_form_fields(form_html):
    """Собирает ВСЕ поля формы, как это сделал бы браузер: hidden, text, submit,
    а также select с их выбранными значениями. Поля socks_* мы всё равно
    перезаписываем своими — но серверу важно получить скрытые поля целиком."""
    fields = {}
    for tag in re.findall(r"<(?:input|button)[^>]*>", form_html, re.I):
        nm = re.search(r'name\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        if not nm:
            continue
        name = nm.group(1)
        low = tag.lower()
        if 'type="radio"' in low or "type='radio'" in low:
            if "checked" not in low:
                continue
        if 'type="checkbox"' in low or "type='checkbox'" in low:
            if "checked" not in low:
                continue
        vm = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.I)
        fields[name] = html_unescape(vm.group(1)) if vm else ""
    for sname, inner in re.findall(
            r"<select[^>]*name\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</select>",
            form_html, re.S | re.I):
        chosen, first = None, None
        for om in re.finditer(r"<option([^>]*)>([^<]*)", inner, re.I):
            attrs, text = om.group(1), om.group(2).strip()
            vm = re.search(r'value\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
            val = html_unescape(vm.group(1)) if vm else html_unescape(text)
            if first is None:
                first = val   # первый пункт списка, даже с пустым value (как браузер)
            if re.search(r"\bselected\b", attrs, re.I):
                chosen = val
        if chosen is not None:
            fields[sname] = chosen
        elif first is not None:
            fields[sname] = first
    return fields


def collect_pagination_links(page_html):
    """Ссылки на следующие страницы результатов (page=, p=, start=, offset=)."""
    links = []
    for m in re.finditer(r'<a[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]*>', page_html, re.I):
        href = m.group(1)
        low = href.lower()
        if any(k in low for k in ("page=", "p=", "start=", "offset=")):
            links.append(urllib.parse.urljoin(PAGE_URL, href.split("#")[0]))
    return links


def _dedupe(proxies):
    seen, uniq = set(), []
    for p in proxies:
        k = (p["ip"], p["port"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(p)
    return uniq



def _dump(name, text):
    try:
        with open(os.path.join(APP_DIR, DUMP_PREFIX + name), "w", encoding="utf-8", errors="replace") as f:
            f.write(text or "")
    except Exception:
        pass


def get_proxies(mode, log=None):
    """Загружает список прокси согласно режиму.

    Каскад значений фильтра: сервер может ждать value варианта, полный
    текст («RU - Russia») или название страны («Russia»). Каждый кандидат
    пробуется на свежей странице (капча одноразовая). Временные отказы
    («sent too fast», «invalid security code», сетевая ошибка) НЕ расходуют
    кандидата — он возвращается в начало очереди. Если все кандидаты дали
    «no results» — запасной путь: разбор Random 100 с уже скачанной
    страницы, без формы и капчи.
    Возвращаем (proxies, источник, причина_отказа)."""
    log = log or (lambda msg: None)
    only_ru = (mode == MODE_RU)
    ex_ru = (mode == MODE_NOT_RU)
    reason = None
    last_html = None
    cand_queue = []          # кандидаты значения location; [] = ещё не построена
    attempt = 0
    while attempt < MAX_ATTEMPTS:
        attempt += 1
        try:
            html = fetch(PAGE_URL)
        except Exception as e:
            detail = ""
            if hasattr(e, "reason"):
                detail = f" reason={e.reason!r}"
            log(f"[поиск] не удалось загрузить: {type(e).__name__}: {e}{detail}")
            time.sleep(RETRY_WAIT)
            continue                 # сетевой сбой: кандидат не расходуется

        last_html = html
        form_html, action, method = find_search_form(html)
        if not form_html:
            found = parse_table_proxies(html, only_russia=only_ru, exclude_russia=ex_ru)
            if found:
                return found, "случайная выборка главной страницы (формы нет)", None
            return [], "формы поиска на странице нет", None

        code = solve_captcha(form_html)
        if code is None:
            _dump("form.html", html)
            reason = "капчу решить не удалось (дамп: tehome_form.html)"
            log(f"[поиск] {reason}, повтор…")
            time.sleep(RETRY_WAIT)
            continue

        if not cand_queue:
            cand_queue = resolve_location_candidates(form_html, mode)
            if not cand_queue:
                if only_ru:
                    _dump("location_options.txt", "\n".join(
                        f"{v!r} :: {t!r}" for v, t in
                        select_options(form_html, "socks_location")))
                    return [], ("вариант Russia в списке Location не найден "
                                "(дамп: tehome_location_options.txt)"), None
                cand_queue = [None]     # без поля location вовсе
        loc = cand_queue[0]             # кандидат расходуется только на «no results»
        data = collect_form_fields(form_html)
        if loc is None:
            data.pop("socks_location", None)
        else:
            data["socks_location"] = loc
        data["socks_send"] = data.get("socks_send") or "Search"
        data["socks_code"] = str(code)
        data.pop("socks_cancel", None)   # браузер шлёт только нажатую кнопку
        payload = urllib.parse.urlencode(data).encode("utf-8")
        shown = "(поле не отправляется)" if loc is None else repr(loc)
        log(f"[поиск] попытка {attempt}/{MAX_ATTEMPTS}: капча {code}, "
            f"location={shown}, пауза {FORM_WAIT:.0f} с…")
        time.sleep(FORM_WAIT)
        try:
            if method == "POST":
                result = fetch(action, data=payload)
            else:
                qs = dict(data)
                result = fetch(action + ("&" if "?" in action else "?")
                               + urllib.parse.urlencode(qs))
        except Exception as e:
            _dump("post_error.txt", traceback.format_exc())
            reason = f"ошибка при отправке формы: {e.__class__.__name__} (дамп: tehome_post_error.txt)"
            log(f"[поиск] {reason}, повтор…")
            time.sleep(RETRY_WAIT)
            continue                     # кандидат остаётся в очереди
        low = (result or "").lower()
        last_html = result
        if "sent too fast" in low:
            reason = "отклонено: «sent too fast»"
            log(f"[поиск] {reason} (попытка {attempt}), ждём {RETRY_WAIT:.0f} с и перечитываем страницу…")
            time.sleep(RETRY_WAIT)
            continue                     # кандидат остаётся в очереди
        if "invalid security code" in low:
            reason = f"отклонено: «invalid security code» (ответ {code} не подошёл)"
            log(f"[поиск] {reason}, перечитываем страницу (капча меняется)…")
            time.sleep(RETRY_WAIT)
            continue                     # кандидат остаётся в очереди
        found = parse_table_proxies(result, only_russia=only_ru, exclude_russia=ex_ru)
        if not found:
            if "no results" in low:
                reason = f"сервер: по фильтру {shown} совпадений нет — пробую следующее значение"
                log(f"[поиск] {reason}")
                cand_queue.pop(0)        # честный отказ: кандидат расходуется
                if cand_queue:
                    continue             # следующая попытка — свежая страница
                break
            _dump("post_result.html", result)
            reason = "форма принята, но строки не разобрались (дамп: tehome_post_result.html)"
            return [], reason, reason
        pages = 0
        for link in collect_pagination_links(result):
            if pages >= 5:
                break
            try:
                found += parse_table_proxies(fetch(link), only_russia=only_ru,
                                             exclude_russia=ex_ru)
                pages += 1
            except Exception:
                pass
        found = _dedupe(found)
        return found, f"полный список через форму (location={shown}, страниц: {pages + 1})", None
    # кандидаты исчерпаны или попытки кончились — запасной путь Random 100:
    html = last_html
    if not html:
        try:
            html = fetch(PAGE_URL)
        except Exception:
            return [], "нет данных для разбора Random 100", reason
    found = parse_table_proxies(html, only_russia=only_ru, exclude_russia=ex_ru)
    if found:
        return found, "Random 100 со страницы по умолчанию (без фильтра страны)", reason
    if html is last_html:
        try:
            html = fetch(PAGE_URL)
            found = parse_table_proxies(html, only_russia=only_ru, exclude_russia=ex_ru)
        except Exception:
            found = []
    if found:
        return found, "Random 100 главной страницы (без фильтра страны)", reason
    return [], (f"фильтры не сработали и Random 100 пуст "
                f"(последняя причина: {reason})"), reason


def recv_exact(sock, size):
    """Читает ровно size байт; None означает закрытое/неполное соединение."""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def read_socks5_reply(sock):
    """Полностью читает ответ SOCKS5 CONNECT, включая адрес и порт."""
    head = recv_exact(sock, 4)
    if head is None or head[0] != 5:
        return False
    if head[3] == 1:
        size = 4
    elif head[3] == 4:
        size = 16
    elif head[3] == 3:
        length = recv_exact(sock, 1)
        if length is None:
            return False
        size = length[0]
    else:
        return False
    tail = recv_exact(sock, size + 2)
    return tail is not None and head[1] == 0



def socks_open(proxy_ip, proxy_port, version, dst_ip=None, dst_domain=None,
               dst_port=80, timeout=TIMEOUT):
    """Открывает соединение через SOCKS4/5 с НАСТОЯЩИМИ байтами протокола
    (в старой сборке байты были записаны как текст из-за лишнего экранирования).
    Возвращает сокет при успехе, None при любой ошибке."""
    s = None
    try:
        s = socket.create_connection((proxy_ip, int(proxy_port)), timeout)
        s.settimeout(timeout)
        if int(version) == 5:
            s.sendall(b"\x05\x01\x00")
            if recv_exact(s, 2) != b"\x05\x00":
                raise OSError("SOCKS5: метод без авторизации не принят")
            if dst_ip:
                addr = b"\x01" + socket.inet_aton(dst_ip)
            else:
                domain = (dst_domain or "").encode("idna")
                if not domain or len(domain) > 255:
                    raise ValueError("Некорректное доменное имя")
                addr = b"\x03" + bytes([len(domain)]) + domain
            s.sendall(b"\x05\x01\x00" + addr + int(dst_port).to_bytes(2, "big"))
            if not read_socks5_reply(s):
                raise OSError("SOCKS5: CONNECT отклонён")
        else:
            if dst_domain and not dst_ip:
                dst_ip = socket.gethostbyname(dst_domain)
            s.sendall(b"\x04\x01" + int(dst_port).to_bytes(2, "big")
                      + socket.inet_aton(dst_ip) + b"\x00")
            rep = recv_exact(s, 8)
            if rep is None or len(rep) < 2 or rep[0] != 0 or rep[1] != 0x5A:
                raise OSError("SOCKS4: CONNECT отклонён")
        return s
    except Exception:
        try:
            if s:
                s.close()
        except Exception:
            pass
        return None


# ------------------------------------------------- качество и утечки

def countries_match(a, b):
    """Сверка заявленной и фактической страны: «Russia» и
    «Russian Federation» считаются одной страной."""
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    if not a or not b:
        return True          # нет данных — утечкой не считаем
    if is_russia(a) and is_russia(b):
        return True
    return a == b or a.split()[0] == b.split()[0]


def http_via(s):
    """Один HTTP GET через уже открытый SOCKS-сокет (проверка качества)."""
    try:
        s.sendall(b"GET /json?fields=status,country,query HTTP/1.1\r\n"
                  b"Host: ip-api.com\r\nConnection: close\r\n\r\n")
        s.settimeout(TIMEOUT)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 200_000:
                break
        body = buf.decode("utf-8", "replace")
        m = re.search(r"\{[^{}]*\}", body)
        return json.loads(m.group(0)) if m else None
    except Exception:
        return None


def quick_check(ip, port, version, timeout=3.0):
    """Быстрая проверка живости: хендшейк + CONNECT. Возвращает мс или None."""
    t0 = time.time()
    s = socks_open(ip, port, version, dst_ip=IPAPI_IP, dst_port=80, timeout=timeout)
    if s is None:
        return None
    try:
        s.close()
    except Exception:
        pass
    return (time.time() - t0) * 1000.0


def check_socks(ip, port, version, timeout=3.0):
    """Жив ли прокси: реальный SOCKS-хендшейк. Возвращает мс или None."""
    return quick_check(ip, port, version, timeout=timeout)


def check_quality(p, rounds=ROUNDS):
    """Трёхраундовая проверка качества: реальный SOCKS-хендшейк плюс HTTP-запрос
    через прокси на ip-api. Считает процент успешных соединений, среднее время
    отклика, флаг «неустойчивый», фактический IP/страну и утечку (расхождение
    фактической страны с заявленной). Обновляет запись на месте и возвращает её."""
    ok, lats, info = 0, [], {}
    for _ in range(rounds):
        t0 = time.time()
        s = socks_open(p["ip"], p["port"], p["version"], dst_ip=IPAPI_IP, dst_port=80)
        if s is None:
            continue
        lats.append((time.time() - t0) * 1000.0)
        data = http_via(s)
        try:
            s.close()
        except Exception:
            pass
        if data:
            ok += 1
            info = data
    p["alive"] = ok > 0
    p["success"] = round(100.0 * ok / rounds)
    p["avg_ms"] = int(sum(lats) / len(lats)) if lats else 99999
    p["flaky"] = 1 if 0 < ok < rounds else 0
    if info.get("status") == "success":
        p["actual_ip"] = info.get("query", "?")
        p["actual_country"] = info.get("country", "?")
        p["leak"] = not countries_match(p.get("country"), info.get("country"))
    else:
        p["actual_ip"] = p.get("actual_ip", "?")
        p["actual_country"] = p.get("actual_country", "?")
        p["leak"] = p.get("leak", False)
    p["checked_at"] = time.time()
    p["score"] = score_of(p)
    return p


def score_of(p):
    """Рейтинг: база 100, минус штрафы за задержку, неуспешные раунды,
    неустойчивость и утечку. Мёртвым — ноль."""
    if not p.get("alive"):
        return 0
    s = 100.0
    s -= min(40.0, p.get("avg_ms", 99999) / 50.0)
    s -= (100 - p.get("success", 0)) * 0.5
    if p.get("flaky"):
        s -= 10
    if p.get("leak"):
        s -= 15
    return max(0, int(round(s)))

# ---------------------------------------------------------------- кэш (шифрованный)

CACHE_KEY = b"ProxyGUI-cache-v1-2024"
CACHE_MAGIC = b"PXYC1\n"


def _cache_encrypt(plain):
    """XOR по фиксированному ключу + base64. Это обфускация: защищает от
    случайного взгляда в файл, но не от целенаправленного взлома."""
    x = bytes(b ^ CACHE_KEY[i % len(CACHE_KEY)] for i, b in enumerate(plain))
    return base64.b64encode(CACHE_MAGIC + x).decode("ascii")


def _cache_decrypt(text):
    """Возвращает расшифрованные байты или None (не наш формат / мусор)."""
    try:
        raw = base64.b64decode(text.strip())
    except Exception:
        return None
    if not raw.startswith(CACHE_MAGIC):
        return None
    x = raw[len(CACHE_MAGIC):]
    return bytes(b ^ CACHE_KEY[i % len(CACHE_KEY)] for i, b in enumerate(x))


def load_cache():
    """Возвращает (список прокси, режим). Старый открытый кэш читается как раньше
    и шифруется при первом же сохранении; битый файл даёт пустой кэш."""
    if not os.path.exists(CACHE_PATH):
        return [], MODE_RU
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception:
        return [], MODE_RU
    data = None
    plain = _cache_decrypt(text)
    if plain is not None:
        try:
            data = json.loads(plain.decode("utf-8"))
        except Exception:
            data = None
    if data is None:
        try:
            data = json.loads(text)
        except Exception:
            return [], MODE_RU
    mode = data.get("mode") if data.get("mode") in MODES else MODE_RU
    return data.get("proxies", []), mode


def save_cache(proxies, mode):
    """Атомарно сохраняет кэш; при ошибке старый файл остаётся нетронутым."""
    data = {"proxies": proxies, "mode": mode if mode in MODES else MODE_RU}
    plain = json.dumps(data, ensure_ascii=False).encode("utf-8")
    tmp = CACHE_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(_cache_encrypt(plain))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CACHE_PATH)
    except OSError as exc:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        print(f"[cache] не удалось сохранить кэш: {exc}")


def country_ok(entry, mode):
    """Подходит ли запись под текущий режим (пустая страна = не проверена, не бракуем)."""
    cc = (entry.get("country") or "").upper()
    if mode == MODE_RU:
        return cc in ("", "RU")
    return cc != "RU"

# ---------------------------------------------------------------- мост SOCKS4 -> SOCKS5

class SocksBridge:
    """Локальный сервер SOCKS4/4a, пересылающий соединения во внешний SOCKS5."""

    def __init__(self, port, log, on_switch=None):
        self.port = port
        self.bound_port = port
        self.log = log
        self.on_switch = on_switch
        self.upstream = None
        self.mode = MODE_RU
        self.up_lock = threading.Lock()
        self.stop_event = threading.Event()
        self._sock = None
        self._accept_thread = None
        self._watch_thread = None

    # --- запуск / остановка

    def start(self, upstream, mode):
        # чистый перезапуск: гасим старый цикл, сбрасываем стоп-событие
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self.stop_event.clear()
        self.upstream = upstream
        self.mode = mode
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("127.0.0.1", self.port))
            self._sock.listen(32)
        except OSError as e:
            self._sock = None
            self.log(f"[мост] не удалось занять порт {self.port}: {e} — "
                     f"возможно, работает ещё один экземпляр программы.")
            return False
        self._sock.settimeout(1.0)
        self.bound_port = self._sock.getsockname()[1]
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        self._watch_thread = threading.Thread(target=self._watch_loop, args=(mode,), daemon=True)
        self._watch_thread.start()
        return True

    def stop(self):
        self.stop_event.set()
        with self.up_lock:
            self.upstream = None
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
        # accept-поток может ещё висеть в заблокированном accept() —
        # пока он не выйдет, порт не освободится; даём ему до 2 секунд
        for t in (self._accept_thread, self._watch_thread):
            if t and t is not threading.current_thread():
                t.join(timeout=2.0)
        self._accept_thread = None
        self._watch_thread = None

    def set_upstream(self, p):
        with self.up_lock:
            self.upstream = p
        self.log(f"[мост] апстрим: socks5 {p['ip']}:{p['port']}"
                 + (f" (выход: {p.get('country') or '?'})" if p.get("country") else ""))

    # --- выбор живого апстрима из кэша

    def select_upstream(self, mode, exclude=None):
        # 1) из хранилища в памяти — по рейтингу (score), живые и без утечек
        for p in STORE.best(mode, exclude=exclude, version=5):
            ms = check_socks(p["ip"], p["port"], 5)
            if ms is not None:
                p["ping"] = ms
                return p
        # 2) из шифрованного кэша, по задержке соединения
        best = None
        for p in load_cache()[0]:
            if p.get("version") != 5:
                continue
            if not country_ok(p, mode):
                continue
            if exclude and p["ip"] == exclude["ip"] and p["port"] == exclude["port"]:
                continue
            ms = check_socks(p["ip"], p["port"], 5)
            if ms is not None and (best is None or ms < best.get("ping", 10 ** 9)):
                p["ping"] = ms
                best = p
        return best

    # --- служебные циклы

    def _accept_loop(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _watch_loop(self, mode):
        while not self.stop_event.wait(WATCH_INTERVAL):
            with self.up_lock:
                up = self.upstream
            if up is None:
                continue
            if check_socks(up["ip"], up["port"], 5) is None:
                self.log(f"[мост] апстрим {up['ip']}:{up['port']} умер, ищу замену…")
                nxt = self.select_upstream(mode, exclude=up)
                if nxt:
                    self.set_upstream(nxt)
                    if self.on_switch:
                        self.on_switch(nxt)
                else:
                    self.log("[мост] живых SOCKS5 в кэше нет — нажмите «Обновить и включить».")

    # --- обработка клиента (SOCKS4/4a)

    @staticmethod
    def _recv_exact(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _handle_client(self, conn):
        upstream_sock = None
        try:
            conn.settimeout(TIMEOUT)
            hdr = self._recv_exact(conn, 8)
            if hdr is None or hdr[0] != 4:
                return
            port_req = int.from_bytes(hdr[2:4], "big")
            dst_ip = hdr[4:8]
            # userid до NUL
            guard = 0
            while True:
                b = conn.recv(1)
                guard += 1
                if not b or guard > 256:
                    return
                if b == b"\x00":
                    break
            domain = None
            if dst_ip[:3] == b"\x00\x00\x00" and dst_ip[3] != 0:  # SOCKS4a: домен идёт следом
                buf = b""
                while True:
                    b = conn.recv(1)
                    if not b:
                        return
                    if b == b"\x00":
                        break
                    buf += b
                    if len(buf) > 256:
                        return
                domain = buf.decode("utf-8", "replace")
            target = domain if domain else socket.inet_ntoa(dst_ip)

            for attempt in (1, 2):
                with self.up_lock:
                    up = self.upstream
                if up is None:
                    break
                try:
                    upstream_sock = socket.create_connection((up["ip"], up["port"]), TIMEOUT)
                    upstream_sock.settimeout(TIMEOUT)
                    upstream_sock.sendall(b"\x05\x01\x00")
                    if upstream_sock.recv(2) != b"\x05\x00":
                        raise OSError("upstream отказал в SOCKS5")
                    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", target):
                        addr = b"\x01" + socket.inet_aton(target)
                    else:
                        d = target.encode()
                        addr = b"\x03" + bytes([len(d)]) + d
                    upstream_sock.sendall(b"\x05\x01\x00" + addr + port_req.to_bytes(2, "big"))
                    reply = upstream_sock.recv(10)
                    if len(reply) < 2 or reply[1] != 0:
                        raise OSError("upstream отказал в CONNECT")
                    conn.settimeout(None)
                    conn.sendall(b"\x00\x5a" + port_req.to_bytes(2, "big") + b"\x00\x00\x00\x00")
                    self._relay(conn, upstream_sock)
                    return
                except OSError:
                    if upstream_sock:
                        try:
                            upstream_sock.close()
                        except OSError:
                            pass
                        upstream_sock = None
                    # апстрим умер в момент запроса — берём следующий и повторяем
                    nxt = self.select_upstream(self.mode, exclude=up)
                    if not nxt:
                        break
                    self.set_upstream(nxt)
                    if self.on_switch:
                        self.on_switch(nxt)
            # не получилось — отказ клиенту
            conn.sendall(b"\x00\x5b" + b"\x00" * 6)
        except OSError:
            pass
        finally:
            for s in (conn, upstream_sock):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    @staticmethod
    def _pipe(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def _relay(self, a, b):
        t1 = threading.Thread(target=self._pipe, args=(a, b), daemon=True)
        t2 = threading.Thread(target=self._pipe, args=(b, a), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()


# ------------------------------------------------- хранилище и мониторы

class Store:
    """Хранилище прокси в памяти с рейтингом: источник истины для таблицы,
    фильтров и выбора апстрима мостом."""

    def __init__(self):
        self.lock = threading.Lock()
        self.items = {}          # (ip, port) -> запись

    def update_many(self, proxies):
        with self.lock:
            for p in proxies:
                key = (p["ip"], p["port"])
                old = self.items.get(key, {})
                merged = dict(old)
                merged.update(p)
                self.items[key] = merged

    def all(self):
        with self.lock:
            return list(self.items.values())

    def counts(self):
        with self.lock:
            total = len(self.items)
            alive = sum(1 for p in self.items.values() if p.get("alive"))
            leaks = sum(1 for p in self.items.values() if p.get("leak"))
        return total, alive, leaks

    def best(self, mode, exclude=None, version=None, limit=None):
        """Кандидаты по убыванию рейтинга: живые, соответствующие режиму;
        при режиме «Все, кроме России» утечки-маскировки отсеиваются."""
        rows = self.all()
        out = []
        for p in rows:
            if version is not None and p.get("version") != version:
                continue
            if not country_ok(p, mode):
                continue
            if mode == MODE_NOT_RU and p.get("leak"):
                continue
            if exclude and p["ip"] == exclude["ip"] and p["port"] == exclude["port"]:
                continue
            if not p.get("alive"):
                continue
            out.append(p)
        out.sort(key=lambda p: (-p.get("score", 0), p.get("avg_ms", 99999)))
        return out[:limit] if limit else out


STORE = Store()


def monitor_loop(q, store, bridge):
    """Мониторинг активного прокси: периодический ping активного апстрима
    и статус в карточке. Переключение при обрыве делает мост (select_upstream)."""
    while True:
        time.sleep(MONITOR_INTERVAL)
        with bridge.up_lock:
            up = bridge.upstream
        if up is None:
            q.put(("status", ("нет активного прокси", "idle")))
            continue
        ms = quick_check(up["ip"], up["port"], 5, timeout=4.0)
        if ms is None:
            q.put(("status", (f"{up['ip']}:{up['port']}", "down")))
        else:
            q.put(("status", (f"{up['ip']}:{up['port']}", "up", int(ms))))




# ---------------------------------------------------------------- GUI (Kivy — Android)

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.uix.togglebutton import ToggleButton

ANDROID = bool(os.environ.get("ANDROID_ARGUMENT") or os.environ.get("ANDROID_DATA"))
BRIDGE_HINT = ("Прокси поднят на 127.0.0.1:%d. Как включить на Android:\n"
               "1) Настройки → Wi-Fi → ваша сеть → «Прокси» → «Вручную»\n"
               "2) Имя хоста: 127.0.0.1, порт: %d\n"
               "3) Для мобильного интернета системный прокси недоступен — "
               "используйте браузер с настройкой прокси (127.0.0.1:%d)." %
               (BRIDGE_PORT, BRIDGE_PORT, BRIDGE_PORT))


def status_color(score):
    """Цвет строки таблицы по рейтингу."""
    if score >= 75:
        return (0.35, 0.75, 0.4, 0.35)
    if score >= 40:
        return (0.95, 0.8, 0.35, 0.35)
    return (0.5, 0.5, 0.5, 0.25)


class ProxyApp(App):
    title = "ProxyGUI"

    def build(self):
        Window.softinput_mode = "below_target"
        self.q = queue.Queue()
        self._busy = False
        self.mode_name = MODES[0]
        self.manual = False
        self.rows = {}
        self.bridge = SocksBridge(BRIDGE_PORT, self.log, on_switch=self.on_bridge_switch)
        threading.Thread(target=monitor_loop, args=(self.q, STORE, self.bridge),
                         daemon=True).start()

        root = BoxLayout(orientation="vertical", padding=dp(6), spacing=dp(6))

        # --- карточка состояния
        self.lbl_active = Label(text="● нет активного прокси", halign="left",
                                size_hint_y=None, height=dp(26),
                                font_size=dp(14), bold=True, color=(0.9, 0.9, 0.9, 1))
        self.lbl_extra = Label(text="", halign="left",
                               size_hint_y=None, height=dp(22), font_size=dp(12),
                               color=(0.7, 0.7, 0.7, 1))
        self.lbl_counts = Label(text="всего: 0 · живых: 0 · утечек: 0", halign="left",
                                size_hint_y=None, height=dp(22), font_size=dp(12),
                                color=(0.7, 0.7, 0.7, 1))
        for w in (self.lbl_active, self.lbl_extra, self.lbl_counts):
            w.bind(size=lambda i, s: setattr(i, "text_size", (s[0], None)))
            root.add_widget(w)

        # --- режим и панель управления
        self.sp_mode = Spinner(text=self.mode_name, values=list(MODES),
                               size_hint_y=None, height=dp(40), sync_height=True)
        self.sp_mode.bind(text=self.on_mode)
        root.add_widget(self.sp_mode)

        bar = BoxLayout(size_hint_y=None, height=dp(42), spacing=dp(6))
        bar.add_widget(self._btn("Обновить и включить", lambda *_: self.refresh(True)))
        bar.add_widget(self._btn("Обновить", lambda *_: self.refresh(False)))
        bar.add_widget(self._btn("Выключить", lambda *_: self.disable()))
        root.add_widget(bar)

        # --- фильтры
        flt = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(6))
        self.in_search = TextInput(multiline=False, hint_text="поиск (IP/страна)",
                                   size_hint_x=0.45, font_size=dp(12), write_tab=False)
        self.in_search.bind(text=lambda *_: self.apply_filters())
        flt.add_widget(self.in_search)
        self.sp_country = Spinner(text="все страны", values=["все страны"],
                                  size_hint_x=0.35, sync_height=True)
        self.sp_country.bind(text=lambda *_: self.apply_filters())
        flt.add_widget(self.sp_country)
        self.tg_live = self._tg("живые", True)
        self.tg_noleak = self._tg("без утечек", False)
        self.tg_s5 = self._tg("SOCKS5", False)
        for tg in (self.tg_live, self.tg_noleak, self.tg_s5):
            tg.bind(state=lambda *_: self.apply_filters())
            flt.add_widget(tg)
        root.add_widget(flt)

        # --- таблица прокси
        self.grid = GridLayout(cols=1, size_hint_y=None, spacing=dp(2), padding=dp(2))
        self.grid.bind(minimum_height=self.grid.setter("height"))
        sc = ScrollView(bar_width=dp(6), scroll_type=["bars", "content"])
        sc.add_widget(self.grid)
        root.add_widget(sc)

        # --- журнал
        self.logbox = TextInput(readonly=True, font_size=dp(11),
                                size_hint_y=None, height=dp(120),
                                background_color=(0.06, 0.06, 0.08, 1),
                                foreground_color=(0.85, 0.9, 0.85, 1))
        root.add_widget(self.logbox)

        Clock.schedule_interval(self._poll, 0.2)
        Clock.schedule_once(self._auto, REFRESH_MINUTES * 60.0)
        return root

    # ---------- вспомогательные виджеты

    def _btn(self, text, cb):
        b = Button(text=text, font_size=dp(12), bold=True, size_hint=(1, None),
                   height=dp(42))
        b.bind(on_release=cb)
        return b

    @staticmethod
    def _tg(text, down):
        b = ToggleButton(text=text, font_size=dp(10), size_hint_y=None, height=dp(40))
        b.state = "down" if down else "normal"
        return b

    # ---------- журнал и очередь событий

    def log(self, msg):
        print(msg)
        self.q.put(("log", str(msg)))

    def _poll(self, *_):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.logbox.text += payload + "\n"
                    self.logbox.scroll_y = 0.0
                elif kind == "row":
                    self.upsert_row(payload)
                elif kind == "status":
                    self._card(*payload)
                elif kind == "card":
                    self._card(*payload)
                elif kind == "counts":
                    self.lbl_counts.text = payload
                elif kind == "filters":
                    self.sp_country.values = payload
                elif kind == "refilter":
                    self.apply_filters()
        except queue.Empty:
            pass
        except Exception as e:
            print("[ui] " + traceback.format_exc(limit=2))
            self.q.put(("log", f"[ui] ошибка отображения: {type(e).__name__}: {e}"))  

    def _card(self, active, state, ms=None):
        color = {"up": (0.3, 0.85, 0.4, 1), "down": (0.9, 0.3, 0.3, 1),
                 "idle": (0.7, 0.7, 0.7, 1)}[state]
        self.lbl_active.color = color
        tail = f" · {ms} мс" if ms is not None else ""
        self.lbl_active.text = f"Активный: {active}{tail}"
        self.lbl_extra.text = (f"режим: {self.mode_name}"
                               + (" · выбран вручную" if self.manual else ""))

    # ---------- таблица и фильтры

    def upsert_row(self, p):
        key = (p["ip"], p["port"])
        btn = self.rows.get(key)
        if btn and btn.parent is self.grid:
            btn.text = self.row_text(p)
            btn.background_color = status_color(p.get("score", 0))

    @staticmethod
    def row_text(p):
        return ("%s:%s  v%s  %s  %s  %s%%  ★%s  %s" % (
            p["ip"], p["port"], p.get("version", 5), (p.get("country") or "?")[:14],
            (str(p.get("delay", "?")) + "мс") if p.get("delay") else "?",
            p.get("success", 0), p.get("score", 0),
            "утечка" if p.get("leak") else "ok"))

    @staticmethod
    def status_text(p):
        if not p.get("alive"):
            return "мёртв"
        bits = ["жив"]
        if p.get("actual_country"):
            bits.append(p["actual_country"])
        if p.get("avg_ms") and p["avg_ms"] < 99000:
            bits.append(f"{p['avg_ms']} мс")
        if p.get("leak"):
            bits.append("утечка: фактическая страна не та")
        if p.get("flaky"):
            bits.append("неустойчивый")
        return " · ".join(bits)

    def apply_filters(self):
        self.grid.clear_widgets()
        self.rows.clear()
        q = self.in_search.text.strip().lower()
        ctry = self.sp_country.text
        rows = STORE.all()
        rows.sort(key=lambda p: (-p.get("score", 0), p.get("avg_ms", 99999)))
        for p in rows:
            if self.tg_live.state == "down" and not p.get("alive"):
                continue
            if self.tg_s5.state == "down" and p.get("version") != 5:
                continue
            if self.tg_noleak.state == "down" and p.get("leak"):
                continue
            if ctry != "все страны" and (p.get("country") or "") != ctry:
                continue
            if q and q not in (p["ip"] + " " + (p.get("country") or "")).lower():
                continue
            b = Button(text=self.row_text(p), font_size=dp(12), halign="left",
                       valign="middle", size_hint_y=None, height=dp(38),
                       background_color=status_color(p.get("score", 0)),
                       on_release=(lambda pp: self.activate_selected(pp))(p))
            b.bind(width=lambda i, w: setattr(i, "text_size", (w - dp(12), None)))
            self.rows[(p["ip"], p["port"])] = b
            self.grid.add_widget(b)

    # ---------- обновление и проверка

    def on_mode(self, spinner, text):
        if text in MODES and text != self.mode_name:
            self.mode_name = text
            self.log(f"[режим] {text}")

    def refresh(self, enable):
        if self._busy:
            self.log("[обновление] уже идёт — дождитесь завершения")
            return
        self._busy = True
        threading.Thread(target=self._worker_run, args=(enable,), daemon=True).start()

    def _worker_run(self, enable):
        try:
            self._worker(enable)
        finally:
            self._busy = False
          
    def _worker(self, enable):
        try:
            proxies, source, reason = get_proxies(self.mode_name, self.log)
            if not proxies:
                if reason:
                    self.log(f"[поиск] не удалось: {reason}")
                return
            self.log(f"[поиск] {source}: найдено {len(proxies)}")
            save_cache(proxies, self.mode_name)
            STORE.update_many(proxies)
            self.q.put(("counts", "всего: %d · живых: ? · утечек: ?" % len(proxies)))
            with concurrent.futures.ThreadPoolExecutor(TEST_WORKERS) as ex:
                futs = [ex.submit(check_quality, p) for p in proxies[:TEST_LIMIT]]
            total = len(futs)
            checked = []
            for f in concurrent.futures.as_completed(futs):
                checked.append(f.result())
                done = len(checked)
                if done % 10 == 0 or done == total:
                    alive = sum(1 for c in checked if c.get("alive"))
                    self.log(f"[проверка] {done}/{total}, живых: {alive}…")
                if done % 25 == 0 or done == total:
                    STORE.update_many(checked)
                    checked = []
                    alive = sum(1 for c in STORE.all() if c.get("alive"))
                    self.q.put(("counts", f"всего: {len(proxies)} · живых: {alive} · утечек: ?"))
                    self.q.put(("refilter", None))
            self.q.put(("counts", self._counts_text()))
            countries = sorted({p.get("country", "") for p in STORE.all() if p.get("country")})
            self.q.put(("filters", ["все страны"] + countries))
            self.q.put(("refilter", None))
            if enable:
                best = STORE.best(self.mode_name, version=5)
                target = best[0] if best else None
                if target:
                    self.activate(target)
                else:
                    self.log("[включение] живых SOCKS5 не нашлось — попробуйте позже.")
        except Exception:
            self.log("[ошибка воркера] " + traceback.format_exc(limit=1).splitlines()[-1])
          
    def _counts_text(self):
        total, alive, leaks = STORE.counts()
        return f"всего: {total} · живых: {alive} · утечек: {leaks}"

    # ---------- включение и переключение

    def activate(self, p, manual=False):
        if manual:
            self.log(f"[включение] перепроверяю {p['ip']}:{p['port']}…")
            ms = quick_check(p["ip"], p["port"], p["version"])
            if ms is None:
                self.log(f"[включение] {p['ip']}:{p['port']} не отвечает — включение отменено.")
                return
        self.manual = manual
        if not self.bridge.start(p, self.mode_name):
            return
        STORE.update_many([dict(p, alive=True)])
        self.log(f"[включение] активен {p['ip']}:{p['port']} "
                 f"({p.get('country') or '?'}, рейтинг {p.get('score', 0)})")
        if ANDROID:
            self.log(BRIDGE_HINT)
        self.q.put(("card", (f"{p['ip']}:{p['port']}", "up")))
        self.q.put(("refilter", None))

    def activate_selected(self, p):
        self.activate(p, manual=True)

    def disable(self):
        self.bridge.stop()
        self.manual = False
        self.log("[выключение] мост остановлен" +
                 (". Снимите прокси в настройках Wi-Fi." if ANDROID else "."))
        self._card("нет активного прокси", "idle")

    def on_bridge_switch(self, p):
        self.manual = False
        self.log(f"[мост] переключился на {p['ip']}:{p['port']}")
        self.q.put(("card", (f"{p['ip']}:{p['port']}", "up")))

    def _auto(self, *_):
        if not self.manual:
            self.log("[авто] плановое обновление списка…")
            self.refresh(False)
        Clock.schedule_once(self._auto, REFRESH_MINUTES * 60.0)

    def on_stop(self):
        self.bridge.stop()


def main():
    os.environ.setdefault("KIVY_NO_ARGS", "1")
    ProxyApp().run()


if __name__ == "__main__":
    main()
