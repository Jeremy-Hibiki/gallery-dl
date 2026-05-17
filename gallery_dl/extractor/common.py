# -*- coding: utf-8 -*-

# Copyright 2014-2026 Mike Fährmann
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

"""Common classes and constants used by extractor modules."""

import os
import re
import ssl
import time
import netrc
import queue
import pickle
import random
import getpass
import logging
import httpx
import threading
import urllib.parse
from xml.etree import ElementTree
from curl_cffi import Session as CurlSession
from curl_cffi.requests import RequestsError as CurlRequestsError
from .message import Message
from .. import config, output, text, util, dt, cache, exception


class ResponseWrapper():
    """Normalizes httpx.Response and curl_cffi.Response APIs."""

    __slots__ = ("_resp", "_stream_ctx", "_iter")

    def __init__(self, response, stream_ctx=None):
        self._resp = response
        self._stream_ctx = stream_ctx
        self._iter = None

    @property
    def status_code(self):
        return self._resp.status_code

    @property
    def reason(self):
        r = self._resp
        # httpx uses reason_phrase, curl_cffi uses reason
        return getattr(r, "reason_phrase", None) or getattr(r, "reason", "") or ""

    @property
    def text(self):
        return self._resp.text

    @property
    def content(self):
        return self._resp.content

    @property
    def url(self):
        return str(self._resp.url)

    @property
    def headers(self):
        return self._resp.headers

    @property
    def encoding(self):
        return self._resp.encoding

    @encoding.setter
    def encoding(self, value):
        self._resp.encoding = value

    @property
    def history(self):
        return [ResponseWrapper(r) for r in self._resp.history]

    def json(self):
        return self._resp.json()

    def iter_content(self, chunk_size=1):
        if self._iter is not None:
            return self._iter
        resp = self._resp
        if hasattr(resp, "iter_content"):
            gen = resp.iter_content(chunk_size)
        else:
            gen = resp.iter_bytes(chunk_size)
        self._iter = gen
        return gen

    @property
    def raw(self):
        return _RawProxy(self._resp)

    def close(self):
        self._resp.close()
        if self._stream_ctx is not None:
            try:
                self._stream_ctx.__exit__(None, None, None)
            except Exception:
                pass
            self._stream_ctx = None

    def __getattr__(self, name):
        return getattr(self._resp, name)


class _CookiesProxy():
    """Proxy that provides a requests-compatible cookies interface.

    Both httpx.Cookies and curl_cffi Cookies iterate over cookie names
    (str) instead of Cookie objects. This proxy iterates over the
    underlying CookieJar to yield real Cookie objects.
    """

    __slots__ = ("_cookies",)

    def __init__(self, cookies):
        self._cookies = cookies

    def set(self, name, value, domain="", **kwargs):
        if "expires" in kwargs or "path" in kwargs:
            # Create a real Cookie object for advanced params
            import http.cookiejar
            expires = kwargs.get("expires")
            path = kwargs.get("path", "/")
            cookie = http.cookiejar.Cookie(
                version=0, name=name, value=value,
                port=None, port_specified=False,
                domain=domain, domain_specified=bool(domain),
                domain_initial_dot=domain.startswith("."),
                path=path, path_specified=True,
                secure=kwargs.get("secure", False),
                expires=expires,
                discard=expires is None,
                comment=None, comment_url=None, rest={}, rfc2109=False,
            )
            self._cookies.jar.set_cookie(cookie)
        else:
            self._cookies.set(name, value, domain=domain)

    def set_cookie(self, cookie):
        self._cookies.jar.set_cookie(cookie)

    @property
    def jar(self):
        return self._cookies.jar

    def __iter__(self):
        return iter(self._cookies.jar)

    def __len__(self):
        return len(self._cookies)

    def __contains__(self, key):
        return key in self._cookies

    def __bool__(self):
        return bool(self._cookies)

    def keys(self):
        return self._cookies.keys()

    def values(self):
        return self._cookies.values()

    def items(self):
        return self._cookies.items()

    def get(self, name, default=None, domain=None):
        return self._cookies.get(name, default, domain=domain)

    def clear(self):
        self._cookies.clear()

    def __repr__(self):
        return repr(self._cookies)


# Patch httpx.Headers to ignore None values and accept bytes (requests compat)
_orig_headers_setitem = httpx.Headers.__setitem__


def _patched_setitem(self, key, value):
    if value is not None:
        if isinstance(value, bytes):
            value = value.decode("latin1")
        _orig_headers_setitem(self, key, value)


httpx.Headers.__setitem__ = _patched_setitem


class _RawProxy():
    """Proxy for response.raw compatibility (chunked detection)."""
    __slots__ = ("_resp",)

    def __init__(self, resp):
        self._resp = resp

    @property
    def chunked(self):
        te = self._resp.headers.get("transfer-encoding", "")
        return "chunked" in te.lower()


def _format_connection_error(exc):
    try:
        if isinstance(exc, CurlRequestsError):
            return str(exc)
        reason = exc.args[0].reason
        cls = reason.__class__.__name__
        pre, _, err = str(reason.args[-1]).partition(":")
        return f" {cls}: {(err or pre).lstrip()}"
    except Exception:
        return str(exc)


class Extractor():

    category = ""
    subcategory = ""
    basecategory = ""
    basesubcategory = ""
    categorytransfer = False
    parent = False
    directory_fmt = ("{category}",)
    filename_fmt = "{filename}.{extension}"
    archive_fmt = ""
    status = 0
    root = ""
    cookies_file = ""
    cookies_index = 0
    cookies_domain = ""
    session = None
    referer = True
    ciphers = None
    tls12 = True
    browser = None
    useragent = util.USERAGENT_FIREFOX
    geobypass = None
    request_interval = 0.0
    request_interval_min = 0.0
    request_interval_429 = 60.0
    request_timestamp = 0.0
    exc = exception
    finalize = skip_files = skip_posts = skip_children = skip_date = \
        import_blacklist = None

    def __init__(self, match):
        self.log = logging.getLogger(self.category)
        self.url = match.string
        self.match = match
        self.groups = match.groups()
        self.kwdict = {}

        if self.category in CATEGORY_MAP:
            catsub = f"{self.category}:{self.subcategory}"
            if catsub in CATEGORY_MAP:
                self.category, self.subcategory = CATEGORY_MAP[catsub]
            else:
                self.category = CATEGORY_MAP[self.category]

        self.parse_datetime = dt.parse
        self.parse_datetime_iso = dt.parse_iso
        self.parse_timestamp = dt.parse_ts

        self._cfgpath = ("extractor", self.category, self.subcategory)
        self._parentdir = ""

    def __str__(self):
        return f"{self.__class__.__name__} <{self.url}>"

    @classmethod
    def from_url(cls, url):
        if isinstance(cls.pattern, str):
            cls.pattern = util.re_compile(cls.pattern)
        match = cls.pattern.match(url)
        return cls(match) if match else None

    def __iter__(self):
        self.initialize()
        return self.items()

    def initialize(self):
        self._init_options()

        if self.session is None:
            self._init_session()
            self.cookies = _CookiesProxy(self.session.cookies)
            if self.cookies_domain is not None:
                self._init_cookies()
        else:
            self.cookies = _CookiesProxy(self.session.cookies)

        self._init()
        self.initialize = util.noop

    def items(self):
        return
        yield

    def config(self, key, default=None):
        return config.interpolate(self._cfgpath, key, default)

    def config2(self, key, key2, default=None, sentinel=util.SENTINEL):
        value = self.config(key, sentinel)
        if value is not sentinel:
            return value
        return self.config(key2, default)

    def config_accumulate(self, key):
        return config.accumulate(self._cfgpath, key)

    def config_instance(self, key, default=None):
        return default

    def _config_shared(self, key, default=None):
        return config.interpolate_common(
            ("extractor",), self._cfgpath, key, default)

    def _config_shared_accumulate(self, key):
        first = True
        extr = ("extractor",)

        for path in self._cfgpath:
            if first:
                first = False
                values = config.accumulate(extr + path, key)
            elif conf := config.get(extr, path[0]):
                values[:0] = config.accumulate(
                    (self.subcategory,), key, conf=conf)

        return values

    def request(self, url, method="GET", session=None, fatal=True,
                retries=None, retry_codes=None, expected=(), interval=True,
                encoding=None, notfound=None, **kwargs):
        if session is None:
            session = self.session
        if retries is None:
            retries = self._retries
        if retry_codes is None:
            retry_codes = self._retry_codes
        if "proxies" not in kwargs:
            kwargs["proxies"] = self._proxies
        if "timeout" not in kwargs:
            kwargs["timeout"] = self._timeout
        if "verify" not in kwargs:
            kwargs["verify"] = self._verify

        if "json" in kwargs:
            if (json := kwargs["json"]) is not None:
                kwargs["data"] = util.json_dumps(json).encode()
                del kwargs["json"]
                if headers := kwargs.get("headers"):
                    headers["Content-Type"] = "application/json"
                else:
                    kwargs["headers"] = {"Content-Type": "application/json"}

        # Translate kwargs for httpx compatibility
        if isinstance(session, httpx.Client):
            if "allow_redirects" in kwargs:
                kwargs["follow_redirects"] = kwargs.pop("allow_redirects")
            # httpx handles verify/proxies at Client level, not per-request
            kwargs.pop("verify", None)
            kwargs.pop("proxies", None)
            # httpx replaces URL query params when params kwarg is provided,
            # but requests merges them. Merge into the URL manually.
            extra_params = kwargs.get("params")
            if extra_params and "?" in url:
                parsed = urllib.parse.urlparse(url)
                existing = urllib.parse.parse_qs(parsed.query)
                for k, v in (extra_params.items()
                             if isinstance(extra_params, dict)
                             else extra_params):
                    existing.setdefault(k, []).append(v)
                query = urllib.parse.urlencode(existing, doseq=True)
                url = urllib.parse.urlunparse(parsed._replace(query=query))
                del kwargs["params"]

        response = challenge = None
        tries = 1

        if self._interval_request is not None and interval:
            seconds = (self._interval_request() -
                       (time.time() - Extractor.request_timestamp))
            if seconds > 0.0:
                self.sleep(seconds, "request")

        while True:
            try:
                raw_response = session.request(method, url, **kwargs)
                response = ResponseWrapper(raw_response)
            except (httpx.ConnectError, CurlRequestsError) as exc:
                msg = _format_connection_error(exc)
                code = 0
            except (httpx.TimeoutException,) as exc:
                msg = exc
                code = 0
            except (httpx.StreamError, httpx.DecodingError) as exc:
                msg = exc
                code = 0
            except httpx.HTTPError as exc:
                msg = exc
                break
            else:
                code = response.status_code
                if self._write_pages:
                    self._dump_response(response)
                if (
                    code < 400 or
                    code in expected or
                    code < 500 and (
                        not fatal and code != 429 or fatal is None) or
                    fatal is ...
                ):
                    if encoding:
                        response.encoding = encoding
                    return response
                if notfound is not None and code == 404:
                    if notfound is True:
                        notfound = self.__class__.subcategory
                    self.status |= exception.NotFoundError.code
                    raise exception.NotFoundError(notfound)

                msg = f"'{code} {response.reason}' for '{response.url}'"

                challenge = util.detect_challenge(response)
                if challenge is not None:
                    self.log.warning(challenge)

                if code == 429 and self._handle_429(response):
                    continue
                elif code == 429 and self._interval_429:
                    pass
                elif code not in retry_codes and code < 500:
                    break

            finally:
                if interval:
                    Extractor.request_timestamp = time.time()

            self.log.debug("%s (%s/%s)", msg, tries, retries+1)
            if tries > retries:
                break

            seconds = self._interval_retry(tries)
            if self._interval_request is not None:
                s = self._interval_request()
                if seconds < s:
                    seconds = s
            if code == 429 and self._interval_429 is not None:
                s = self._interval_429(tries)
                if seconds < s:
                    seconds = s
                self.wait(seconds=seconds, reason="429 Too Many Requests")
            else:
                self.sleep(seconds, "retry")
            tries += 1

        if not fatal or fatal is ...:
            self.log.warning(msg)
            return util.NullResponse(url, msg)

        if challenge is None:
            exc = exception.HttpError(msg, response)
        else:
            exc = exception.ChallengeError(challenge, response)
        self.status |= exc.code
        raise exc

    def request_location(self, url, **kwargs):
        kwargs.setdefault("method", "HEAD")
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("interval", False)
        return self.request(url, **kwargs).headers.get("location", "")

    def request_json(self, url, **kwargs):
        response = self.request(url, **kwargs)

        try:
            return util.json_loads(response.text)
        except Exception as exc:
            fatal = kwargs.get("fatal", True)
            if not fatal or fatal is ...:
                if challenge := util.detect_challenge(response):
                    self.log.warning(challenge)
                else:
                    self.log.warning("%s: %s", exc.__class__.__name__, exc)
                return {}
            raise

    def request_xml(self, url, xmlns=True, **kwargs):
        response = self.request(url, **kwargs)

        if xmlns:
            text = response.text
        else:
            text = response.text.replace(" xmlns=", " ns=")

        parser = ElementTree.XMLParser()
        try:
            parser.feed(text)
            return parser.close()
        except Exception as exc:
            fatal = kwargs.get("fatal", True)
            if not fatal or fatal is ...:
                if challenge := util.detect_challenge(response):
                    self.log.warning(challenge)
                else:
                    self.log.warning("%s: %s", exc.__class__.__name__, exc)
                return ElementTree.Element("")
            raise

    _handle_429 = util.false

    def wait(self, seconds=None, until=None, adjust=1.0,
             reason="rate limit"):
        now = time.time()

        if seconds:
            seconds = float(seconds)
            until = now + seconds
        elif until:
            if isinstance(until, dt.datetime):
                # convert to UTC timestamp
                until = dt.to_ts(until)
            else:
                until = float(until)
            seconds = until - now
        else:
            raise ValueError("Either 'seconds' or 'until' is required")

        seconds += adjust
        if seconds <= 0.0:
            return

        if reason:
            if seconds >= 3600.0:
                h, m = divmod(seconds, 3600.0)
                dur = f"{int(h)}h {int(m/60.0)}min"
            elif seconds >= 60.0:
                dur = str(int(seconds/60.0)) + " minutes"
            else:
                dur = str(int(seconds)) + " seconds"
            t = time.localtime(until)
            iso = f"{t.tm_hour:02}:{t.tm_min:02}:{t.tm_sec:02}"
            self.log.info("Waiting for %s until %s (%s)", dur, iso, reason)
        time.sleep(seconds)

    def sleep(self, seconds, reason):
        self.log.debug("Sleeping %.2f seconds (%s)",
                       seconds, reason)
        time.sleep(seconds)

    def utils(self, module="", name=None):
        module = (self.__class__.category if not module else
                  module[1:] if module[0] == "/" else
                  f"{self.__class__.category}_{module}")
        if module in CACHE_UTILS:
            res = CACHE_UTILS[module]
        else:
            res = CACHE_UTILS[module] = __import__(
                "utils." + module, globals(), None, module, 1)
        return res if name is None else getattr(res, name, None)

    def cache(self, func, *args, _key=0, _exp=0, _mem=True):
        if _key is None:
            key = f"{func.__module__}.{func.__name__}"
        else:
            key = f"{func.__module__}.{func.__name__}-{args[_key]}"

        try:
            value, expires = CACHE_MEMORY[key]
        except KeyError:
            expires = 1

        if not expires or expires > (now := int(time.time())):
            return value

        if not _mem and (db := cache.database()):
            with db:
                cursor = db.cursor()
                try:
                    cursor.execute("BEGIN EXCLUSIVE")
                except Exception:
                    pass  # swallow exception when already in a transaction
                cursor.execute(
                    "SELECT value, expires FROM data WHERE key=? LIMIT 1",
                    (key,))

                if (result := cursor.fetchone()) and (
                        not (expires := result[1]) or expires > now):
                    value, expires = result
                    value = pickle.loads(value)
                else:
                    value = func(*args)
                    expires = _exp and _exp+now
                    cursor.execute(
                        "INSERT OR REPLACE INTO data VALUES (?,?,?)",
                        (key, pickle.dumps(value), expires))
        else:
            value = func(*args)
            expires = _exp and _exp+now

        CACHE_MEMORY[key] = value, expires
        return value

    def cache_update(self, func, key=..., value=None, _exp=0, _mem=False):
        if key is ...:
            key = f"{func.__module__}.{func.__name__}"
        else:
            key = f"{func.__module__}.{func.__name__}-{key}"

        if value is None:
            # delete cached value
            try:
                del CACHE_MEMORY[key]
            except KeyError:
                pass
            if not _mem and (db := cache.database()):
                with db:
                    db.execute("DELETE FROM data WHERE key=?", (key,))
        else:
            # replace cached value
            expires = _exp and _exp+int(time.time())
            CACHE_MEMORY[key] = value, expires
            if not _mem and (db := cache.database()):
                with db:
                    db.execute(
                        "INSERT OR REPLACE INTO data VALUES (?,?,?)",
                        (key, pickle.dumps(value), expires))

    def input(self, prompt, echo=True):
        self._check_input_allowed(prompt)

        if echo:
            try:
                return input(prompt)
            except (EOFError, OSError):
                return None
        else:
            return getpass.getpass(prompt)

    def _check_input_allowed(self, prompt=""):
        input = self.config("input")
        if input is None:
            input = output.TTY_STDIN
        if not input:
            raise exception.AbortExtraction(
                f"User input required ({prompt.strip(' :')})")

    def _get_auth_info(self, password=None):
        """Return authentication information as (username, password) tuple"""
        username = self.config("username")

        if username or password:
            password = self.config("password")
            if not password:
                self._check_input_allowed("password")
                password = util.LazyPrompt()

        elif self.config("netrc", False):
            try:
                info = netrc.netrc().authenticators(self.category)
                username, _, password = info
            except (OSError, netrc.NetrcParseError) as exc:
                self.log.error("netrc: %s", exc)
            except TypeError:
                self.log.warning("netrc: No authentication info")

        return username, password

    def _init(self):
        pass

    def _init_options(self):
        self._write_pages = self.config("write-pages", False)
        self._retry_codes = self.config("retry-codes")
        self._retries = self.config("retries", 4)
        self._timeout = self.config("timeout", 30)
        self._verify = self.config("verify", True)
        self._proxies = util.build_proxy_map(self.config("proxy"), self.log)

        if self._retries < 0:
            self._retries = float("inf")
        if not self._retry_codes:
            self._retry_codes = ()

        self._interval_request = util.build_duration_func(
            self.config("sleep-request", self.request_interval),
            self.request_interval_min)

        _interval_retry = self.config("sleep-retries")
        if _interval_retry is None:
            self._interval_retry = util.identity
        else:
            try:
                self._interval_retry = util.build_duration_func_ex(
                    _interval_retry)
            except Exception as exc:
                self.log.error("Invalid 'sleep-retry' value '%s' (%s: %s)",
                               _interval_retry, exc.__class__.__name__, exc)
                self._interval_retry = util.identity

        _interval_429 = self.config("sleep-429")
        if _interval_429 is None:
            _interval_429 = self.request_interval_429
        try:
            self._interval_429 = util.build_duration_func_ex(_interval_429)
        except Exception as exc:
            self.log.error("Invalid 'sleep-429' value '%s' (%s: %s)",
                           _interval_429, exc.__class__.__name__, exc)
            self._interval_429 = util.build_duration_func_ex(
                self.request_interval_429)

    def _init_session(self):
        browser = self.config("browser")
        if browser is None:
            browser = self.browser

        if browser and isinstance(browser, str):
            browser_lower, _, platform = browser.lower().partition(":")

            if browser_lower.startswith("firefox"):
                impersonate = "firefox"
            elif browser_lower.startswith("chrome"):
                impersonate = "chrome"
            else:
                impersonate = browser_lower

            self.session = session = CurlSession(
                impersonate=impersonate)  # type: ignore[arg-type]
            headers = session.headers

            if referer := self.config("referer", self.referer):
                if isinstance(referer, str):
                    headers["Referer"] = referer
                elif self.root:
                    headers["Referer"] = self.root + "/"

            custom_ua = self.config("user-agent")
            if not custom_ua or custom_ua == "auto":
                pass
            elif custom_ua == "browser":
                headers["User-Agent"] = self.cache(
                    _browser_useragent, None, _exp=86400, _mem=False)
            elif custom_ua[0] == "@":
                headers["User-Agent"] = self.cache(
                    _browser_useragent, custom_ua[1:], _exp=86400, _mem=False)
            elif custom_ua[0] == "+":
                custom_ua = custom_ua[1:].lower()
                if custom_ua in {"firefox", "ff"}:
                    headers["User-Agent"] = util.USERAGENT_FIREFOX
                elif custom_ua in {"chrome", "cr"}:
                    headers["User-Agent"] = util.USERAGENT_CHROME
                elif custom_ua in {"gallery-dl", "gallerydl", "gdl"}:
                    headers["User-Agent"] = util.USERAGENT_GALLERYDL
                elif custom_ua in {"google-bot", "googlebot", "bot"}:
                    headers["User-Agent"] = "Googlebot-Image/1.0"
                else:
                    self.log.warning(
                        "Unsupported User-Agent preset '%s'", custom_ua)
            elif self.useragent is Extractor.useragent and not self.browser or \
                    custom_ua is not config.get(("extractor",), "user-agent"):
                headers["User-Agent"] = custom_ua

            if custom_headers := self.config("headers"):
                if isinstance(custom_headers, str):
                    if custom_headers in HEADERS:
                        custom_headers = HEADERS[custom_headers]
                    else:
                        self.log.error("Invalid 'headers' value '%s'",
                                       custom_headers)
                        custom_headers = ()
                headers.update(custom_headers)

        else:
            client_kwargs = {
                "http2": True,
                "follow_redirects": True,
                "verify": self._verify,
                "trust_env": bool(self.config("proxy-env", True)),
            }
            if self._proxies:
                # httpx uses single proxy= at client level
                proxy = (self._proxies.get("https") or
                         self._proxies.get("http"))
                if proxy and "://" not in proxy:
                    proxy = "http://" + proxy
                if proxy:
                    client_kwargs["proxy"] = proxy
            self.session = session = httpx.Client(**client_kwargs)
            headers = session.headers
            headers.clear()

            headers["User-Agent"] = self.useragent
            headers["Accept"] = "*/*"
            headers["Accept-Language"] = "en-US,en;q=0.5"

            if BROTLI:
                headers["Accept-Encoding"] = "gzip, deflate, br"
            else:
                headers["Accept-Encoding"] = "gzip, deflate"
            if ZSTD:
                headers["Accept-Encoding"] += ", zstd"

            if referer := self.config("referer", self.referer):
                if isinstance(referer, str):
                    headers["Referer"] = referer
                elif self.root:
                    headers["Referer"] = self.root + "/"

            custom_ua = self.config("user-agent")
            if not custom_ua or custom_ua == "auto":
                pass
            elif custom_ua == "browser":
                headers["User-Agent"] = self.cache(
                    _browser_useragent, None, _exp=86400, _mem=False)
            elif custom_ua[0] == "@":
                headers["User-Agent"] = self.cache(
                    _browser_useragent, custom_ua[1:], _exp=86400, _mem=False)
            elif custom_ua[0] == "+":
                custom_ua = custom_ua[1:].lower()
                if custom_ua in {"firefox", "ff"}:
                    headers["User-Agent"] = util.USERAGENT_FIREFOX
                elif custom_ua in {"chrome", "cr"}:
                    headers["User-Agent"] = util.USERAGENT_CHROME
                elif custom_ua in {"gallery-dl", "gallerydl", "gdl"}:
                    headers["User-Agent"] = util.USERAGENT_GALLERYDL
                elif custom_ua in {"google-bot", "googlebot", "bot"}:
                    headers["User-Agent"] = "Googlebot-Image/1.0"
                else:
                    self.log.warning(
                        "Unsupported User-Agent preset '%s'", custom_ua)
            elif self.useragent is Extractor.useragent and not self.browser or \
                    custom_ua is not config.get(("extractor",), "user-agent"):
                headers["User-Agent"] = custom_ua

            if custom_headers := self.config("headers"):
                if isinstance(custom_headers, str):
                    if custom_headers in HEADERS:
                        custom_headers = HEADERS[custom_headers]
                    else:
                        self.log.error("Invalid 'headers' value '%s'",
                                       custom_headers)
                        custom_headers = ()
                headers.update(custom_headers)

        if custom_xff := self.config("geo-bypass"):
            if custom_xff is None or custom_xff == "auto":
                custom_xff = self.geobypass
        else:
            custom_xff = self.config("geo-bypass")
            if custom_xff == "auto":
                custom_xff = self.geobypass

        if custom_xff is not None:
            if ip := self.utils("/geo").random_ipv4(custom_xff):
                headers["X-Forwarded-For"] = ip
                self.log.debug("Using fake IP %s as 'X-Forwarded-For'", ip)
            else:
                self.log.warning("xff: Invalid ISO 3166 country code '%s'",
                                 custom_xff)

    def _init_cookies(self):
        """Populate the session's cookiejar"""
        if cookies := self.config("cookies"):
            if select := self.config("cookies-select"):
                if select == "rotate":
                    cookies = cookies[self.cookies_index % len(cookies)]
                    Extractor.cookies_index += 1
                else:
                    cookies = random.choice(cookies)
            self.cookies_load(cookies)

    def cookies_load(self, cookies_source):
        if isinstance(cookies_source, dict):
            self.cookies_update_dict(cookies_source, self.cookies_domain)

        elif isinstance(cookies_source, str):
            path = util.expand_path(cookies_source)
            try:
                with open(path, encoding="utf-8") as fp:
                    cookies = util.cookiestxt_load(fp)
            except ValueError as exc:
                self.log.warning("cookies: Invalid Netscape cookies.txt file "
                                 "'%s' (%s: %s)",
                                 cookies_source, exc.__class__.__name__, exc)
            except Exception as exc:
                self.log.warning("cookies: Failed to load '%s' (%s: %s)",
                                 cookies_source, exc.__class__.__name__, exc)
            else:
                self.log.debug("cookies: Loading cookies from '%s'",
                               cookies_source)
                try:
                    set_cookie = self.cookies.set_cookie
                except AttributeError:
                    for cookie in cookies:
                        self.cookies.set(
                            cookie.name, cookie.value,
                            domain=cookie.domain)
                else:
                    for cookie in cookies:
                        set_cookie(cookie)
                self.cookies_file = path

        elif isinstance(cookies_source, (list, tuple)):
            key = tuple(cookies_source)
            cookies = CACHE_COOKIES.get(key)

            if cookies is None:
                from ..cookies import load_cookies
                try:
                    cookies = load_cookies(cookies_source)
                except Exception as exc:
                    self.log.warning("cookies: %s", exc)
                    cookies = ()
                else:
                    CACHE_COOKIES[key] = cookies
            else:
                self.log.debug("cookies: Using cached cookies from %s", key)

            try:
                set_cookie = self.cookies.set_cookie
            except AttributeError:
                for cookie in cookies:
                    self.cookies.set(
                        cookie.name, cookie.value,
                        domain=cookie.domain)
            else:
                for cookie in cookies:
                    set_cookie(cookie)

        else:
            self.log.error(
                "cookies: Expected 'dict', 'list', or 'str' value for "
                "'cookies' option, got '%s' instead (%r)",
                cookies_source.__class__.__name__, cookies_source)

    def cookies_store(self):
        """Store the session's cookies in a cookies.txt file"""
        export = self.config("cookies-update", True)
        if not export:
            return

        if isinstance(export, str):
            path = util.expand_path(export)
        else:
            path = self.cookies_file
            if not path:
                return

        path_tmp = path + ".tmp"
        try:
            with open(path_tmp, "w", encoding="utf-8") as fp:
                # Use .jar for real Cookie objects (httpx/curl_cffi compat)
                try:
                    cookies_iter = self.cookies.jar
                except AttributeError:
                    cookies_iter = self.cookies
                util.cookiestxt_store(fp, cookies_iter)
            os.replace(path_tmp, path)
        except OSError as exc:
            self.log.error("cookies: Failed to write to '%s' "
                           "(%s: %s)", path, exc.__class__.__name__, exc)

    def cookies_update(self, cookies, domain=""):
        """Update the session's cookiejar with 'cookies'"""
        if isinstance(cookies, dict):
            self.cookies_update_dict(cookies, domain or self.cookies_domain)
        else:
            try:
                set_cookie = self.cookies.set_cookie
            except AttributeError:
                try:
                    cookies = iter(cookies)
                except TypeError:
                    self.cookies.set(
                        cookies.name, cookies.value,
                        domain=cookies.domain)
                else:
                    for cookie in cookies:
                        self.cookies.set(
                            cookie.name, cookie.value,
                            domain=cookie.domain)
            else:
                try:
                    cookies = iter(cookies)
                except TypeError:
                    set_cookie(cookies)
                else:
                    for cookie in cookies:
                        set_cookie(cookie)

    def cookies_update_dict(self, cookiedict, domain):
        """Update cookiejar with name-value pairs from a dict"""
        set_cookie = self.cookies.set
        for name, value in cookiedict.items():
            set_cookie(name, value, domain=domain)

    def cookies_check(self, cookies_names, domain=None, subdomains=False):
        """Check if all 'cookies_names' are in the session's cookiejar"""
        if not self.cookies:
            return False

        if domain is None:
            domain = self.cookies_domain
        names = set(cookies_names)
        now = time.time()

        # Iterate over .jar for real Cookie objects (httpx/curl_cffi
        # iteration yields strings, not Cookie objects)
        try:
            cookie_iter = self.cookies.jar
        except AttributeError:
            cookie_iter = self.cookies

        for cookie in cookie_iter:
            if cookie.name not in names:
                continue

            if not domain or cookie.domain == domain:
                pass
            elif not subdomains or not cookie.domain.endswith(domain):
                continue

            if cookie.expires:
                diff = int(cookie.expires - now)

                if diff <= 0:
                    self.log.warning(
                        "cookies: %s/%s expired at %s",
                        cookie.domain.lstrip("."), cookie.name,
                        dt.datetime.fromtimestamp(cookie.expires))
                    continue

                elif diff <= 86400:
                    hours = diff // 3600
                    self.log.warning(
                        "cookies: %s/%s will expire in less than %s hour%s",
                        cookie.domain.lstrip("."), cookie.name,
                        hours + 1, "s" if hours else "")

            names.discard(cookie.name)
            if not names:
                return True
        return False

    def _extract_jsonld(self, page):
        return util.json_loads(
            text.extr(page, '<script type="application/ld+json">',
                      "</script>") or
            text.extr(page, "<script type='application/ld+json'>",
                      "</script>"))

    def _extract_nextdata(self, page):
        return util.json_loads(
            text.extr(page, ' id="__NEXT_DATA__" type="application/json">',
                      "</script>") or
            text.extr(page, " id='__NEXT_DATA__' type='application/json'>",
                      "</script>"))

    def _get_date_min_max(self, dmin=None, dmax=None):
        """Retrieve and parse 'date-min' and 'date-max' config values"""
        def get(key, default):
            ts = self.config(key, default)
            if isinstance(ts, str):
                dt_obj = dt.parse_iso(ts)
                if dt_obj is dt.NONE:
                    self.log.warning("Unable to parse '%s': Invalid ISO 8601 "
                                     "date/time value '%s'", key, ts)
                    ts = default
                else:
                    ts = int(dt.to_ts(dt_obj))
            return ts
        if self.config("date-format"):
            self.log.error("'date-format' is no longer supported. "
                           "Use ISO 8601 date/time values instead.")
        return get("date-min", dmin), get("date-max", dmax)

    def _dump_response(self, response, history=True):
        """Write the response content to a .txt file in the current directory.

        The file name is derived from the response url,
        replacing special characters with "_"
        """
        if history:
            for resp in response.history:
                self._dump_response(resp, False)

        if hasattr(Extractor, "_dump_index"):
            Extractor._dump_index += 1
        else:
            Extractor._dump_index = 1
            Extractor._dump_sanitize = util.re_compile(
                r"[\\\\|/<>:\"?*&=#]+").sub

        fname = (f"{Extractor._dump_index:>02}_"
                 f"{Extractor._dump_sanitize('_', response.url)}")

        if util.WINDOWS:
            path = os.path.abspath(fname)[:255]
        else:
            path = fname[:251]

        try:
            with open(path + ".txt", 'wb') as fp:
                util.dump_response(
                    response, fp,
                    headers=(self._write_pages in {"all", "ALL"}),
                    hide_auth=(self._write_pages != "ALL")
                )
            self.log.info("Writing '%s' response to '%s'",
                          response.url, path + ".txt")
        except Exception as e:
            self.log.warning("Failed to dump HTTP request (%s: %s)",
                             e.__class__.__name__, e)


class GalleryExtractor(Extractor):

    subcategory = "gallery"
    filename_fmt = "{category}_{gallery_id}_{num:>03}.{extension}"
    directory_fmt = ("{category}", "{gallery_id} {title}")
    archive_fmt = "{gallery_id}_{num}"
    enum = "num"

    def __init__(self, match, url=None):
        Extractor.__init__(self, match)

        if url is None and (path := self.groups[0]) and path[0] == "/":
            self.page_url = self.root + path
        else:
            self.page_url = url

    def items(self):
        self.login()

        if self.page_url:
            page = self.request(
                self.page_url, notfound=self.subcategory).text
        else:
            page = None

        data = self.metadata(page)
        imgs = self.images(page)
        assets = self.assets(page)

        if "count" in data:
            if self.config("page-reverse"):
                images = util.enumerate_reversed(imgs, 1, data["count"])
            else:
                images = zip(
                    range(1, data["count"]+1),
                    imgs,
                )
        else:
            enum = enumerate
            try:
                data["count"] = len(imgs)
            except TypeError:
                pass
            else:
                if self.config("page-reverse"):
                    enum = util.enumerate_reversed
            images = enum(imgs, 1)

        yield Message.Directory, "", data
        enum_key = self.enum

        if assets:
            for asset in assets:
                url = asset["url"]
                asset.update(data)
                asset[enum_key] = 0
                if "extension" not in asset:
                    text.nameext_from_url(url, asset)
                yield Message.Url, url, asset

        for data[enum_key], (url, imgdata) in images:
            if imgdata:
                data.update(imgdata)
                if "extension" not in imgdata:
                    text.nameext_from_url(url, data)
            else:
                text.nameext_from_url(url, data)
            yield Message.Url, url, data

    def login(self):
        """Login and set necessary cookies"""

    def metadata(self, page):
        """Return a dict with general metadata"""

    def images(self, page):
        """Return a list or iterable of all (image-url, metadata)-tuples"""

    def assets(self, page):
        """Return an iterable of additional gallery assets

        Each asset must be a 'dict' containing at least 'url' and 'type'
        """


class ChapterExtractor(GalleryExtractor):

    subcategory = "chapter"
    directory_fmt = (
        "{category}", "{manga}",
        "{volume:?v/ />02}c{chapter:>03}{chapter_minor:?//}{title:?: //}")
    filename_fmt = (
        "{manga}_c{chapter:>03}{chapter_minor:?//}_{page:>03}.{extension}")
    archive_fmt = (
        "{manga}_{chapter}{chapter_minor}_{page}")
    enum = "page"


class MangaExtractor(Extractor):

    subcategory = "manga"
    categorytransfer = True
    chapterclass = None
    reverse = True

    def __init__(self, match, url=None):
        Extractor.__init__(self, match)

        if url is None and (path := self.groups[0]) and path[0] == "/":
            self.page_url = self.root + path
        else:
            self.page_url = url

        if self.config("chapter-reverse", False):
            self.reverse = not self.reverse

    def items(self):
        self.login()

        if self.page_url:
            page = self.request(self.page_url, notfound=self.subcategory).text
        else:
            page = None

        chapters = self.chapters(page)
        if self.reverse:
            chapters.reverse()

        for chapter, data in chapters:
            data["_extractor"] = self.chapterclass
            yield Message.Queue, chapter, data

    def login(self):
        """Login and set necessary cookies"""

    def chapters(self, page):
        """Return a list of all (chapter-url, metadata)-tuples"""


class Dispatch():
    subcategory = "user"
    cookies_domain = None
    finalize = Extractor.finalize
    skip_files = None

    def __iter__(self):
        return self.items()

    def initialize(self):
        pass

    def _dispatch_extractors(self, extractor_data, default=(), alt=None):
        extractors = {
            data[0].subcategory: data
            for data in extractor_data
        }

        include = self.config("include", default) or ()
        if include == "all":
            include = extractors
        else:
            if isinstance(include, str):
                include = include.replace(" ", "").split(",")
            if alt is not None:
                for sub, sub_alt, url in alt:
                    extractors[sub_alt] = (extractors[sub] if url is None else
                                           (extractors[sub][0], url))

        results = []
        for category in include:
            try:
                extr, url = extractors[category]
            except KeyError:
                self.log.warning("Invalid include '%s'", category)
            else:
                results.append((Message.Queue, url, {"_extractor": extr}))
        return iter(results)


class AsynchronousMixin():
    """Run info extraction in a separate thread"""

    def __iter__(self):
        self.initialize()

        messages = queue.Queue(5)
        thread = threading.Thread(
            target=self.async_items,
            args=(messages,),
            daemon=True,
        )

        thread.start()
        while True:
            msg = messages.get()
            if msg is None:
                thread.join()
                return
            if isinstance(msg, Exception):
                thread.join()
                raise msg
            yield msg
            messages.task_done()

    def async_items(self, messages):
        try:
            for msg in self.items():
                messages.put(msg)
        except Exception as exc:
            messages.put(exc)
        messages.put(None)


class BaseExtractor(Extractor):
    instances = ()

    def __init__(self, match):
        if not self.category:
            self._init_category(match)
        Extractor.__init__(self, match)

    def _init_category(self, match):
        for index, group in enumerate(match.groups()):
            if group is not None:
                if index:
                    self.category, self.root, info = self.instances[index-1]
                    if not self.root:
                        self.root = text.root_from_url(match[0])
                    self.config_instance = info.get
                else:
                    self.root = group
                    self.category = group.partition("://")[2]
                break

    @classmethod
    def update(cls, instances):
        if extra_instances := config.get(("extractor",), cls.basecategory):
            for category, info in extra_instances.items():
                if isinstance(info, dict) and "root" in info:
                    instances[category] = info

        pattern_list = []
        instance_list = cls.instances = []
        for category, info in instances.items():
            if root := info["root"]:
                root = root.rstrip("/")
            instance_list.append((category, root, info))

            pattern = info.get("pattern")
            if not pattern:
                pattern = re.escape(root[root.index(":") + 3:])
            pattern_list.append(pattern + "()")

        return (f"(?:{cls.basecategory}:(https?://[^/?#]+)|"
                f"(?:https?://)?(?:{'|'.join(pattern_list)}))")


def _browser_useragent(browser):
    """Get User-Agent header from default browser"""
    import webbrowser
    try:
        open = webbrowser.get(browser).open
    except webbrowser.Error:
        if not browser:
            raise
        import shutil
        if not (browser := shutil.which(browser)):
            raise

        def open(url):
            util.Popen((browser, url),
                       start_new_session=False if util.WINDOWS else True)

    import socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    host, port = server.getsockname()
    open(f"http://{host}:{port}/user-agent")

    client = server.accept()[0]
    server.close()

    for line in client.recv(1024).split(b"\r\n"):
        key, _, value = line.partition(b":")
        if key.strip().lower() == b"user-agent":
            useragent = value.strip()
            break
    else:
        useragent = b""

    client.send(b"HTTP/1.1 200 OK\r\n\r\n" + useragent)
    client.close()

    return useragent.decode()


CACHE_COOKIES = {}
CACHE_MEMORY = {}
CACHE_UTILS = {}
CATEGORY_MAP = ()


HEADERS_FIREFOX_140 = (
    ("User-Agent", "Mozilla/5.0 ({}; rv:140.0) Gecko/20100101 Firefox/140.0"),
    ("Accept", "text/html,application/xhtml+xml,"
               "application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", None),
    ("Connection", "keep-alive"),
    ("Content-Type", None),
    ("Content-Length", None),
    ("Referer", None),
    ("Origin", None),
    ("Cookie", None),
    ("Sec-Fetch-Dest", "empty"),
    ("Sec-Fetch-Mode", "cors"),
    ("Sec-Fetch-Site", "same-origin"),
    ("TE", "trailers"),
)
HEADERS_FIREFOX_128 = (
    ("User-Agent", "Mozilla/5.0 ({}; rv:128.0) Gecko/20100101 Firefox/128.0"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", None),
    ("Referer", None),
    ("Connection", "keep-alive"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Cookie", None),
    ("Sec-Fetch-Dest", "empty"),
    ("Sec-Fetch-Mode", "no-cors"),
    ("Sec-Fetch-Site", "same-origin"),
    ("TE", "trailers"),
)
HEADERS_CHROMIUM_138 = (
    ("Connection", "keep-alive"),
    ("sec-ch-ua", '"Not)A;Brand";v="8", "Chromium";v="138"'),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", '"Linux"'),
    ("Upgrade-Insecure-Requests", "1"),
    ("User-Agent", "Mozilla/5.0 ({}) AppleWebKit/537.36 (KHTML, "
                   "like Gecko) Chrome/138.0.0.0 Safari/537.36"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7"),
    ("Referer", None),
    ("Sec-Fetch-Site", "same-origin"),
    ("Sec-Fetch-Mode", "no-cors"),
    #  ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "empty"),
    ("Accept-Encoding", None),
    ("Accept-Language", "en-US,en;q=0.9"),
)
HEADERS_CHROMIUM_111 = (
    ("Connection", "keep-alive"),
    ("Upgrade-Insecure-Requests", "1"),
    ("User-Agent", "Mozilla/5.0 ({}) AppleWebKit/537.36 (KHTML, "
                   "like Gecko) Chrome/111.0.0.0 Safari/537.36"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7"),
    ("Referer", None),
    ("Sec-Fetch-Site", "same-origin"),
    ("Sec-Fetch-Mode", "no-cors"),
    ("Sec-Fetch-Dest", "empty"),
    ("Accept-Encoding", None),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("cookie", None),
    ("content-length", None),
)
HEADERS = {
    "firefox"    : HEADERS_FIREFOX_140,
    "firefox/140": HEADERS_FIREFOX_140,
    "firefox/128": HEADERS_FIREFOX_128,
    "chrome"     : HEADERS_CHROMIUM_138,
    "chrome/138" : HEADERS_CHROMIUM_138,
    "chrome/111" : HEADERS_CHROMIUM_111,
}

BROTLI = True
ZSTD = True
