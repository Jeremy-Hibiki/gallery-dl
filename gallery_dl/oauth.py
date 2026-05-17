# -*- coding: utf-8 -*-

# Copyright 2018-2026 Mike Fährmann
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

"""OAuth helper functions and classes"""

import hmac
import time
import random
import string
import hashlib
import binascii
import urllib.parse

import httpx

from . import text


def nonce(size, alphabet=string.ascii_letters):
    """Generate a nonce value with 'size' characters"""
    return "".join(random.choice(alphabet) for _ in range(size))


def quote(value, quote=urllib.parse.quote):
    """Quote 'value' according to the OAuth1.0 standard"""
    return quote(value, "~")


def concat(*args):
    """Concatenate 'args' as expected by OAuth1.0"""
    return "&".join(quote(item) for item in args)


class OAuth1Session():
    """Extension to httpx.Client to support OAuth 1.0"""

    def __init__(self, consumer_key, consumer_secret,
                 token=None, token_secret=None):
        self.auth = OAuth1Client(
            consumer_key, consumer_secret,
            token, token_secret,
        )
        self._session = httpx.Client()
        self.cookies = self._session.cookies

    def request(self, method, url, **kwargs):
        req = self._session.build_request(method, url, **kwargs)
        self.auth(req)
        return self._session.send(req)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self):
        self._session.close()


class OAuth1Client():
    """OAuth1.0a authentication"""

    def __init__(self, consumer_key, consumer_secret,
                 token=None, token_secret=None):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.token = token
        self.token_secret = token_secret

    def __call__(self, request):
        """Sign an httpx Request with OAuth 1.0 headers."""
        oauth_params = [
            ("oauth_consumer_key", self.consumer_key),
            ("oauth_nonce", nonce(16)),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", str(int(time.time()))),
            ("oauth_version", "1.0"),
        ]
        if self.token:
            oauth_params.append(("oauth_token", self.token))

        signature = self.generate_signature(request, oauth_params)
        oauth_params.append(("oauth_signature", signature))

        request.headers["Authorization"] = "OAuth " + ",".join(
            key + '="' + value + '"' for key, value in oauth_params)

        return request

    def generate_signature(self, request, params):
        """Generate 'oauth_signature' value"""
        url = str(request.url)
        url, _, query = url.partition("?")

        params = params.copy()
        for key, value in text.parse_query(query).items():
            params.append((quote(key), quote(value)))
        params.sort()
        query = "&".join("=".join(item) for item in params)

        message = concat(request.method, url, query).encode()
        key = concat(self.consumer_secret, self.token_secret or "").encode()
        signature = hmac.new(key, message, hashlib.sha1).digest()

        return quote(binascii.b2a_base64(signature)[:-1].decode())


class OAuth1API():
    """Base class for OAuth1.0 based API interfaces"""
    API_KEY = None
    API_SECRET = None

    def __init__(self, extractor):
        self.exc = extractor.exc
        self.log = extractor.log
        self.extractor = extractor

        api_key = extractor.config("api-key", self.API_KEY)
        api_secret = extractor.config("api-secret", self.API_SECRET)
        token = extractor.config("access-token")
        token_secret = extractor.config("access-token-secret")
        key_type = "default" if api_key == self.API_KEY else "custom"

        if token is None or token == "cache":
            token, token_secret = extractor.cache(
                _token_cache, (extractor.category, api_key), _mem=False)

        if api_key and api_secret and token and token_secret:
            self.log.debug("Using %s OAuth1.0 authentication", key_type)
            self.session = OAuth1Session(
                api_key, api_secret, token, token_secret)
            self.api_key = None
        else:
            self.log.debug("Using %s api_key authentication", key_type)
            self.session = extractor.session
            self.api_key = api_key

    def request(self, url, **kwargs):
        kwargs["fatal"] = None
        kwargs["session"] = self.session
        return self.extractor.request(url, **kwargs)


def _token_cache(key):
    return None, None
