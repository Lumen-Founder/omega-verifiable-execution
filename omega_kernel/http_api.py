"""Minimal JSON-over-HTTP developer API, loopback only.

POST /intents            body {"envelope": {...}, "auth_tag": "<hex>"}  -> receipt
POST /intents/<id>/execute                                              -> receipt
GET  /intents/<id>        status
GET  /intents/<id>/verify journal/backend cross-check
GET  /recovery            open intents and journal chain
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from omega_kernel import envelope as E

MAX_BODY = 16384
ROUTE = re.compile(r'/intents/([0-9a-f]{32})(/execute|/verify)?')


def serve(kernel, port=0, host='127.0.0.1'):
    if host not in ('127.0.0.1', '::1', 'localhost'):
        raise ValueError('LOOPBACK_ONLY')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # request lines may carry ids; keep stderr quiet
            pass

        def _send(self, code, obj):
            body = json.dumps(obj, sort_keys=True).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == '/recovery':
                return self._send(200, kernel.recovery_report())
            m = ROUTE.fullmatch(self.path)
            if not m or m.group(2) == '/execute':
                return self._send(404, {'ok': False, 'code': 'NO_ROUTE'})
            r = kernel.verify(m.group(1)) if m.group(2) else kernel.status(m.group(1))
            return self._send(200 if r.get('ok') or r.get('state') else 404, r)

        def do_POST(self):
            n = int(self.headers.get('Content-Length') or 0)
            if n > MAX_BODY:
                return self._send(413, {'ok': False, 'code': 'TOO_LARGE'})
            raw = self.rfile.read(n)
            if self.path == '/intents':
                try:  # same strict decoding as envelopes: duplicate keys / floats / NaN refused
                    req = json.loads(raw, parse_float=E._no_float, parse_constant=E._no_float, object_pairs_hook=E._pairs)
                    env, auth = req['envelope'], req['auth_tag']
                except E.EnvelopeError as e:
                    return self._send(400, {'ok': False, 'code': e.code})
                except (ValueError, KeyError, TypeError):
                    return self._send(400, {'ok': False, 'code': 'BAD_REQUEST'})
                r = kernel.submit(env, auth)
                return self._send(200 if r.get('state') else 400, r)
            m = ROUTE.fullmatch(self.path)
            if m and m.group(2) == '/execute':
                r = kernel.execute(m.group(1))
                return self._send(200 if r.get('state') else 404, r)
            return self._send(404, {'ok': False, 'code': 'NO_ROUTE'})

    srv = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
