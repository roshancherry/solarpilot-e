#!/usr/bin/env python3
"""Solar Pilot Bridge - Home Assistant app.

Polls the Solar Pilot mode queue and runs the customer's OWN Home Assistant
scripts locally. The connection key is never written to logs. The app can only
run scripts the customer explicitly maps in its Configuration tab; with no
mapping, a mode command is confirmed back as "not run" and nothing executes.

Safety semantics (validated against the queue worker and real HA Core):
- at-least-once delivery: an unconfirmed command is delivered again. A
  persistent per-command state (received -> dispatched -> done, atomically
  stored) makes crashes safe WITHOUT ever re-running on uncertainty:
    * redelivery of a confirmed command re-sends the recorded result only.
    * redelivery after a crash DURING dispatch is never retried and never
      re-run: the outcome is unknowable (Home Assistant's last_triggered is
      entity-level, not per-command - the user or another automation can run
      the same script), so the command is confirmed as "interrupted, outcome
      unknown, not re-run" and left for manual review in HA's logbook.
- execution result: script.turn_on returns when the script STARTS, not when
  it finishes. On the live (non-crash) path the app waits for the script
  entity to report completion before confirming ran=[script]; if completion
  is not observed within the timeout it conservatively confirms
  failed=["started but completion not confirmed"] - it never claims an
  execution it did not observe. Completion is entity-level evidence, not
  per-command proof; concurrent manual runs of the same script can make
  completion be attributed to this command. That residual is accepted and
  documented rather than hidden.
- freshness: a command is only eligible to run when its age is provable from
  SERVER timestamps: the queue delivers the command's enqueue time (ts) and
  its own current time (lastPoll) in the same response, so age = lastPoll -
  ts is immune to this host's clock. A command older than MAX_COMMAND_AGE_S
  is confirmed as "expired, not run". A queue response without these fields
  fails closed: the command is confirmed as "freshness unverifiable" and
  never executed. Delivery freshness is not enough on its own: a command
  must also be dispatched within LOCAL_STALL_S of local MONOTONIC time
  after delivery, or it is confirmed as "stalled locally, not run" - a
  stalled queue response can never execute an old command. The queue
  additionally enforces a hard TTL server-side (90 s as deployed) so stale
  commands are never delivered at all.
- fail-closed configuration and state: any malformed option (bad server URL,
  customer id, key format, poll interval, or a mapping outside the script
  domain) or an unreadable/corrupt command store stops the app at startup
  with a clear message; nothing is polled or executed from a questionable
  base.
"""
import json
import os
import re
import time
import traceback
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

DATA = os.environ.get('SP_DATA', '/data')
STORE_PATH = os.path.join(DATA, 'commands.json')
MAX_STORE = 200
MAX_COMMAND_AGE_S = 45       # refuse to run commands older than this AT DELIVERY (server TTL is 90 s)
LOCAL_STALL_S = int(os.environ.get('SP_STALL_S', '30'))  # monotonic bound on delivery->dispatch delay

RE_CUSTOMER = re.compile(r'^owner:[A-Za-z0-9_-]+$')
RE_KEY = re.compile(r'^spk_[0-9a-f]{48}$')
RE_SCRIPT = re.compile(r'^script\.[a-z0-9_]+$')


def log(*a):
    print('[solar-pilot-bridge]', *a, flush=True)


def die(msg):
    log('CONFIGURATION ERROR:', msg)
    raise SystemExit(1)


def load_options():
    raw = os.environ.get('SP_OPTIONS')
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            die('options are not valid JSON.')
    try:
        with open(os.path.join(DATA, 'options.json')) as f:
            return json.load(f)
    except FileNotFoundError:
        die('options file missing - configure the app in its Configuration tab first.')
    except Exception:
        die('options file is not valid JSON.')


def http(method, url, headers=None, payload=None, timeout=20):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header('user-agent', 'SolarPilotBridge/0.1.1')
    req.add_header('content-type', 'application/json')
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode() or '')[:200]
    except Exception as e:
        return 0, str(e)



LINK_PATH = os.path.join(DATA, 'link.json')
DEVICE_PATH = os.path.join(DATA, 'device.json')
RE_RID = re.compile(r'^[A-Za-z0-9_-]{22,64}$')


def b64u(b):
    import base64
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


class Enrollment:
    """No-copy provisioning. The Bridge holds a high-entropy device secret D
    that never leaves it except once inside the redeem POST body over TLS. A
    public correlation id C appears in the Link URL; C alone redeems nothing.
    The owner approves C in Solar Pilot under their session; only a request
    presenting D whose hash matches the registered hash receives the key,
    exactly once (server consumes the grant atomically)."""

    def __init__(self, server, ha_url, ha_token):
        self.server = server
        self.ha_url = ha_url
        self.ha_token = ha_token
        self.dev = self._load_device()
        self.linked = None

    def _load_device(self):
        try:
            with open(DEVICE_PATH) as f:
                d = json.load(f)
            if RE_RID.match(d.get('request_id', '')) and len(d.get('secret', '')) >= 32:
                return d
        except Exception:
            pass
        import hashlib, secrets
        d = {'secret': b64u(secrets.token_bytes(32)), 'request_id': b64u(secrets.token_bytes(16))}
        d['d_hash'] = hashlib.sha256(d['secret'].encode()).hexdigest()
        os.makedirs(DATA, exist_ok=True)
        tmp = DEVICE_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, DEVICE_PATH)
        return d

    def _post(self, path, payload):
        return http('POST', self.server + path, payload=payload)

    def register(self):
        status, body = self._post('/api/ha/link-request',
                                  {'request_id': self.dev['request_id'], 'd_hash': self.dev['d_hash'],
                                   'label': 'Solar Pilot Bridge'})
        return status == 200

    def state(self):
        status, body = http('GET', self.server + '/api/ha/link-status?request_id=' + self.dev['request_id'])
        if status != 200:
            return None
        try:
            return json.loads(body).get('state')
        except Exception:
            return None

    def redeem(self):
        status, body = self._post('/api/ha/link-redeem',
                                  {'request_id': self.dev['request_id'], 'd': self.dev['secret']})
        if status != 200:
            return False
        try:
            j = json.loads(body)
            key, customer = j['key'], j['customer']
        except Exception:
            return False
        if not RE_KEY.match(key) or not RE_CUSTOMER.match(customer):
            return False
        tmp = LINK_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'connection_key': key, 'customer': customer}, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, LINK_PATH)
        log('linked to Solar Pilot - connection details provisioned without any copying')
        return True

    def page(self):
        link = self.server + '/ha-pairing?link=' + self.dev['request_id']
        st = self.state() or 'unknown'
        return ('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>Solar Pilot Bridge</title>'
                '<body style="font-family:system-ui;max-width:32em;margin:3em auto;padding:0 1em">'
                '<h1>Solar Pilot Bridge</h1>'
                '<p>Status: <b>' + st + '</b></p>'
                '<p><a style="display:inline-block;background:#0a7cff;color:#fff;padding:.8em 1.4em;'
                'border-radius:8px;text-decoration:none" href="' + link + '">Link this Home Assistant</a></p>'
                '<p style="color:#666">Opens Solar Pilot to approve the connection. Nothing to copy or paste.</p>'
                '<script>setTimeout(function(){location.reload()},5000)</script>')

    def serve(self, port):
        enr = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = enr.page().encode()
                self.send_response(200)
                self.send_header('content-type', 'text/html; charset=utf-8')
                self.send_header('content-length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(('0.0.0.0', port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def run(self):
        port = int(os.environ.get('INGRESS_PORT') or '8099')
        if not self.register():
            log('could not register a link request yet; will keep retrying in the background')
        self.serve(port)
        log('waiting to be linked - open this app\'s web interface and tap "Link this Home Assistant"')
        while True:
            st = self.state()
            if st == 'approved':
                if self.redeem():
                    return load_linked_options()
                time.sleep(5)
            elif st in ('expired', 'none'):
                self.register()
                time.sleep(10)
            else:
                time.sleep(5)


def load_linked_options():
    with open(LINK_PATH) as f:
        j = json.load(f)
    return {'server': None, 'customer': j['customer'], 'connection_key': j['connection_key']}


class Bridge:
    def __init__(self, opts):
        self.server = (opts.get('server') or 'https://solar-pilot-cherri.pages.dev').rstrip('/')
        if not self.server.startswith('https://') and os.environ.get('SP_ALLOW_INSECURE') != '1':
            die('server must be an https URL.')
        self.customer = (opts.get('customer') or '').strip()
        if not RE_CUSTOMER.match(self.customer):
            die('customer id is missing or malformed - copy it exactly from the Solar Pilot pairing page.')
        self.key = (opts.get('connection_key') or '').strip()
        if not RE_KEY.match(self.key):
            die('connection key is missing or malformed - paste the exact spk_... key from the Solar Pilot pairing page.')
        try:
            self.interval = int(opts.get('poll_interval_seconds') or 10)
        except Exception:
            die('poll interval must be a number of seconds.')
        if not 5 <= self.interval <= 300:
            die('poll interval must be between 5 and 300 seconds.')
        try:
            self.completion_timeout = int(opts.get('completion_timeout_seconds') or 120)
        except Exception:
            die('completion timeout must be a number of seconds.')
        if not 10 <= self.completion_timeout <= 600:
            die('completion timeout must be between 10 and 600 seconds.')
        self.scripts = {}
        for k, v in (opts.get('mode_scripts') or {}).items():
            v = (v or '').strip()
            if v and not RE_SCRIPT.match(v):
                die('mode "' + k.replace('_', '-') + '" must map to a script entity (script.something) - the app will not run anything else.')
            if v:
                self.scripts[k.replace('_', '-')] = v
        self.ha_url = os.environ.get('HA_URL', 'http://supervisor/core').rstrip('/')
        self.ha_token = os.environ.get('SUPERVISOR_TOKEN', '')
        if not self.ha_token:
            die('Home Assistant API token missing - this app must run as a Home Assistant app with API access.')
        self.store = self._load_store()

    # ---- persistent per-command state ----

    def _load_store(self):
        if not os.path.exists(STORE_PATH):
            return {}
        try:
            with open(STORE_PATH) as f:
                d = json.load(f)
            if not isinstance(d, dict):
                raise ValueError('not an object')
            return d
        except Exception:
            # A corrupt store means crash state is lost; refuse to start rather
            # than risk re-running an interrupted command.
            die('command store at ' + STORE_PATH + ' is unreadable - remove it only after checking Home Assistant for any interrupted mode run.')

    def _save_store(self):
        try:
            os.makedirs(DATA, exist_ok=True)
            done = sorted((r for r in self.store.values() if r.get('state') == 'done'),
                          key=lambda r: r.get('first_seen', 0))
            while len(self.store) > MAX_STORE and done:
                del self.store[done.pop(0)['id']]
            tmp = STORE_PATH + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(self.store, f)
            os.replace(tmp, STORE_PATH)
        except Exception as e:
            log('warning: could not persist command store:', e)

    # ---- queue ----

    def poll(self):
        status, body = http('GET', f'{self.server}/api/ha/poll?customer={self.customer}',
                            headers={'x-sp-ha-key': self.key})
        if status == 401:
            log('queue refused the connection key (401). Rotate the key in Solar Pilot and update the app Configuration.')
            return None, None, self.interval * 6  # back off; a wrong key will never succeed by retrying fast
        if status != 200:
            log('queue poll failed (status', status, '); retrying')
            return None, None, self.interval
        try:
            d = json.loads(body)
            return d.get('command'), d.get('lastPoll'), self.interval
        except Exception:
            return None, None, self.interval

    def ack(self, command_id, ran, failed):
        status, _ = http('POST', f'{self.server}/api/ha/ack?customer={self.customer}',
                         headers={'x-sp-ha-key': self.key},
                         payload={'id': command_id, 'ran': ran, 'failed': failed})
        return status == 200

    def finish(self, rec, ran, failed, note):
        if self.ack(rec['id'], ran, failed):
            rec['state'] = 'done'
            rec['result'] = {'ran': ran, 'failed': failed, 'outcome': rec.get('outcome', 'settled')}
            self._save_store()
            log(note)
        else:
            log('confirmation failed for', rec.get('mode', '?'), '- queue will redeliver; recorded state is kept')

    # ---- Home Assistant ----

    def ha_state(self, entity):
        status, body = http('GET', f'{self.ha_url}/api/states/{entity}',
                            headers={'Authorization': 'Bearer ' + self.ha_token})
        if status != 200:
            return None
        try:
            return json.loads(body)
        except Exception:
            return None

    def turn_on(self, entity):
        status, _ = http('POST', f'{self.ha_url}/api/services/script/turn_on',
                         headers={'Authorization': 'Bearer ' + self.ha_token},
                         payload={'entity_id': entity})
        return status in (200, 201), status

    def wait_completion(self, entity, since_ts):
        """Wait until the script entity reports a run started at/after since_ts
        has finished. Entity-level evidence, not per-command proof."""
        deadline = time.time() + self.completion_timeout
        while time.time() < deadline:
            st = self.ha_state(entity)
            if st is not None:
                attrs = st.get('attributes') or {}
                lt = attrs.get('last_triggered')
                try:
                    lt_ts = datetime.fromisoformat((lt or '').replace('Z', '+00:00')).timestamp() if lt else None
                except Exception:
                    lt_ts = None
                if lt_ts and lt_ts >= since_ts - 2 and not attrs.get('current'):
                    return True
            time.sleep(2)
        return False

    def dispatch(self, rec):
        entity = rec['entity']
        rec['dispatched_at'] = time.time()
        rec['state'] = 'dispatched'
        self._save_store()  # persist BEFORE the call: a crash here lands in the never-retry branch
        ok, st = self.turn_on(entity)
        if not ok:
            self.finish(rec, [], [entity + ' (http ' + str(st) + ')'],
                        'script call failed for ' + entity + ' (http ' + str(st) + ') - reported as failed')
            return
        if self.wait_completion(entity, rec['dispatched_at']):
            self.finish(rec, [entity], [],
                        'ran ' + entity + ' for mode ' + rec['mode'] + ' (completion observed) and confirmed')
        else:
            self.finish(rec, [], ['started but completion not confirmed within ' + str(self.completion_timeout) + 's'],
                        entity + ' started but completion was not confirmed within ' +
                        str(self.completion_timeout) + 's - conservatively reported as unconfirmed')

    # ---- command handling ----

    def handle(self, cmd, server_now_ms):
        cid, mode = cmd.get('id'), cmd.get('mode')
        if not cid or not mode:
            return
        now = time.time()
        rec = self.store.get(cid)

        if rec is not None and rec.get('state') == 'done':
            # Queue redelivered a command we already confirmed: re-send the recorded result only.
            r = rec.get('result') or {'ran': [], 'failed': []}
            if self.ack(cid, r['ran'], r['failed']):
                log('re-confirmed', rec['mode'], 'after redelivery (did not run again)')
            return

        if rec is not None and rec.get('state') == 'dispatched':
            # A crash interrupted dispatch. Whether the script actually ran is
            # unknowable (HA evidence is entity-level, not per-command), so this
            # is NEVER retried and NEVER re-run. The outcome stays UNKNOWN in the
            # stored record and in what is reported - it is not converted into a
            # proven failure or a proven not-run.
            rec['outcome'] = 'unknown'
            self.finish(rec, [], ['interrupted during execution - outcome unknown, not re-run'],
                        'command ' + rec['mode'] + ' was interrupted during execution - outcome unknown, NOT re-run; check the script\'s history in Home Assistant')
            return

        # Freshness from SERVER timestamps only (immune to this host's clock).
        ts, sn = cmd.get('ts'), server_now_ms
        if not isinstance(ts, (int, float)) or not isinstance(sn, (int, float)):
            if rec is None:
                rec = {'id': cid, 'mode': mode, 'entity': self.scripts.get(mode),
                       'state': 'received', 'first_seen': now, 'dispatched_at': None}
                self.store[cid] = rec
            self.finish(rec, [], ['freshness unverifiable - queue server outdated'],
                        'command ' + mode + ' carried no server timestamp - confirmed as unverifiable, not run')
            return
        age = (sn - ts) / 1000.0
        if age > MAX_COMMAND_AGE_S:
            if rec is None:
                rec = {'id': cid, 'mode': mode, 'entity': self.scripts.get(mode),
                       'state': 'received', 'first_seen': now, 'dispatched_at': None}
                self.store[cid] = rec
            self.finish(rec, [], ['expired - not run'],
                        'command ' + mode + ' was ' + str(int(age)) + 's old at delivery - confirmed as expired, not run')
            return

        if rec is None:
            entity = self.scripts.get(mode)
            rec = {'id': cid, 'mode': mode, 'entity': entity, 'state': 'received',
                   'first_seen': now, 'first_seen_mono': time.monotonic(), 'dispatched_at': None}
            self.store[cid] = rec
            if not entity:
                self.finish(rec, [], ['unmapped:' + mode],
                            'mode ' + mode + ' has no script mapped - confirmed as not run, nothing executed')
                return
            self._save_store()

        # Post-delivery bound on the LOCAL monotonic clock: even a command that was
        # fresh at delivery must not execute after stalling locally (backlog,
        # suspend/resume, slow earlier commands). Records restored from disk after a
        # restart carry no meaningful monotonic stamp; the server-age check above
        # already re-verified freshness at THIS delivery, so they start a fresh stamp.
        rec.setdefault('first_seen_mono', time.monotonic())
        if time.monotonic() - rec['first_seen_mono'] > LOCAL_STALL_S:
            self.finish(rec, [], ['stalled locally - not run'],
                        'command ' + rec['mode'] + ' stalled locally after delivery - confirmed as expired, not run')
            return

        self.dispatch(rec)

    def loop(self):
        log('started; polling every', self.interval, 's for', self.customer)
        delay = self.interval
        while True:
            try:
                cmd, server_now, delay = self.poll()
                if cmd:
                    self.handle(cmd, server_now)
                    delay = 0.5  # drain further pending commands promptly
            except SystemExit:
                raise
            except Exception:
                log('unexpected error:', traceback.format_exc(limit=2))
                delay = self.interval
            time.sleep(delay)


if __name__ == '__main__':
    opts = load_options()
    if (opts.get('connection_key') or '').strip():
        Bridge(opts).loop()
    elif os.path.exists(LINK_PATH):
        lp = load_linked_options()
        lp['server'] = opts.get('server') or None
        lp['poll_interval_seconds'] = opts.get('poll_interval_seconds')
        lp['completion_timeout_seconds'] = opts.get('completion_timeout_seconds')
        lp['mode_scripts'] = opts.get('mode_scripts') or {}
        Bridge(lp).loop()
    else:
        server = (opts.get('server') or 'https://solar-pilot-cherri.pages.dev').rstrip('/')
        if not server.startswith('https://') and os.environ.get('SP_ALLOW_INSECURE') != '1':
            die('server must be an https URL.')
        lp = Enrollment(server, os.environ.get('HA_URL', 'http://supervisor/core').rstrip('/'),
                        os.environ.get('SUPERVISOR_TOKEN', '')).run()
        lp['server'] = opts.get('server') or None
        lp['poll_interval_seconds'] = opts.get('poll_interval_seconds')
        lp['completion_timeout_seconds'] = opts.get('completion_timeout_seconds')
        lp['mode_scripts'] = opts.get('mode_scripts') or {}
        Bridge(lp).loop()
