#!/usr/bin/env python3
"""CyberDeck Dashboard Server v3 — system stats, email alerts, social share support."""

import http.server, socketserver, json, os, re, signal, sys, smtplib
from collections import defaultdict
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ── Config ─────────────────────────────────────────────────────────────────────
PORT           = int(os.environ.get('DASHBOARD_PORT', '8000'))
DASHBOARD_DIR  = Path(__file__).resolve().parent
PROJECT_ROOT   = DASHBOARD_DIR.parent
LOGS_DIR       = PROJECT_ROOT / 'logs'
OUTPUT_DIR     = PROJECT_ROOT / 'output'
ALLOWED_ORIGIN = os.environ.get('DASHBOARD_ORIGIN', '*')

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER)

_alert_cfg = {
    'cpu_warn': 70.0, 'cpu_crit': 90.0,
    'mem_warn': 75.0, 'mem_crit': 90.0,
    'disk_warn': 80.0, 'disk_crit': 95.0,
    'email_to': '', 'email_notify': False,
}

_ICON_MAP = {'.txt':'📄','.log':'📝','.json':'🔍','.html':'🌐',
             '.csv':'📊','.xml':'📋','.zip':'📦','.tar':'📦','.gz':'📦','.pdf':'📕'}

_CATEGORY_MAP = {
    'detect_suspicious_net_linux':'network','secure_system':'security','revert_security':'security',
    'system_info':'system','forensic_collect':'forensic','web_recon':'recon',
    'network_tools':'network','core_protocols':'network','ip_addressing':'network',
    'network_master':'network','networking_basics':'network','switching_routing':'network',
    'security_fundamentals':'security',
}

if sys.version_info < (3, 8):
    sys.exit('Python 3.8+ required.')


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(DASHBOARD_DIR), **kw)

    def do_GET(self):
        p, qs = urlparse(self.path), parse_qs(urlparse(self.path).query)
        {
            '/api/dashboard-data': self._serve_dashboard_data,
            '/api/file':           lambda: self._serve_file(qs),
            '/api/search':         lambda: self._serve_search(qs),
            '/api/tail':           lambda: self._serve_tail(qs),
            '/api/metrics':        self._serve_metrics,
            '/api/categories':     self._serve_categories,
            '/api/system-stats':   self._serve_system_stats,
            '/api/alert-settings': lambda: self._json_response(200, {**_alert_cfg, 'smtp_configured': bool(SMTP_USER and SMTP_PASS)}),
        }.get(p.path, super().do_GET)()

    def do_POST(self):
        p = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        try:    payload = json.loads(self.rfile.read(length)) if length else {}
        except: payload = {}
        if p == '/api/notify-email':   self._handle_notify_email(payload)
        elif p == '/api/alert-settings': self._handle_alert_settings(payload)
        else:   self._send_error(404, 'Not found')

    def do_OPTIONS(self):
        self.send_response(204); self._add_sec(); self.end_headers()

    # ── Security headers ──────────────────────────────────────────────────────
    def _add_sec(self):
        for k, v in [
            ('X-Content-Type-Options','nosniff'), ('X-Frame-Options','DENY'),
            ('Referrer-Policy','strict-origin-when-cross-origin'),
            ('Access-Control-Allow-Origin', ALLOWED_ORIGIN),
            ('Access-Control-Allow-Methods','GET,POST,OPTIONS'),
            ('Access-Control-Allow-Headers','Content-Type'),
            ('Content-Security-Policy',
             "default-src 'self';style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;"
             "font-src 'self' https://fonts.gstatic.com;script-src 'self' 'unsafe-inline';"
             "connect-src 'self';img-src 'self' data:;frame-ancestors 'none';"),
        ]: self.send_header(k, v)

    def _add_security_headers(self): self._add_sec()

    # ── /api/dashboard-data ───────────────────────────────────────────────────
    def _serve_dashboard_data(self):
        try:
            h = self._get_history()
            self._json_response(200, {'logs': self._get_logs(), 'outputs': self._get_outputs(),
                                       'history': h, 'stats': self._calc_stats(h), 'timeline': h[:30]})
        except Exception as e:
            self._send_error(500, str(e))

    # ── /api/file ─────────────────────────────────────────────────────────────
    def _serve_file(self, qs):
        rd, rn = qs.get('dir',[''])[0], qs.get('name',[''])[0]
        bd = LOGS_DIR if rd == 'logs' else OUTPUT_DIR if rd == 'outputs' else None
        if not bd: return self._send_error(400, "dir must be 'logs' or 'outputs'")
        if not rn: return self._send_error(400, "Missing 'name'")
        safe = Path(rn).name
        if safe != rn: return self._send_error(400, 'name must be bare filename')
        fp = (bd / safe).resolve()
        try: fp.relative_to(bd.resolve())
        except ValueError: return self._send_error(403, 'Access denied')
        if not fp.is_file(): return self._send_error(404, 'Not found')
        try: content = fp.read_bytes()
        except OSError as e: return self._send_error(500, str(e))
        ct = {'.log':'text/plain;charset=utf-8','.txt':'text/plain;charset=utf-8',
              '.json':'application/json;charset=utf-8','.html':'text/html;charset=utf-8',
              '.csv':'text/csv;charset=utf-8','.xml':'application/xml;charset=utf-8'}.get(fp.suffix.lower(),'application/octet-stream')
        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(content)))
        if ct == 'application/octet-stream':
            self.send_header('Content-Disposition', f'attachment;filename="{safe}"')
        self._add_sec(); self.end_headers(); self.wfile.write(content)

    # ── /api/search ───────────────────────────────────────────────────────────
    def _serve_search(self, qs):
        q = qs.get('q',[''])[0].strip()
        limit = min(int((qs.get('limit',['50'])[0]) or 50), 200)
        if len(q) < 2: return self._json_response(200, {'results':[],'query':q,'total':0})
        pat, results = re.compile(re.escape(q), re.I), []
        if LOGS_DIR.is_dir():
            for f in sorted(LOGS_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.suffix != '.log' or not f.is_file(): continue
                try:
                    for no, line in enumerate(f.read_bytes()[:512_000].decode('utf-8',errors='replace').splitlines(),1):
                        if pat.search(line):
                            results.append({'file':f.name,'dir':'logs','line':no,'content':line.strip()[:200],'match':q})
                            if len(results) >= limit: break
                except OSError: continue
                if len(results) >= limit: break
        self._json_response(200, {'results':results,'query':q,'total':len(results)})

    # ── /api/tail ─────────────────────────────────────────────────────────────
    def _serve_tail(self, qs):
        rd, rn = qs.get('dir',['logs'])[0], qs.get('name',[''])[0]
        n = min(int((qs.get('lines',['100'])[0]) or 100), 1000)
        bd = LOGS_DIR if rd == 'logs' else OUTPUT_DIR
        if not rn: return self._send_error(400, "Missing 'name'")
        fp = (bd / Path(rn).name).resolve()
        try: fp.relative_to(bd.resolve())
        except ValueError: return self._send_error(403, 'Access denied')
        if not fp.is_file(): return self._send_error(404, 'Not found')
        try:
            lines = fp.read_bytes().decode('utf-8',errors='replace').splitlines()
            st = fp.stat()
            self._json_response(200, {'lines':lines[-n:],'total':len(lines),'returned':min(n,len(lines)),'size':st.st_size,'mtime':st.st_mtime,'name':fp.name})
        except OSError as e: self._send_error(500, str(e))

    # ── /api/metrics ──────────────────────────────────────────────────────────
    def _serve_metrics(self):
        h = self._get_history()
        by_day, by_cat, durs = defaultdict(lambda:{'success':0,'error':0,'warning':0,'total':0}), defaultdict(int), []
        for x in h:
            try: by_day[x['timestamp'][:10]][x.get('status','unknown')] += 1; by_day[x['timestamp'][:10]]['total'] += 1
            except: pass
            by_cat[x.get('category','other')] += 1
            m = re.match(r'(\d+)m\s*(\d+)s', x.get('duration',''))
            if m: durs.append(int(m.group(1))*60+int(m.group(2)))
        ls = sum(f.stat().st_size for f in LOGS_DIR.iterdir() if f.is_file()) if LOGS_DIR.is_dir() else 0
        os_ = sum(f.stat().st_size for f in OUTPUT_DIR.iterdir() if f.is_file()) if OUTPUT_DIR.is_dir() else 0
        self._json_response(200, {
            'by_day': dict(by_day), 'by_category': dict(by_cat),
            'avg_duration_s': int(sum(durs)/len(durs)) if durs else 0,
            'disk': {'logs_bytes':ls,'outputs_bytes':os_,'total_bytes':ls+os_},
            'success_rate': round(sum(1 for x in h if x['status']=='success')/len(h)*100,1) if h else 0,
        })

    def _serve_categories(self):
        self._json_response(200, {'categories': sorted({h.get('category','other') for h in self._get_history()})})

    # ── /api/system-stats (NEW) ───────────────────────────────────────────────
    def _serve_system_stats(self):
        if not HAS_PSUTIL:
            return self._json_response(200, {'available': False,
                'message': 'Run: pip install psutil --break-system-packages'})
        try:
            cpu  = psutil.cpu_percent(interval=0.5)
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net  = psutil.net_io_counters()
            temps = {}
            try:
                for name, entries in (psutil.sensors_temperatures() or {}).items():
                    if entries: temps[name] = round(entries[0].current, 1)
            except: pass

            def lvl(v, w, c): return 'critical' if v >= c else 'warning' if v >= w else 'ok'
            s = _alert_cfg
            stats = {
                'available': True, 'ts': datetime.now().isoformat(),
                'cpu':    {'percent': round(cpu,1), 'count': psutil.cpu_count(), 'level': lvl(cpu, s['cpu_warn'], s['cpu_crit'])},
                'memory': {'percent': round(mem.percent,1), 'used_mb': round(mem.used/1_048_576),
                           'total_mb': round(mem.total/1_048_576), 'avail_mb': round(mem.available/1_048_576),
                           'level': lvl(mem.percent, s['mem_warn'], s['mem_crit'])},
                'disk':   {'percent': round(disk.percent,1), 'used_gb': round(disk.used/1_073_741_824,2),
                           'total_gb': round(disk.total/1_073_741_824,2), 'free_gb': round(disk.free/1_073_741_824,2),
                           'level': lvl(disk.percent, s['disk_warn'], s['disk_crit'])},
                'network':{'bytes_sent': net.bytes_sent, 'bytes_recv': net.bytes_recv,
                           'packets_sent': net.packets_sent, 'packets_recv': net.packets_recv,
                           'errin': net.errin, 'errout': net.errout,
                           'level': 'critical' if (net.errin+net.errout) > 100 else 'ok'},
                'temperatures': temps,
                'thresholds': {k:v for k,v in s.items() if k not in ('email_to','email_notify')},
            }
            # Auto-alert on critical
            if s.get('email_notify') and s.get('email_to'):
                crits = [k for k in ('cpu','memory','disk') if stats[k]['level']=='critical']
                if crits: self._auto_alert(stats, crits)
            self._json_response(200, stats)
        except Exception as e:
            self._send_error(500, str(e))

    # ── /api/alert-settings POST ──────────────────────────────────────────────
    def _handle_alert_settings(self, payload):
        allowed = {'cpu_warn','cpu_crit','mem_warn','mem_crit','disk_warn','disk_crit','email_to','email_notify'}
        for k, v in payload.items():
            if k not in allowed: continue
            if k == 'email_to' and isinstance(v, str): _alert_cfg[k] = v.strip()
            elif k == 'email_notify' and isinstance(v, bool): _alert_cfg[k] = v
            elif k.endswith(('_warn','_crit')) and isinstance(v, (int,float)): _alert_cfg[k] = float(v)
        self._json_response(200, {'ok': True, 'settings': dict(_alert_cfg)})

    # ── /api/notify-email POST ────────────────────────────────────────────────
    def _handle_notify_email(self, payload):
        to = payload.get('to','').strip()
        if not to: return self._send_error(400, "Missing 'to'")
        if not (SMTP_USER and SMTP_PASS): return self._send_error(503, 'SMTP not configured. Set SMTP_USER and SMTP_PASS env vars.')
        ok, msg = self._smtp_send(to, payload.get('subject','CyberDeck Notification'), payload.get('body',''))
        if ok: self._json_response(200, {'sent': True, 'to': to})
        else:  self._send_error(500, f'Email failed: {msg}')

    def _smtp_send(self, to, subject, body):
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'], msg['From'], msg['To'] = subject, SMTP_FROM or SMTP_USER, to
            msg.attach(MIMEText(body, 'plain'))
            msg.attach(MIMEText(
                f'<html><body style="font-family:monospace;background:#0a0d14;color:#e2eaf7;padding:24px">'
                f'<h2 style="color:#38bdf8">⬡ CyberDeck</h2>'
                f'<pre style="background:#161c28;padding:16px;border-left:3px solid #38bdf8;border-radius:8px">{body}</pre>'
                f'<p style="color:#546278;font-size:12px">Networking & Cybersecurity Automation Toolkit</p></body></html>', 'html'))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
                s.ehlo(); s.starttls(); s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_FROM or SMTP_USER, to, msg.as_string())
            return True, 'ok'
        except Exception as e:
            return False, str(e)

    def _auto_alert(self, stats, crits):
        lines = [f'⚠ CRITICAL — {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n']
        for r in crits:
            lines.append(f'  {r.upper()}: {stats[r].get("percent","?")}%  [CRITICAL]')
        self._smtp_send(_alert_cfg['email_to'], f'CyberDeck CRITICAL — {", ".join(crits)}', '\n'.join(lines))

    # ── File helpers ──────────────────────────────────────────────────────────
    def _get_logs(self):
        if not LOGS_DIR.is_dir(): return []
        logs = []
        for e in LOGS_DIR.iterdir():
            if e.suffix != '.log' or not e.is_file(): continue
            m = re.match(r'(.+?)_(\d{8}_\d{6})\.log$', e.name)
            stem = m.group(1) if m else e.stem
            kws = ('network','protocol','addressing','basics','switching','security_fund','master')
            st = e.stat()
            logs.append({'name':e.name,'script':stem,'timestamp':datetime.fromtimestamp(st.st_mtime).isoformat(),
                         'size':st.st_size,'dir':'logs','name_param':e.name,
                         'source':'tool' if stem in _CATEGORY_MAP and any(k in stem for k in kws) else 'script',
                         'category':_CATEGORY_MAP.get(stem,'other')})
        return sorted(logs, key=lambda x: x['timestamp'], reverse=True)

    def _get_outputs(self):
        if not OUTPUT_DIR.is_dir(): return []
        out = []
        for e in OUTPUT_DIR.iterdir():
            if not e.is_file(): continue
            st = e.stat()
            out.append({'name':e.name,'icon':_ICON_MAP.get(e.suffix.lower(),'📄'),
                        'timestamp':datetime.fromtimestamp(st.st_mtime).isoformat(),
                        'size':st.st_size,'dir':'outputs','name_param':e.name,'ext':e.suffix.lower()})
        return sorted(out, key=lambda x: x['timestamp'], reverse=True)

    def _get_history(self):
        if not LOGS_DIR.is_dir(): return []
        hist = []
        for e in LOGS_DIR.iterdir():
            if e.suffix != '.log' or not e.is_file() or e.name == 'dashboard.log': continue
            m = re.match(r'(.+?)_(\d{8}_\d{6})\.log$', e.name)
            if not m: continue
            name = m.group(1)
            try:    ts = datetime.strptime(m.group(2), '%Y%m%d_%H%M%S')
            except: ts = datetime.fromtimestamp(e.stat().st_mtime)
            status, dur = self._parse_log(e)
            hist.append({'name':name,'log_name':e.name,'category':self._cat(name),
                         'status':status,'duration':dur,'timestamp':ts.isoformat(),'size':e.stat().st_size})
        return sorted(hist, key=lambda x: x['timestamp'], reverse=True)

    @staticmethod
    def _cat(name):
        if name in _CATEGORY_MAP: return _CATEGORY_MAP[name]
        n = name.lower()
        if any(k in n for k in ('net','network','protocol','routing','switching')): return 'network'
        if any(k in n for k in ('secure','security')): return 'security'
        if 'forensic' in n: return 'forensic'
        if any(k in n for k in ('recon','web')): return 'recon'
        if any(k in n for k in ('system','info')): return 'system'
        return 'other'

    @staticmethod
    def _parse_log(path):
        try: content = path.read_bytes()[:131_072].decode('utf-8', errors='replace')
        except: return 'unknown', 'N/A'
        m = re.search(r'exit code (\d+)', content)
        if m:   st = 'success' if m.group(1)=='0' else 'error'
        elif re.search(r'\berror\b|\bfailed\b|\btimed out\b', content, re.I): st = 'error'
        elif re.search(r'\bwarning\b|\bwarn\b', content, re.I): st = 'warning'
        else:   st = 'success'
        sm, em, dur = re.search(r'started at (.+?) ===', content), re.search(r'completed at (.+?) with', content), 'N/A'
        if sm and em:
            for fmt in ('%a %b %d %H:%M:%S %Z %Y','%a %b  %d %H:%M:%S %Z %Y','%a %b %d %H:%M:%S %Y'):
                try:
                    s, e = datetime.strptime(sm.group(1).strip(), fmt), datetime.strptime(em.group(1).strip(), fmt)
                    secs = int((e-s).total_seconds()); dur = f'{secs//60}m {secs%60}s'; break
                except: continue
        return st, dur

    @staticmethod
    def _calc_stats(h):
        return {'total':len(h),'successful':sum(1 for x in h if x['status']=='success'),
                'warnings':sum(1 for x in h if x['status']=='warning'),'failed':sum(1 for x in h if x['status']=='error')}

    def _json_response(self, code, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header('Content-Type','application/json;charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._add_sec(); self.end_headers(); self.wfile.write(body)

    def _send_error(self, code, msg): self._json_response(code, {'error': msg})

    def log_message(self, fmt, *a):
        print(f'[{datetime.now().strftime("%H:%M:%S")}] [{self.client_address[0]}] {fmt%a}')


class ReuseAddrServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    LOGS_DIR.mkdir(exist_ok=True); OUTPUT_DIR.mkdir(exist_ok=True)
    print('='*58, f'\n  CyberDeck Dashboard Server v3\n'+'='*58)
    if not HAS_PSUTIL:
        print('\n  ⚠  psutil missing — install: pip install psutil --break-system-packages\n')
    try: server = ReuseAddrServer(('', PORT), DashboardHandler)
    except OSError as e: sys.exit(f'Cannot bind port {PORT}: {e}')
    def _stop(sig, _): print(f'\nShutting down…'); server.shutdown()
    signal.signal(signal.SIGINT, _stop); signal.signal(signal.SIGTERM, _stop)
    print(f'  ✓  http://localhost:{PORT}')
    print(f'  ✓  psutil: {"available" if HAS_PSUTIL else "NOT installed"}')
    print(f'  ✓  SMTP:   {"configured" if SMTP_USER else "not configured (set SMTP_USER/SMTP_PASS)"}')
    print('='*58)
    server.serve_forever()

if __name__ == '__main__': main()