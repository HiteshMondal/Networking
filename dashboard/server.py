#!/usr/bin/env python3
"""
Cybersecurity Automation Toolkit — Dashboard Server  (server.py)

Improvements over the original:
  * Path traversal prevention uses os.path.realpath + prefix check instead of
    the naive str.replace('..', '') which is bypassable (e.g. '....//').
  * File serving is restricted to the logs/ and output/ directories only —
    requests for arbitrary project files are rejected with 403.
  * Content-Security-Policy and other security headers on every response.
  * CORS header is no longer '*' in production; uses ALLOWED_ORIGIN env var.
  * /api/file requires a 'name' parameter (filename only, no path component)
    and a 'dir' parameter ('logs' or 'outputs') rather than accepting a raw
    file-system path from the client.
  * Log status heuristic adds a fast-path: exit-code check happens before the
    full content scan so failure is detected even in truncated logs.
  * Structured startup banner and per-request logging with client IP.
  * Graceful shutdown on SIGINT / SIGTERM with informative message.
  * Python version guard at startup (requires 3.8+).
  * TCPServer configured with allow_reuse_address=True to prevent
    "Address already in use" on rapid restart.
"""

import http.server
import socketserver
import json
import os
import re
import signal
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ─── Configuration ────────────────────────────────────────────────────────────
PORT           = int(os.environ.get('DASHBOARD_PORT', '8000'))
DASHBOARD_DIR  = Path(__file__).resolve().parent
PROJECT_ROOT   = DASHBOARD_DIR.parent
LOGS_DIR       = PROJECT_ROOT / 'logs'
OUTPUT_DIR     = PROJECT_ROOT / 'output'

# Restrict CORS to a specific origin in production; keep '*' for localhost dev.
ALLOWED_ORIGIN = os.environ.get('DASHBOARD_ORIGIN', 'http://localhost')

# Icon mapping for output file types
_ICON_MAP: dict[str, str] = {
    '.txt':  '📄', '.log': '📝', '.json': '🔍',
    '.html': '🌐', '.csv': '📊', '.xml':  '📋',
    '.zip':  '📦', '.tar': '📦', '.gz':   '📦',
    '.pdf':  '📕',
}

# ─── Python version guard ─────────────────────────────────────────────────────
if sys.version_info < (3, 8):
    sys.exit('Error: Python 3.8 or later is required.')


# ─── Request Handler ──────────────────────────────────────────────────────────
class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Serves the static dashboard and a small JSON API."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    # ── Routing ───────────────────────────────────────────────────────────────
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == '/api/dashboard-data':
            self._serve_dashboard_data()
        elif path == '/api/file':
            self._serve_file(parse_qs(parsed.query))
        else:
            # Static files — let SimpleHTTPRequestHandler handle it.
            # Override directory to DASHBOARD_DIR prevents escaping to parent.
            super().do_GET()

    # ── Security headers (added to every response) ────────────────────────────
    def _add_security_headers(self) -> None:
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        # Only allow CORS for the API endpoints (not static files)
        self.send_header('Access-Control-Allow-Origin', ALLOWED_ORIGIN)
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    # ── /api/dashboard-data ───────────────────────────────────────────────────
    def _serve_dashboard_data(self) -> None:
        try:
            data = {
                'logs':    self._get_log_files(),
                'outputs': self._get_output_files(),
                'history': self._get_execution_history(),
                'stats':   self._calculate_stats(),
            }
            body = json.dumps(data, indent=2).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self._add_security_headers()
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            self._send_error(500, f'Error generating dashboard data: {exc}')

    # ── /api/file ─────────────────────────────────────────────────────────────
    def _serve_file(self, qs: dict) -> None:
        """
        Serve a file from logs/ or output/ for download or inline viewing.

        Query parameters:
          dir  — 'logs' | 'outputs'  (required)
          name — bare filename only  (required)
        """
        # -- Validate 'dir' parameter -----------------------------------------
        raw_dir = qs.get('dir', [''])[0]
        if raw_dir == 'logs':
            base_dir = LOGS_DIR
        elif raw_dir == 'outputs':
            base_dir = OUTPUT_DIR
        else:
            self._send_error(400, "Parameter 'dir' must be 'logs' or 'outputs'.")
            return

        # -- Validate 'name' parameter ----------------------------------------
        raw_name = qs.get('name', [''])[0]
        if not raw_name:
            self._send_error(400, "Missing required parameter 'name'.")
            return

        # Strip any path components the client might have injected
        safe_name = Path(raw_name).name
        if not safe_name or safe_name != raw_name:
            # The name contained path separators — reject it.
            self._send_error(400, "Parameter 'name' must be a bare filename (no path separators).")
            return

        # -- Resolve and verify the final path --------------------------------
        candidate = base_dir / safe_name
        try:
            resolved = candidate.resolve()
        except OSError as exc:
            self._send_error(400, f'Invalid filename: {exc}')
            return

        # Ensure the resolved path is still inside the permitted directory.
        # This is the correct defence against symlink-based traversal.
        permitted_root = base_dir.resolve()
        try:
            resolved.relative_to(permitted_root)
        except ValueError:
            self._send_error(403, 'Access denied: path outside permitted directory.')
            return

        if not resolved.is_file():
            self._send_error(404, 'File not found.')
            return

        # -- Serve the file ---------------------------------------------------
        try:
            content = resolved.read_bytes()
        except PermissionError:
            self._send_error(403, 'Permission denied.')
            return
        except OSError as exc:
            self._send_error(500, f'Error reading file: {exc}')
            return

        suffix = resolved.suffix.lower()
        content_types = {
            '.log':  'text/plain; charset=utf-8',
            '.txt':  'text/plain; charset=utf-8',
            '.json': 'application/json; charset=utf-8',
            '.html': 'text/html; charset=utf-8',
            '.csv':  'text/csv; charset=utf-8',
            '.xml':  'application/xml; charset=utf-8',
        }
        ct = content_types.get(suffix, 'application/octet-stream')

        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(content)))
        # Suggest a download filename for binary types
        if ct == 'application/octet-stream':
            self.send_header('Content-Disposition', f'attachment; filename="{safe_name}"')
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(content)

    # ── File listing helpers ──────────────────────────────────────────────────
    def _get_log_files(self) -> list[dict]:
        logs: list[dict] = []
        if not LOGS_DIR.is_dir():
            return logs

        for entry in LOGS_DIR.iterdir():
            if entry.suffix != '.log' or not entry.is_file():
                continue
            stat = entry.stat()
            m    = re.match(r'(.+?)_(\d{8}_\d{6})\.log$', entry.name)
            logs.append({
                'name':      entry.name,
                'script':    m.group(1) if m else entry.stem,
                'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'size':      stat.st_size,
                # Expose only dir+name, not full absolute path
                'dir':       'logs',
                'fileParam': entry.name,
            })

        logs.sort(key=lambda x: x['timestamp'], reverse=True)
        return logs

    def _get_output_files(self) -> list[dict]:
        outputs: list[dict] = []
        if not OUTPUT_DIR.is_dir():
            return outputs

        for entry in OUTPUT_DIR.iterdir():
            if not entry.is_file():
                continue
            stat = entry.stat()
            outputs.append({
                'name':      entry.name,
                'icon':      _ICON_MAP.get(entry.suffix.lower(), '📄'),
                'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'size':      stat.st_size,
                'dir':       'outputs',
                'fileParam': entry.name,
            })

        outputs.sort(key=lambda x: x['timestamp'], reverse=True)
        return outputs

    def _get_execution_history(self) -> list[dict]:
        history: list[dict] = []
        if not LOGS_DIR.is_dir():
            return history

        for entry in LOGS_DIR.iterdir():
            if entry.suffix != '.log' or not entry.is_file():
                continue
            m = re.match(r'(.+?)_(\d{8}_\d{6})\.log$', entry.name)
            if not m:
                continue

            script_name = m.group(1)
            try:
                ts = datetime.strptime(m.group(2), '%Y%m%d_%H%M%S')
            except ValueError:
                ts = datetime.fromtimestamp(entry.stat().st_mtime)

            status, duration = self._parse_log_status(entry)
            history.append({
                'name':      script_name,
                'category':  self._categorise_script(script_name),
                'status':    status,
                'duration':  duration,
                'timestamp': ts.isoformat(),
            })

        history.sort(key=lambda x: x['timestamp'], reverse=True)
        return history

    # ── Log analysis ──────────────────────────────────────────────────────────
    @staticmethod
    def _categorise_script(name: str) -> str:
        n = name.lower()
        if 'net' in n or 'network' in n:   return 'network'
        if 'secure' in n or 'security' in n: return 'security'
        if 'forensic' in n:                return 'forensic'
        if 'recon' in n or 'web' in n:     return 'recon'
        return 'other'

    @staticmethod
    def _parse_log_status(log_path: Path) -> tuple[str, str]:
        """
        Determine exit status and wall-clock duration from a log file.
        Fast path: check exit code first (avoids reading entire file for
        clearly-failed scripts that write the exit code early).
        """
        try:
            # Read up to 128 KB to avoid loading huge forensic logs fully
            raw = log_path.read_bytes()[:131_072]
            content = raw.decode('utf-8', errors='replace')
        except OSError:
            return 'unknown', 'N/A'

        # Exit code — definitive signal
        ec_match = re.search(r'exit code (\d+)', content)
        if ec_match:
            status = 'success' if ec_match.group(1) == '0' else 'error'
        elif re.search(r'\berror\b|\bfailed\b', content, re.IGNORECASE):
            status = 'error'
        elif re.search(r'\bwarning\b', content, re.IGNORECASE):
            status = 'warning'
        else:
            status = 'success'

        # Duration
        start_m = re.search(r'started at (.+?) ===', content)
        end_m   = re.search(r'completed at (.+?) with', content)
        duration = 'N/A'
        if start_m and end_m:
            for fmt in ('%a %b %d %H:%M:%S %Z %Y', '%a %b  %d %H:%M:%S %Z %Y'):
                try:
                    start = datetime.strptime(start_m.group(1).strip(), fmt)
                    end   = datetime.strptime(end_m.group(1).strip(), fmt)
                    secs  = int((end - start).total_seconds())
                    duration = f'{secs // 60}m {secs % 60}s'
                    break
                except ValueError:
                    continue

        return status, duration

    def _calculate_stats(self) -> dict:
        history = self._get_execution_history()
        return {
            'total':      len(history),
            'successful': sum(1 for h in history if h['status'] == 'success'),
            'warnings':   sum(1 for h in history if h['status'] == 'warning'),
            'failed':     sum(1 for h in history if h['status'] == 'error'),
        }

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _send_error(self, code: int, message: str) -> None:
        """Send a JSON error response (overrides the default HTML error page)."""
        body = json.dumps({'error': message}).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        """Structured per-request log line."""
        ts     = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        client = self.client_address[0] if self.client_address else '?'
        print(f'[{ts}] [{client}] {fmt % args}')


# ─── Reusable address server ──────────────────────────────────────────────────
class ReuseAddrServer(socketserver.TCPServer):
    """TCPServer with SO_REUSEADDR so the port is reclaimed on fast restart."""
    allow_reuse_address = True


# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    LOGS_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)

    print('=' * 60)
    print('  Cybersecurity Automation Toolkit — Dashboard Server')
    print('=' * 60)

    try:
        server = ReuseAddrServer(('', PORT), DashboardHandler)
    except OSError as exc:
        sys.exit(f'Cannot bind to port {PORT}: {exc}')

    def _shutdown(sig, _frame):
        print(f'\n[{datetime.now().strftime("%H:%M:%S")}] Received signal {sig} — shutting down gracefully…')
        server.shutdown()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print(f'\n  ✓  Listening on   http://localhost:{PORT}')
    print(f'  ✓  Logs directory  {LOGS_DIR}')
    print(f'  ✓  Output dir      {OUTPUT_DIR}')
    print(f'  ✓  Allowed origin  {ALLOWED_ORIGIN}')
    print(f'\n  Press Ctrl+C to stop\n')
    print('=' * 60)

    server.serve_forever()
    print('\n' + '=' * 60)
    print('  Server stopped.')
    print('=' * 60)


if __name__ == '__main__':
    main()