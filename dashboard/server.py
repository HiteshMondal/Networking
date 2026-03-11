#!/usr/bin/env python3
"""
CyberDeck Dashboard Server v4.0
Networking & Cybersecurity Automation Toolkit

Changes from v3.1:
  - Reads structured .jsonl logs (produced by lib/logging.sh) for rich metadata
  - Falls back to legacy .log parsing for backward compatibility
  - Alert thresholds boot from environment / settings.conf exports
  - /api/log-stream endpoint returns parsed JSON records (not raw text)
  - /api/findings endpoint aggregates log_finding() records
  - /api/sessions endpoint lists unique session IDs across runs
"""

import http.server
import json
import os
import re
import signal
import smtplib
import sys
from collections import defaultdict
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import socketserver

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

if sys.version_info < (3, 8):
    sys.exit("Python 3.8+ required.")

#  Config 

PORT           = int(os.environ.get("DASHBOARD_PORT", "8000"))
DASHBOARD_DIR  = Path(__file__).resolve().parent
PROJECT_ROOT   = DASHBOARD_DIR.parent
LOGS_DIR       = PROJECT_ROOT / "logs"
OUTPUT_DIR     = PROJECT_ROOT / "output"
ALLOWED_ORIGIN = os.environ.get("DASHBOARD_ORIGIN", "*")

# SMTP — loaded from environment only, never hardcoded
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

# Alert thresholds — seeded from settings.conf exports, editable via API
_alert_cfg = {
    "cpu_warn":      float(os.environ.get("ALERT_CPU_WARN",  "70")),
    "cpu_crit":      float(os.environ.get("ALERT_CPU_CRIT",  "90")),
    "mem_warn":      float(os.environ.get("ALERT_MEM_WARN",  "75")),
    "mem_crit":      float(os.environ.get("ALERT_MEM_CRIT",  "90")),
    "disk_warn":     float(os.environ.get("ALERT_DISK_WARN", "80")),
    "disk_crit":     float(os.environ.get("ALERT_DISK_CRIT", "95")),
    "email_to":      "",
    "email_notify":  False,
}

#  Static maps 

_ICON_MAP = {
    ".txt": "📄", ".log": "📝", ".jsonl": "🔍", ".json": "🔍",
    ".html": "🌐", ".csv": "📊", ".xml": "📋",
    ".zip": "📦", ".tar": "📦", ".gz": "📦",
    ".pdf": "📕", ".sh": "⚙",
}

_CATEGORY_MAP = {
    "detect_suspicious_net_linux": "network",
    "secure_system":               "security",
    "revert_security":             "security",
    "system_info":                 "system",
    "forensic_collect":            "forensic",
    "web_recon":                   "recon",
    "malware_analysis":            "security",
    "lateral_movement_detect":     "security",
    "log_analysis":                "system",
    "cloud_exposure_audit":        "network",
    "data_exfil_detect":           "security",
    "network_tools":               "network",
    "core_protocols":              "network",
    "ip_addressing":               "network",
    "network_master":              "network",
    "networking_basics":           "network",
    "switching_routing":           "network",
    "packet_analysis":             "network",
    "security_fundamentals":       "security",
    "wireless_security":           "security",
    "firewall_ids":                "security",
    "network_hardening":           "security",
    "threat_intelligence":         "security",
}

_TOOL_NAMES = {
    "network_tools", "core_protocols", "ip_addressing", "network_master",
    "networking_basics", "switching_routing", "packet_analysis",
    "security_fundamentals", "wireless_security", "firewall_ids",
    "network_hardening", "threat_intelligence",
}

#  Helpers 

def _stem_from_name(filename: str) -> str:
    """Extract module stem from a log filename.
    Handles:   module_20240118_120000.log   →  module
               module_20240118_120000.jsonl →  module
    """
    name = Path(filename).stem       # strip extension
    if name.endswith(".sh"):
        name = name[:-3]
    m = re.match(r"^(.+?)_(\d{8}_\d{6})$", name)
    return m.group(1) if m else name


def _category(name: str) -> str:
    if name in _CATEGORY_MAP:
        return _CATEGORY_MAP[name]
    n = name.lower()
    if any(k in n for k in ("net", "network", "protocol", "routing",
                              "switching", "packet", "ip_addr", "wireless")):
        return "network"
    if any(k in n for k in ("secure", "security", "firewall", "ids",
                              "hardening", "threat", "malware", "exfil",
                              "lateral", "cloud")):
        return "security"
    if "forensic" in n:
        return "forensic"
    if any(k in n for k in ("recon", "web")):
        return "recon"
    if any(k in n for k in ("system", "info", "log")):
        return "system"
    return "other"


#  JSON log parsing 

def _parse_jsonl(path: Path) -> list[dict]:
    """Parse a .jsonl file and return a list of log record dicts.
    Silently skips malformed lines."""
    records = []
    try:
        with path.open("r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return records


def _summarise_jsonl(path: Path) -> tuple[str, str, str | None]:
    """Return (status, duration, session_id) derived from a .jsonl file."""
    records = _parse_jsonl(path)
    if not records:
        return "unknown", "N/A", None

    session_id = records[0].get("session")

    # Derive status from highest-severity level seen
    levels = [r.get("level", "").upper() for r in records]
    if "CRITICAL" in levels or "ERROR" in levels:
        status = "error"
    elif "WARNING" in levels:
        status = "warning"
    else:
        status = "success"

    # Also honour any explicit exit_code in a data field
    for r in reversed(records):
        ec = r.get("data", {}).get("exit_code")
        if ec is not None:
            status = "success" if str(ec) == "0" else "error"
            break

    # Duration: diff between first and last timestamp
    def _parse_ts(s: str) -> datetime | None:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except (ValueError, TypeError):
                continue
        return None

    first_ts = _parse_ts(records[0].get("timestamp", ""))
    last_ts  = _parse_ts(records[-1].get("timestamp", ""))
    duration = "N/A"
    if first_ts and last_ts:
        secs = int((last_ts - first_ts).total_seconds())
        duration = f"{secs // 60}m {secs % 60}s"

    return status, duration, session_id


def _parse_legacy_log(path: Path) -> tuple[str, str]:
    """Parse a legacy .log file (plain text). Returns (status, duration)."""
    try:
        content = path.read_bytes()[:131_072].decode("utf-8", errors="replace")
    except OSError:
        return "unknown", "N/A"

    m = re.search(r"exit code (\d+)", content)
    if m:
        status = "success" if m.group(1) == "0" else "error"
    elif re.search(r"\berror\b|\bfailed\b|\btimed out\b", content, re.I):
        status = "error"
    elif re.search(r"\bwarning\b|\bwarn\b", content, re.I):
        status = "warning"
    else:
        status = "success"

    sm  = re.search(r"started at (.+?) ===", content)
    em  = re.search(r"completed at (.+?) \(exit", content)
    dur = "N/A"
    if sm and em:
        for fmt in (
            "%a %b %d %H:%M:%S %Z %Y",
            "%a %b  %d %H:%M:%S %Z %Y",
            "%a %b %d %H:%M:%S %Y",
        ):
            try:
                s = datetime.strptime(sm.group(1).strip(), fmt)
                e = datetime.strptime(em.group(1).strip(), fmt)
                secs = int((e - s).total_seconds())
                dur = f"{secs // 60}m {secs % 60}s"
                break
            except ValueError:
                continue

    return status, dur


#  Request handler 

class DashboardHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(DASHBOARD_DIR), **kw)

    #  Routing 

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)
        routes = {
            "/api/dashboard-data":  self._serve_dashboard_data,
            "/api/file":            lambda: self._serve_file(qs),
            "/api/search":          lambda: self._serve_search(qs),
            "/api/tail":            lambda: self._serve_tail(qs),
            "/api/metrics":         self._serve_metrics,
            "/api/categories":      self._serve_categories,
            "/api/system-stats":    self._serve_system_stats,
            "/api/alert-settings":  lambda: self._json(200, {
                **_alert_cfg,
                "smtp_configured": bool(SMTP_USER and SMTP_PASS),
            }),
            #  New v4 endpoints 
            "/api/log-stream":      lambda: self._serve_log_stream(qs),
            "/api/findings":        self._serve_findings,
            "/api/sessions":        self._serve_sessions,
        }
        routes.get(p.path, super().do_GET)()

    def do_POST(self):
        p      = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            payload = {}

        if p == "/api/notify-email":
            self._handle_notify_email(payload)
        elif p == "/api/alert-settings":
            self._handle_alert_settings(payload)
        else:
            self._err(404, "Not found")

    def do_OPTIONS(self):
        self.send_response(204)
        self._sec()
        self.end_headers()

    #  Security headers 

    def _sec(self):
        for k, v in [
            ("X-Content-Type-Options",  "nosniff"),
            ("X-Frame-Options",          "DENY"),
            ("Referrer-Policy",          "strict-origin-when-cross-origin"),
            ("Access-Control-Allow-Origin",  ALLOWED_ORIGIN),
            ("Access-Control-Allow-Methods", "GET,POST,OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type"),
            (
                "Content-Security-Policy",
                "default-src 'self';"
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;"
                "font-src 'self' https://fonts.gstatic.com;"
                "script-src 'self' 'unsafe-inline';"
                "connect-src 'self';"
                "img-src 'self' data:;"
                "frame-ancestors 'none';",
            ),
        ]:
            self.send_header(k, v)

    #  /api/dashboard-data 

    def _serve_dashboard_data(self):
        try:
            h = self._history()
            self._json(200, {
                "logs":     self._logs(),
                "outputs":  self._outputs(),
                "history":  h,
                "stats":    self._stats(h),
                "timeline": h[:30],
            })
        except Exception as exc:
            self._err(500, str(exc))

    #  /api/log-stream  (NEW) 
    # Returns parsed JSON records from a .jsonl file.
    # Query params: dir=logs&name=<filename>&limit=200

    def _serve_log_stream(self, qs: dict):
        rd   = qs.get("dir",   ["logs"])[0]
        rn   = qs.get("name",  [""])[0]
        limit = min(int(qs.get("limit", ["200"])[0] or 200), 2000)
        bd    = LOGS_DIR if rd == "logs" else OUTPUT_DIR

        if not rn:
            return self._err(400, "Missing 'name'")

        fp = (bd / rn).resolve()
        try:
            fp.relative_to(bd.resolve())
        except ValueError:
            return self._err(403, "Access denied")

        if not fp.is_file():
            return self._err(404, "Not found")

        if fp.suffix == ".jsonl":
            records = _parse_jsonl(fp)[-limit:]
        else:
            # Wrap legacy log lines as minimal JSON records
            try:
                lines = fp.read_bytes().decode("utf-8", errors="replace").splitlines()
            except OSError as exc:
                return self._err(500, str(exc))
            records = [
                {"level": "INFO", "message": ln, "timestamp": "", "data": {}}
                for ln in lines[-limit:]
            ]

        self._json(200, {"records": records, "total": len(records), "file": rn})

    #  /api/findings  (NEW) 
    # Aggregates log_finding() records from all .jsonl files.

    def _serve_findings(self):
        findings: list[dict] = []
        if not LOGS_DIR.is_dir():
            return self._json(200, {"findings": [], "total": 0})

        for f in sorted(LOGS_DIR.rglob("*.jsonl"),
                         key=lambda x: x.stat().st_mtime, reverse=True):
            if not f.is_file():
                continue
            for r in _parse_jsonl(f):
                data = r.get("data", {})
                if "finding_severity" in data:
                    findings.append({
                        "timestamp":  r.get("timestamp", ""),
                        "module":     r.get("module", "unknown"),
                        "session":    r.get("session", ""),
                        "severity":   data.get("finding_severity", "info"),
                        "title":      data.get("finding_title", ""),
                        "detail":     data.get("finding_detail", ""),
                    })
            if len(findings) >= 500:
                break

        # Sort by severity weight then timestamp
        _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: (_sev.get(x["severity"], 5), x["timestamp"]))
        self._json(200, {"findings": findings, "total": len(findings)})

    #  /api/sessions  (NEW) 
    # Returns a list of unique session IDs with their run summary.

    def _serve_sessions(self):
        sessions: dict[str, dict] = {}
        if not LOGS_DIR.is_dir():
            return self._json(200, {"sessions": []})

        for f in LOGS_DIR.rglob("*.jsonl"):
            if not f.is_file():
                continue
            records = _parse_jsonl(f)
            if not records:
                continue
            sid = records[0].get("session", "unknown")
            if sid not in sessions:
                sessions[sid] = {
                    "session":    sid,
                    "started":    records[0].get("timestamp", ""),
                    "modules":    [],
                    "run_count":  0,
                    "error_count": 0,
                }
            stem = _stem_from_name(f.name)
            sessions[sid]["modules"].append(stem)
            sessions[sid]["run_count"] += 1
            levels = {r.get("level", "") for r in records}
            if "ERROR" in levels or "CRITICAL" in levels:
                sessions[sid]["error_count"] += 1

        result = sorted(sessions.values(), key=lambda x: x["started"], reverse=True)
        self._json(200, {"sessions": result, "total": len(result)})

    #  /api/file 

    def _serve_file(self, qs: dict):
        rd = qs.get("dir",  [""])[0]
        rn = qs.get("name", [""])[0]
        bd = LOGS_DIR if rd == "logs" else OUTPUT_DIR if rd == "outputs" else None
        if bd is None:
            return self._err(400, "dir must be 'logs' or 'outputs'")
        if not rn:
            return self._err(400, "Missing 'name'")
        fp = (bd / rn).resolve()
        try:
            fp.relative_to(bd.resolve())
        except ValueError:
            return self._err(403, "Access denied")
        if not fp.is_file():
            return self._err(404, "Not found")
        try:
            content = fp.read_bytes()
        except OSError as exc:
            return self._err(500, str(exc))

        ct = {
            ".log":   "text/plain;charset=utf-8",
            ".jsonl": "application/x-ndjson;charset=utf-8",
            ".txt":   "text/plain;charset=utf-8",
            ".json":  "application/json;charset=utf-8",
            ".html":  "text/html;charset=utf-8",
            ".csv":   "text/csv;charset=utf-8",
            ".xml":   "application/xml;charset=utf-8",
        }.get(fp.suffix.lower(), "application/octet-stream")

        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(content)))
        if ct == "application/octet-stream":
            self.send_header("Content-Disposition",
                             f'attachment;filename="{fp.name}"')
        self._sec()
        self.end_headers()
        self.wfile.write(content)

    #  /api/search 

    def _serve_search(self, qs: dict):
        q     = qs.get("q", [""])[0].strip()
        limit = min(int(qs.get("limit", ["50"])[0] or 50), 200)
        if len(q) < 2:
            return self._json(200, {"results": [], "query": q, "total": 0})

        pat, results = re.compile(re.escape(q), re.I), []
        if LOGS_DIR.is_dir():
            for f in sorted(LOGS_DIR.rglob("*"),
                             key=lambda x: x.stat().st_mtime, reverse=True):
                if not f.is_file() or f.suffix not in (".log", ".jsonl"):
                    continue
                try:
                    for no, line in enumerate(
                        f.read_bytes()[:512_000]
                         .decode("utf-8", errors="replace")
                         .splitlines(), 1
                    ):
                        if pat.search(line):
                            rel = str(f.relative_to(LOGS_DIR))
                            results.append({
                                "file":    rel,
                                "dir":     "logs",
                                "line":    no,
                                "content": line.strip()[:200],
                                "match":   q,
                                "is_json": f.suffix == ".jsonl",
                            })
                            if len(results) >= limit:
                                break
                except OSError:
                    continue
                if len(results) >= limit:
                    break

        self._json(200, {"results": results, "query": q, "total": len(results)})

    #  /api/tail 

    def _serve_tail(self, qs: dict):
        rd = qs.get("dir",   ["logs"])[0]
        rn = qs.get("name",  [""])[0]
        n  = min(int(qs.get("lines", ["100"])[0] or 100), 1000)
        bd = LOGS_DIR if rd == "logs" else OUTPUT_DIR
        if not rn:
            return self._err(400, "Missing 'name'")
        fp = (bd / rn).resolve()
        try:
            fp.relative_to(bd.resolve())
        except ValueError:
            return self._err(403, "Access denied")
        if not fp.is_file():
            return self._err(404, "Not found")
        try:
            raw   = fp.read_bytes().decode("utf-8", errors="replace")
            lines = raw.splitlines()
            st    = fp.stat()
            self._json(200, {
                "lines":    lines[-n:],
                "total":    len(lines),
                "returned": min(n, len(lines)),
                "size":     st.st_size,
                "mtime":    st.st_mtime,
                "name":     fp.name,
                "is_jsonl": fp.suffix == ".jsonl",
            })
        except OSError as exc:
            self._err(500, str(exc))

    #  /api/metrics 

    def _serve_metrics(self):
        h      = self._history()
        by_day = defaultdict(lambda: {"success": 0, "error": 0, "warning": 0, "total": 0})
        by_cat = defaultdict(int)
        durs   = []

        for x in h:
            try:
                day = x["timestamp"][:10]
                by_day[day][x.get("status", "unknown")] += 1
                by_day[day]["total"] += 1
            except Exception:
                pass
            by_cat[x.get("category", "other")] += 1
            m = re.match(r"(\d+)m\s*(\d+)s", x.get("duration", ""))
            if m:
                durs.append(int(m.group(1)) * 60 + int(m.group(2)))

        ls  = sum(f.stat().st_size for f in LOGS_DIR.rglob("*")   if f.is_file()) if LOGS_DIR.is_dir()   else 0
        os_ = sum(f.stat().st_size for f in OUTPUT_DIR.rglob("*") if f.is_file()) if OUTPUT_DIR.is_dir() else 0

        self._json(200, {
            "by_day":          dict(by_day),
            "by_category":     dict(by_cat),
            "avg_duration_s":  int(sum(durs) / len(durs)) if durs else 0,
            "disk": {
                "logs_bytes":    ls,
                "outputs_bytes": os_,
                "total_bytes":   ls + os_,
            },
            "success_rate": round(
                sum(1 for x in h if x["status"] == "success") / len(h) * 100, 1
            ) if h else 0,
        })

    #  /api/categories 

    def _serve_categories(self):
        self._json(200, {
            "categories": sorted({h.get("category", "other") for h in self._history()})
        })

    #  /api/system-stats 

    def _serve_system_stats(self):
        if not HAS_PSUTIL:
            return self._json(200, {
                "available": False,
                "message":   "Run: pip install psutil --break-system-packages",
            })
        try:
            cpu  = psutil.cpu_percent(interval=0.5)
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net  = psutil.net_io_counters()
            temps: dict = {}
            try:
                for name, entries in (psutil.sensors_temperatures() or {}).items():
                    if entries:
                        temps[name] = round(entries[0].current, 1)
            except Exception:
                pass

            def lvl(v: float, w: float, c: float) -> str:
                return "critical" if v >= c else "warning" if v >= w else "ok"

            s = _alert_cfg
            stats = {
                "available": True,
                "ts":        datetime.now().isoformat(),
                "cpu": {
                    "percent": round(cpu, 1),
                    "count":   psutil.cpu_count(),
                    "level":   lvl(cpu, s["cpu_warn"], s["cpu_crit"]),
                },
                "memory": {
                    "percent":  round(mem.percent, 1),
                    "used_mb":  round(mem.used      / 1_048_576),
                    "total_mb": round(mem.total     / 1_048_576),
                    "avail_mb": round(mem.available / 1_048_576),
                    "level":    lvl(mem.percent, s["mem_warn"], s["mem_crit"]),
                },
                "disk": {
                    "percent":  round(disk.percent, 1),
                    "used_gb":  round(disk.used  / 1_073_741_824, 2),
                    "total_gb": round(disk.total / 1_073_741_824, 2),
                    "free_gb":  round(disk.free  / 1_073_741_824, 2),
                    "level":    lvl(disk.percent, s["disk_warn"], s["disk_crit"]),
                },
                "network": {
                    "bytes_sent":   net.bytes_sent,
                    "bytes_recv":   net.bytes_recv,
                    "packets_sent": net.packets_sent,
                    "packets_recv": net.packets_recv,
                    "errin":        net.errin,
                    "errout":       net.errout,
                    "level": "critical" if (net.errin + net.errout) > 100 else "ok",
                },
                "temperatures": temps,
                "thresholds":   {k: v for k, v in s.items()
                                 if k not in ("email_to", "email_notify")},
            }

            if s.get("email_notify") and s.get("email_to"):
                crits = [k for k in ("cpu", "memory", "disk")
                         if stats[k]["level"] == "critical"]
                if crits:
                    self._auto_alert(stats, crits)

            self._json(200, stats)
        except Exception as exc:
            self._err(500, str(exc))

    #  /api/alert-settings POST 

    def _handle_alert_settings(self, payload: dict):
        allowed = {"cpu_warn", "cpu_crit", "mem_warn", "mem_crit",
                   "disk_warn", "disk_crit", "email_to", "email_notify"}
        for k, v in payload.items():
            if k not in allowed:
                continue
            if k == "email_to" and isinstance(v, str):
                _alert_cfg[k] = v.strip()
            elif k == "email_notify" and isinstance(v, bool):
                _alert_cfg[k] = v
            elif k.endswith(("_warn", "_crit")) and isinstance(v, (int, float)):
                _alert_cfg[k] = float(v)
        self._json(200, {"ok": True, "settings": dict(_alert_cfg)})

    #  /api/notify-email POST 

    def _handle_notify_email(self, payload: dict):
        to = payload.get("to", "").strip()
        if not to:
            return self._err(400, "Missing 'to'")
        if not (SMTP_USER and SMTP_PASS):
            return self._err(503, "SMTP not configured. Set SMTP_USER and SMTP_PASS env vars.")
        ok, msg = self._smtp_send(
            to,
            payload.get("subject", "CyberDeck Notification"),
            payload.get("body", ""),
        )
        if ok:
            self._json(200, {"sent": True, "to": to})
        else:
            self._err(500, f"Email failed: {msg}")

    #  Data builders 

    def _logs(self) -> list[dict]:
        """Return metadata for all log files (.log and .jsonl), newest first."""
        if not LOGS_DIR.is_dir():
            return []
        result = []
        seen_stems: set[str] = set()

        # Prefer .jsonl over .log for the same module run
        for suffix in (".jsonl", ".log"):
            for f in LOGS_DIR.rglob(f"*{suffix}"):
                if not f.is_file() or f.name in ("dashboard.log", "toolkit.jsonl"):
                    continue
                stem = _stem_from_name(f.name)
                key  = f"{stem}_{f.stat().st_mtime}"
                if key in seen_stems:
                    continue
                seen_stems.add(key)
                st  = f.stat()
                rel = str(f.relative_to(LOGS_DIR))
                result.append({
                    "name":       f.name,
                    "script":     stem,
                    "timestamp":  datetime.fromtimestamp(st.st_mtime).isoformat(),
                    "size":       st.st_size,
                    "dir":        "logs",
                    "name_param": rel,
                    "source":     "tool" if stem in _TOOL_NAMES else "script",
                    "category":   _category(stem),
                    "log_format": "jsonl" if suffix == ".jsonl" else "legacy",
                })

        return sorted(result, key=lambda x: x["timestamp"], reverse=True)

    def _outputs(self) -> list[dict]:
        if not OUTPUT_DIR.is_dir():
            return []
        out = []
        for f in OUTPUT_DIR.rglob("*"):
            if not f.is_file():
                continue
            st  = f.stat()
            rel = str(f.relative_to(OUTPUT_DIR))
            out.append({
                "name":       rel if "/" in rel else f.name,
                "icon":       _ICON_MAP.get(f.suffix.lower(), "📄"),
                "timestamp":  datetime.fromtimestamp(st.st_mtime).isoformat(),
                "size":       st.st_size,
                "dir":        "outputs",
                "name_param": rel,
                "ext":        f.suffix.lower(),
                "subdir":     f.parent.name if f.parent != OUTPUT_DIR else "",
            })
        return sorted(out, key=lambda x: x["timestamp"], reverse=True)

    def _history(self) -> list[dict]:
        if not LOGS_DIR.is_dir():
            return []
        hist = []
        processed: set[str] = set()

        # Process .jsonl first (richer metadata), then .log as fallback
        for suffix in (".jsonl", ".log"):
            for f in LOGS_DIR.rglob(f"*{suffix}"):
                if not f.is_file() or f.name in ("dashboard.log", "toolkit.jsonl"):
                    continue

                stem = _stem_from_name(f.name)
                # Deduplicate: skip .log if we already have a .jsonl for this run
                run_key = f.stem  # e.g. malware_analysis_20240118_120000
                if run_key in processed:
                    continue
                processed.add(run_key)

                # Timestamp from filename or mtime
                m = re.match(r"^(.+?)_(\d{8}_\d{6})(?:\.sh)?$", Path(f.name).stem)
                ts = datetime.fromtimestamp(f.stat().st_mtime)
                if m:
                    try:
                        ts = datetime.strptime(m.group(2), "%Y%m%d_%H%M%S")
                    except ValueError:
                        pass

                if suffix == ".jsonl":
                    status, dur, session_id = _summarise_jsonl(f)
                else:
                    status, dur = _parse_legacy_log(f)
                    session_id  = None

                rel = str(f.relative_to(LOGS_DIR))
                hist.append({
                    "name":       stem,
                    "log_name":   rel,
                    "category":   _category(stem),
                    "source":     "tool" if stem in _TOOL_NAMES else "script",
                    "status":     status,
                    "duration":   dur,
                    "timestamp":  ts.isoformat(),
                    "size":       f.stat().st_size,
                    "session":    session_id,
                    "log_format": "jsonl" if suffix == ".jsonl" else "legacy",
                })

        return sorted(hist, key=lambda x: x["timestamp"], reverse=True)

    @staticmethod
    def _stats(h: list[dict]) -> dict:
        return {
            "total":      len(h),
            "successful": sum(1 for x in h if x["status"] == "success"),
            "warnings":   sum(1 for x in h if x["status"] == "warning"),
            "failed":     sum(1 for x in h if x["status"] == "error"),
        }

    #  SMTP 

    def _smtp_send(self, to: str, subject: str, body: str) -> tuple[bool, str]:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = SMTP_FROM or SMTP_USER
            msg["To"]      = to
            msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(
                f'<html><body style="font-family:monospace;background:#0a0d14;color:#e2eaf7;padding:24px">'
                f'<h2 style="color:#38bdf8">⬡ CyberDeck</h2>'
                f'<pre style="background:#161c28;padding:16px;border-left:3px solid #38bdf8;'
                f'border-radius:8px">{body}</pre>'
                f'<p style="color:#546278;font-size:12px">Networking &amp; Cybersecurity '
                f'Automation Toolkit</p></body></html>', "html",
            ))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
                s.ehlo(); s.starttls(); s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_FROM or SMTP_USER, to, msg.as_string())
            return True, "ok"
        except Exception as exc:
            return False, str(exc)

    def _auto_alert(self, stats: dict, crits: list[str]):
        lines = [f"⚠ CRITICAL — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"]
        for r in crits:
            lines.append(f"  {r.upper()}: {stats[r].get('percent', '?')}%  [CRITICAL]")
        self._smtp_send(
            _alert_cfg["email_to"],
            f"CyberDeck CRITICAL — {', '.join(crits)}",
            "\n".join(lines),
        )

    #  Response helpers 

    def _json(self, code: int, data):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json;charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._sec()
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code: int, msg: str):
        self._json(code, {"error": msg})

    def log_message(self, fmt, *a):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [{self.client_address[0]}] {fmt % a}")


#  Server 

class ReuseAddrServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    LOGS_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)

    banner = "=" * 58
    print(f"\n{banner}")
    print("  CyberDeck Dashboard Server v4.0")
    print(f"  JSON structured logs: enabled")
    print(f"  psutil:               {'available' if HAS_PSUTIL else 'NOT installed'}")
    print(f"  SMTP:                 {'configured' if SMTP_USER else 'not configured'}")
    print(f"  Alert thresholds:     CPU>{_alert_cfg['cpu_crit']}%  "
          f"MEM>{_alert_cfg['mem_crit']}%  DISK>{_alert_cfg['disk_crit']}%")
    print(banner)

    if not HAS_PSUTIL:
        print("\n  ⚠  pip install psutil --break-system-packages\n")

    try:
        server = ReuseAddrServer(("", PORT), DashboardHandler)
    except OSError as exc:
        sys.exit(f"Cannot bind port {PORT}: {exc}")

    def _stop(sig, _):
        print("\nShutting down…")
        server.shutdown()

    signal.signal(signal.SIGINT,  _stop)
    signal.signal(signal.SIGTERM, _stop)
    print(f"\n  ✓  http://localhost:{PORT}\n{banner}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()