'use strict';

//  State
let dashboardData = {
    logs: [], outputs: [], history: [],
    stats: { total: 0, successful: 0, warnings: 0, failed: 0 },
    timeline: [],
};
let metricsData         = null;
let sysStatsData        = null;
let findingsData        = [];
let sessionsData        = [];
let currentLogFile      = null;
let currentLogRecords   = null; // parsed .jsonl records
let currentViewMode     = 'raw'; // 'raw' | 'parsed'
let tailInterval        = null;
let tailLastMtime       = 0;
let sysStatsInterval    = null;
let autoRefreshOn       = sessionStorage.getItem('autoRefresh') !== 'false';
let refreshTimer        = null;
let searchDebounceTimer = null;
let activeTab           = 'all';
let activeOutputGroup   = 'all';
let activeFindingSev    = 'all';

const REFRESH_MS   = 30_000;
const TAIL_POLL_MS = 3_000;
const SYS_POLL_MS  = 5_000;

//  Bootstrap
document.addEventListener('DOMContentLoaded', () => {
    loadDashboardData();
    loadMetrics();
    loadSystemStats();
    loadFindings();
    loadSessions();
    applyAutoRefreshState();

    // Modal backdrop click
    ['logModal', 'shareModal', 'alertModal', 'findingModal'].forEach(id => {
        document.getElementById(id)?.addEventListener('click', e => {
            if (e.target === e.currentTarget) {
                if (id === 'logModal')     closeModal();
                if (id === 'shareModal')   closeShareModal();
                if (id === 'alertModal')   closeAlertModal();
                if (id === 'findingModal') closeFindingModal();
            }
        });
    });

    // Global search
    const searchEl = document.getElementById('globalSearch');
    if (searchEl) {
        searchEl.addEventListener('input', () => {
            clearTimeout(searchDebounceTimer);
            searchDebounceTimer = setTimeout(() => runSearch(searchEl.value), 350);
        });
        searchEl.addEventListener('keydown', e => {
            if (e.key === 'Escape') { searchEl.value = ''; clearSearchResults(); }
        });
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') { closeModal(); closeShareModal(); closeAlertModal(); closeFindingModal(); }
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') { e.preventDefault(); refreshDashboard(); }
        if ((e.ctrlKey || e.metaKey) && e.key === 'f') { e.preventDefault(); document.getElementById('globalSearch')?.focus(); }
    });

    sysStatsInterval = setInterval(loadSystemStats, SYS_POLL_MS);
});

//  Data Loading
async function loadDashboardData() {
    try {
        const res = await fetch('/api/dashboard-data');
        if (res.ok) dashboardData = await res.json();
        else loadDemoData();
    } catch { loadDemoData(); }
    updateDashboard();
}

async function loadMetrics() {
    try {
        const res = await fetch('/api/metrics');
        if (res.ok) { metricsData = await res.json(); renderMetrics(); }
    } catch {}
}

async function loadSystemStats() {
    try {
        const res = await fetch('/api/system-stats');
        if (res.ok) { sysStatsData = await res.json(); renderSystemStats(); }
    } catch {}
}

async function loadFindings() {
    try {
        const res = await fetch('/api/findings');
        if (res.ok) {
            const data = await res.json();
            findingsData = data.findings ?? [];
            renderFindings(findingsData);
        }
    } catch {
        renderFindings([]);
    }
}

async function loadSessions() {
    try {
        const res = await fetch('/api/sessions');
        if (res.ok) {
            const data = await res.json();
            sessionsData = data.sessions ?? [];
            renderSessions(sessionsData);
        }
    } catch {
        renderSessions([]);
    }
}

function loadDemoData() {
    const scripts = ['detect_suspicious_net_linux', 'system_info', 'secure_system', 'forensic_collect', 'web_recon'];
    const tools   = ['network_tools', 'core_protocols', 'ip_addressing', 'networking_basics', 'security_fundamentals'];
    const all     = [...scripts, ...tools];
    dashboardData = {
        logs: all.map((s, i) => ({
            name: `${s}_20240118_12000${i}.log`,
            script: s,
            timestamp: new Date(Date.now() - i * 3_600_000).toISOString(),
            size: Math.floor(Math.random() * 50_000) + 1_000,
            dir: 'logs', name_param: `${s}_20240118_12000${i}.log`,
            source: tools.includes(s) ? 'tool' : 'script',
            category: tools.includes(s) ? 'network' : 'security',
            log_format: i % 3 === 0 ? 'jsonl' : 'legacy',
        })),
        outputs: [
            { name: 'suspicious_scan/ps_aux.txt',          icon: '📄', size: 15_234, dir: 'outputs', name_param: 'suspicious_scan/ps_aux.txt',          subdir: 'suspicious_scan', timestamp: new Date(Date.now() - 3_600_000).toISOString() },
            { name: 'exfil_detect/dns_tunnelling.txt',     icon: '📄', size: 8_765,  dir: 'outputs', name_param: 'exfil_detect/dns_tunnelling.txt',     subdir: 'exfil_detect',   timestamp: new Date(Date.now() - 7_200_000).toISOString() },
            { name: 'log_analysis/log_inventory.txt',      icon: '📄', size: 5_432,  dir: 'outputs', name_param: 'log_analysis/log_inventory.txt',      subdir: 'log_analysis',   timestamp: new Date(Date.now() - 10_800_000).toISOString() },
            { name: 'malware_analysis/run_timestamp.txt',  icon: '📄', size: 128,    dir: 'outputs', name_param: 'malware_analysis/run_timestamp.txt',  subdir: 'malware_analysis', timestamp: new Date(Date.now() - 14_400_000).toISOString() },
        ],
        history: all.slice(0, 8).map((s, i) => ({
            name: s, log_name: `${s}_20240118_12000${i}.log`,
            category: tools.includes(s) ? 'network' : ['security', 'forensic', 'recon'][i % 3],
            source: tools.includes(s) ? 'tool' : 'script',
            status: ['success', 'success', 'warning', 'error', 'success'][i % 5],
            duration: `${Math.floor(Math.random() * 5)}m ${Math.floor(Math.random() * 59)}s`,
            timestamp: new Date(Date.now() - i * 7_200_000).toISOString(),
            size: Math.floor(Math.random() * 60_000) + 500,
            log_format: i % 3 === 0 ? 'jsonl' : 'legacy',
        })),
        stats: { total: 18, successful: 14, warnings: 2, failed: 2 },
        timeline: [],
    };

    // Demo findings
    findingsData = [
        { severity: 'critical', title: 'Root shell detected', detail: 'PID 4412 — /bin/bash -i listening on :4444', module: 'detect_suspicious_net', timestamp: new Date(Date.now() - 1_800_000).toISOString(), session: 'sess_demo_001' },
        { severity: 'high',     title: 'UPX packer detected', detail: '/tmp/payload — entropy 7.9', module: 'malware_analysis', timestamp: new Date(Date.now() - 3_600_000).toISOString(), session: 'sess_demo_001' },
        { severity: 'high',     title: 'Suspicious outbound connection', detail: '10.0.0.5:31337 → 185.220.101.45:443', module: 'detect_suspicious_net', timestamp: new Date(Date.now() - 5_400_000).toISOString(), session: 'sess_demo_001' },
        { severity: 'medium',   title: 'World-writable cron job', detail: '/etc/cron.d/backup is mode 0777', module: 'secure_system', timestamp: new Date(Date.now() - 7_200_000).toISOString(), session: 'sess_demo_002' },
        { severity: 'medium',   title: 'SSH root login enabled', detail: 'PermitRootLogin yes in /etc/ssh/sshd_config', module: 'secure_system', timestamp: new Date(Date.now() - 9_000_000).toISOString(), session: 'sess_demo_002' },
        { severity: 'low',      title: 'Outdated kernel version', detail: 'Running 5.15.0-89, latest is 5.15.0-101', module: 'system_info', timestamp: new Date(Date.now() - 10_800_000).toISOString(), session: 'sess_demo_002' },
        { severity: 'info',     title: 'Cloud metadata accessible', detail: 'AWS IMDS reachable at 169.254.169.254', module: 'cloud_exposure_audit', timestamp: new Date(Date.now() - 12_600_000).toISOString(), session: 'sess_demo_003' },
    ];
    renderFindings(findingsData);

    // Demo sessions
    sessionsData = [
        { session: 'sess_20240118_120000_1234', started: new Date(Date.now() - 3_600_000).toISOString(), modules: ['detect_suspicious_net', 'malware_analysis', 'forensic_collect'], run_count: 3, error_count: 1 },
        { session: 'sess_20240117_090000_5678', started: new Date(Date.now() - 90_000_000).toISOString(), modules: ['secure_system', 'system_info', 'web_recon', 'log_analysis'], run_count: 4, error_count: 0 },
        { session: 'sess_20240116_150000_9012', started: new Date(Date.now() - 180_000_000).toISOString(), modules: ['network_tools', 'core_protocols'], run_count: 2, error_count: 0 },
    ];
    renderSessions(sessionsData);
}

//  Master Update
function updateDashboard() {
    updateStats();
    updateLogFiles();
    updateOutputFiles();
    updateHistory();
    updateLastUpdate();
    updateDiskWidget();
}

//  Stats
function updateStats() {
    const { total = 0, successful = 0, warnings = 0, failed = 0 } = dashboardData.stats ?? {};
    animateCount('totalScans',      total);
    animateCount('successfulScans', successful);
    animateCount('warningScans',    warnings);
    animateCount('failedScans',     failed);
    const s = total || 1;
    setBarWidth('barTotal',   100);
    setBarWidth('barSuccess', (successful / s) * 100);
    setBarWidth('barWarning', (warnings   / s) * 100);
    setBarWidth('barFailed',  (failed     / s) * 100);
}

function animateCount(id, target) {
    const el = document.getElementById(id); if (!el) return;
    const start = parseInt(el.textContent, 10) || 0; if (start === target) return;
    const dur = 700, t0 = performance.now();
    const step = ts => {
        const p = Math.min((ts - t0) / dur, 1);
        el.textContent = Math.round(start + (target - start) * easeOut(p));
        if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}
function easeOut(t) { return 1 - (1 - t) ** 3; }
function setBarWidth(id, pct) {
    const el = document.getElementById(id);
    if (el) el.style.width = Math.min(Math.max(pct, 0), 100) + '%';
}

//  System Stats
function renderSystemStats() {
    const d = sysStatsData;
    if (!d?.available) {
        const panel = document.getElementById('sysStatsPanel');
        if (panel) panel.innerHTML = `<div class="sys-unavailable">⚠ Install psutil: <code>pip install psutil --break-system-packages</code></div>`;
        return;
    }
    updateSysMeter('cpu',  d.cpu?.percent,    d.cpu?.level,    `${d.cpu?.count} cores`);
    updateSysMeter('mem',  d.memory?.percent, d.memory?.level, `${formatFileSize((d.memory?.used_mb ?? 0) * 1_048_576)} / ${formatFileSize((d.memory?.total_mb ?? 0) * 1_048_576)}`);
    updateSysMeter('disk', d.disk?.percent,   d.disk?.level,   `${d.disk?.free_gb?.toFixed(1)} GB free`);
    updateNetStats(d.network);
    renderTemperatures(d.temperatures);
    ['cpu', 'memory', 'disk'].forEach(k => {
        if (d[k]?.level === 'critical') triggerAlert(k, d[k]);
    });
}

function updateSysMeter(key, pct, level, subtitle) {
    const K = cap(key);
    setText(`sys${K}Pct`, (pct ?? 0).toFixed(1) + '%');
    const barEl  = document.getElementById(`sys${K}Bar`);
    const subEl  = document.getElementById(`sys${K}Sub`);
    const cardEl = document.getElementById(`sysCard${K}`);
    if (barEl)  { barEl.style.width = (pct ?? 0) + '%'; barEl.className = `sys-bar-fill level-${level ?? 'ok'}`; }
    if (subEl)  subEl.textContent = subtitle ?? '';
    if (cardEl) cardEl.className = `sys-card level-${level ?? 'ok'}`;
}

function updateNetStats(net) {
    if (!net) return;
    setText('sysNetSent',   formatFileSize(net.bytes_sent ?? 0));
    setText('sysNetRecv',   formatFileSize(net.bytes_recv ?? 0));
    setText('sysNetErrors', (net.errin ?? 0) + (net.errout ?? 0));
    const badge = document.getElementById('sysNetErrBadge');
    if (badge) {
        const errs = (net.errin ?? 0) + (net.errout ?? 0);
        badge.textContent = errs > 0 ? `${errs} err` : 'OK';
        badge.style.color = errs > 0 ? 'var(--amber)' : 'var(--text-muted)';
    }
    const cardEl = document.getElementById('sysCardNet');
    if (cardEl) cardEl.className = `sys-card level-${net.level ?? 'ok'}`;
}

function renderTemperatures(temps) {
    const el = document.getElementById('sysTemps'); if (!el) return;
    if (!temps || !Object.keys(temps).length) { el.textContent = '—'; return; }
    el.innerHTML = Object.entries(temps).map(([k, v]) =>
        `<span class="temp-chip">${escHtml(k)}: <strong>${v}°C</strong></span>`
    ).join('');
}

let _lastAlertKey = '';
function triggerAlert(key, data) {
    const alertKey = `${key}-${data.percent}`;
    if (alertKey === _lastAlertKey) return;
    _lastAlertKey = alertKey;
    showToast(`⚠ CRITICAL: ${key.toUpperCase()} at ${data.percent}%`, 'error');
}

//  Metrics
function renderMetrics() {
    if (!metricsData) return;
    const rateEl = document.getElementById('successRate');
    if (rateEl) {
        const rate = metricsData.success_rate ?? 0;
        rateEl.textContent = rate + '%';
        const ring = document.getElementById('successRing');
        if (ring) { const c = 2 * Math.PI * 28; ring.style.strokeDasharray = c; ring.style.strokeDashoffset = c * (1 - rate / 100); }
    }
    const avgEl = document.getElementById('avgDuration');
    if (avgEl) { const s = metricsData.avg_duration_s ?? 0; avgEl.textContent = s > 0 ? `${Math.floor(s / 60)}m ${s % 60}s` : '—'; }
    renderCategoryChart(metricsData.by_category ?? {});
    renderTimeline(metricsData.by_day ?? {});
    updateDiskWidget();
}

function renderCategoryChart(byCategory) {
    const container = document.getElementById('categoryChart'); if (!container) return;
    const entries = Object.entries(byCategory).sort((a, b) => b[1] - a[1]);
    const max = entries[0]?.[1] || 1;
    const colors = { network: 'var(--cyan)', security: 'var(--green)', forensic: 'var(--amber)', recon: 'var(--violet)', system: 'var(--teal)', other: 'var(--text-muted)' };
    container.innerHTML = '';
    entries.forEach(([cat, count]) => {
        const pct = (count / max) * 100, row = document.createElement('div');
        row.className = 'chart-row';
        row.innerHTML = `<span class="chart-label">${escHtml(cat)}</span>
          <div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${colors[cat] || 'var(--cyan)'}"></div></div>
          <span class="chart-count">${count}</span>`;
        container.appendChild(row);
    });
}

// Canvas-based sparkline timeline
function renderTimeline(byDay) {
    const canvas = document.getElementById('timelineCanvas');
    const labelsEl = document.getElementById('timelineLabels');
    if (!canvas) return;

    // Build last-7-days buckets
    const days = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date(); d.setDate(d.getDate() - i);
        days.push(d.toISOString().slice(0, 10));
    }
    const values = days.map(d => (byDay[d]?.total ?? 0));
    const maxVal = Math.max(...values, 1);

    const dpr = window.devicePixelRatio || 1;
    const W   = canvas.offsetWidth  || 240;
    const H   = canvas.offsetHeight || 56;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    const pad  = 4;
    const step = (W - pad * 2) / Math.max(values.length - 1, 1);

    // Gradient fill
    const grad = ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, 'rgba(56,189,248,0.25)');
    grad.addColorStop(1, 'rgba(56,189,248,0)');

    // Points
    const pts = values.map((v, i) => ({
        x: pad + i * step,
        y: pad + (1 - v / maxVal) * (H - pad * 2.5),
    }));

    // Fill area
    ctx.beginPath();
    ctx.moveTo(pts[0].x, H);
    pts.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(pts[pts.length - 1].x, H);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    pts.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
    ctx.strokeStyle = 'var(--cyan)';
    ctx.lineWidth   = 1.5;
    ctx.lineJoin    = 'round';
    ctx.stroke();

    // Dots
    pts.forEach((p, i) => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, values[i] > 0 ? 2.5 : 1.5, 0, Math.PI * 2);
        ctx.fillStyle = values[i] > 0 ? 'var(--cyan)' : 'var(--border-2)';
        ctx.fill();
    });

    // Labels (Mon, Tue…)
    if (labelsEl) {
        const shortDays = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
        labelsEl.innerHTML = days.map(d => {
            const dayName = shortDays[new Date(d + 'T12:00:00').getDay()];
            return `<span>${dayName}</span>`;
        }).join('');
    }
}

function updateDiskWidget() {
    const disk = metricsData?.disk; if (!disk) return;
    setText('diskLogs',    formatFileSize(disk.logs_bytes    ?? 0));
    setText('diskOutputs', formatFileSize(disk.outputs_bytes ?? 0));
    setText('diskTotal',   formatFileSize(disk.total_bytes   ?? 0));
}

//  Findings Panel (NEW)
const _SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const _SEV_COLOR  = { critical: 'var(--red)', high: 'var(--amber)', medium: 'var(--violet)', low: 'var(--teal)', info: 'var(--text-muted)' };
const _SEV_ICON   = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ' };
const _SEV_LABEL  = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };

function filterFindings() {
    const sel = document.getElementById('findingSevFilter');
    activeFindingSev = sel?.value ?? 'all';
    const filtered = activeFindingSev === 'all'
        ? findingsData
        : findingsData.filter(f => f.severity === activeFindingSev);
    renderFindings(filtered);
}

function renderFindings(findings) {
    const container = document.getElementById('findingsBody');
    const countBadge = document.getElementById('findingsCount');
    if (countBadge) countBadge.textContent = `${findings.length} finding${findings.length !== 1 ? 's' : ''}`;

    // Severity summary chips
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => { if (f.severity in sevCounts) sevCounts[f.severity]++; });

    if (!findings.length) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-glyph" aria-hidden="true">⚑</div>
                <p>${activeFindingSev !== 'all' ? `No ${activeFindingSev} findings.` : 'No findings yet. Run security modules to populate.'}</p>
            </div>`;
        return;
    }

    const frag = document.createDocumentFragment();

    // Severity summary bar
    const summaryBar = document.createElement('div');
    summaryBar.className = 'findings-summary';
    summaryBar.innerHTML = Object.entries(sevCounts)
        .filter(([, c]) => c > 0)
        .map(([sev, count]) => `
            <button class="sev-chip sev-${sev}" onclick="quickFilterSev('${sev}')" title="Filter to ${sev}">
                ${_SEV_ICON[sev]} ${count} ${_SEV_LABEL[sev]}
            </button>`)
        .join('');
    frag.appendChild(summaryBar);

    // Finding rows
    const list = document.createElement('div');
    list.className = 'findings-list';
    findings.forEach((finding, idx) => {
        const row = document.createElement('div');
        row.className = `finding-row finding-${finding.severity}`;
        row.setAttribute('tabindex', '0');
        row.setAttribute('aria-label', `${finding.severity} finding: ${finding.title}`);

        const handleOpen = () => openFindingDetail(finding);
        row.addEventListener('click', handleOpen);
        row.addEventListener('keydown', e => { if (e.key === 'Enter') handleOpen(); });

        row.innerHTML = `
            <div class="finding-sev-bar"></div>
            <div class="finding-icon">${_SEV_ICON[finding.severity]}</div>
            <div class="finding-content">
                <div class="finding-title">${escHtml(finding.title)}</div>
                <div class="finding-detail">${escHtml(finding.detail)}</div>
                <div class="finding-meta">
                    <span class="finding-module">${escHtml(finding.module ?? '—')}</span>
                    <span class="finding-sep">·</span>
                    <time>${formatTimestampText(finding.timestamp)}</time>
                    ${finding.session ? `<span class="finding-sep">·</span><span class="finding-session">${escHtml(finding.session.slice(-8))}</span>` : ''}
                </div>
            </div>
            <div class="finding-sev-badge sev-badge-${finding.severity}">${_SEV_LABEL[finding.severity]}</div>
            <div class="finding-arrow">›</div>`;
        list.appendChild(row);
    });
    frag.appendChild(list);
    container.replaceChildren(frag);
}

function quickFilterSev(sev) {
    const sel = document.getElementById('findingSevFilter');
    if (sel) sel.value = sev;
    activeFindingSev = sev;
    filterFindings();
}

function openFindingDetail(finding) {
    const modal = document.getElementById('findingModal');
    const title = document.getElementById('findingModalTitle');
    const body  = document.getElementById('findingDetailBody');
    if (!modal || !body) return;
    title.textContent = finding.title;
    const col = _SEV_COLOR[finding.severity] || 'var(--text-muted)';
    body.innerHTML = `
        <div class="finding-detail-header" style="border-left: 3px solid ${col}">
            <span class="fdd-icon">${_SEV_ICON[finding.severity]}</span>
            <div>
                <div class="fdd-sev" style="color:${col}">${_SEV_LABEL[finding.severity]}</div>
                <div class="fdd-module">${escHtml(finding.module ?? '—')}</div>
            </div>
        </div>
        <div class="finding-detail-section">
            <div class="fdd-label">Detail</div>
            <div class="fdd-value">${escHtml(finding.detail)}</div>
        </div>
        <div class="finding-detail-section">
            <div class="fdd-label">Session</div>
            <div class="fdd-value mono">${escHtml(finding.session ?? '—')}</div>
        </div>
        <div class="finding-detail-section">
            <div class="fdd-label">Timestamp</div>
            <div class="fdd-value mono">${finding.timestamp ? new Date(finding.timestamp).toLocaleString() : '—'}</div>
        </div>`;
    modal.classList.add('active');
    trapFocus(modal);
}

function closeFindingModal() { document.getElementById('findingModal')?.classList.remove('active'); }

//  Sessions Panel (NEW)
function renderSessions(sessions) {
    const container  = document.getElementById('sessionsBody');
    const countBadge = document.getElementById('sessionsCount');
    if (countBadge) countBadge.textContent = sessions.length;

    if (!sessions.length) {
        container.innerHTML = `<div class="empty-state"><div class="empty-glyph">◈</div><p>No sessions recorded yet.</p></div>`;
        return;
    }

    const frag = document.createDocumentFragment();
    sessions.forEach(sess => {
        const item = document.createElement('div');
        item.className = 'session-item';
        const hasErrors = sess.error_count > 0;
        item.innerHTML = `
            <div class="session-header">
                <span class="session-id mono">${escHtml(sess.session.slice(-12))}</span>
                <span class="session-status ${hasErrors ? 'sev-badge-high' : 'sev-badge-ok'}">
                    ${hasErrors ? `${sess.error_count} err` : '✓ clean'}
                </span>
            </div>
            <div class="session-modules">
                ${(sess.modules ?? []).slice(0, 5).map(m => `<span class="session-module-chip">${escHtml(m)}</span>`).join('')}
                ${sess.modules?.length > 5 ? `<span class="session-module-more">+${sess.modules.length - 5} more</span>` : ''}
            </div>
            <div class="session-meta">
                <span>${sess.run_count} run${sess.run_count !== 1 ? 's' : ''}</span>
                <span class="finding-sep">·</span>
                <time>${formatTimestampText(sess.started)}</time>
            </div>`;
        frag.appendChild(item);
    });
    container.replaceChildren(frag);
}

//  Log Files
function updateLogFiles(filterTab) {
    activeTab = filterTab ?? activeTab;
    const container  = document.getElementById('logFiles');
    const countBadge = document.getElementById('logCount');
    let logs = dashboardData.logs ?? [];
    if      (activeTab === 'scripts') logs = logs.filter(l => l.source === 'script');
    else if (activeTab === 'tools')   logs = logs.filter(l => l.source === 'tool');
    else if (activeTab === 'jsonl')   logs = logs.filter(l => l.log_format === 'jsonl');
    countBadge.textContent = `${logs.length} file${logs.length !== 1 ? 's' : ''}`;
    document.querySelectorAll('.log-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === activeTab));
    if (!logs.length) {
        container.replaceChildren(buildEmptyState('◫', `No ${activeTab === 'all' ? '' : activeTab + ' '}log files found.`));
        return;
    }
    const frag = document.createDocumentFragment();
    logs.forEach(log => {
        const item = document.createElement('div');
        item.className = 'log-item'; item.setAttribute('role', 'listitem');
        item.setAttribute('tabindex', '0');
        item.addEventListener('click',   () => openLog(log));
        item.addEventListener('keydown', e => { if (e.key === 'Enter') openLog(log); });

        const typeTag = document.createElement('span');
        typeTag.className = `log-type-tag type-${sanitizeClass(log.source ?? 'script')}`;
        typeTag.textContent = log.source === 'tool' ? 'TOOL' : 'SCRIPT';

        // Format badge
        const fmtTag = document.createElement('span');
        fmtTag.className = `log-fmt-tag ${log.log_format === 'jsonl' ? 'fmt-jsonl' : 'fmt-log'}`;
        fmtTag.textContent = log.log_format === 'jsonl' ? 'JSON' : 'LOG';

        const info = document.createElement('div'); info.className = 'log-info';
        const name = document.createElement('div'); name.className = 'log-name'; name.textContent = log.name ?? 'unknown';
        const meta = document.createElement('div'); meta.className = 'log-meta';
        const catSpan = document.createElement('span');
        catSpan.className = `cat-badge-sm cat-${sanitizeClass(log.category ?? 'other')}`;
        catSpan.textContent = log.category ?? 'other';
        meta.appendChild(catSpan); meta.appendChild(document.createTextNode(' '));
        meta.appendChild(buildTimeEl(log.timestamp));
        meta.appendChild(document.createTextNode(` · ${formatFileSize(log.size ?? 0)}`));
        info.appendChild(name); info.appendChild(meta);

        const actions = document.createElement('div'); actions.className = 'log-actions';
        const tailBtn  = makeBtn('⟳', 'Live tail', e => { e.stopPropagation(); openTail(log); });
        const dlBtn    = makeBtn('↓', 'Download',  e => { e.stopPropagation(); downloadFile(log); });
        const shareBtn = makeBtn('↗', 'Share',     e => { e.stopPropagation(); openShareModal(log); });
        actions.appendChild(tailBtn); actions.appendChild(dlBtn); actions.appendChild(shareBtn);
        item.appendChild(typeTag); item.appendChild(fmtTag); item.appendChild(info); item.appendChild(actions);
        frag.appendChild(item);
    });
    container.replaceChildren(frag);
}

function makeBtn(text, title, handler) {
    const b = document.createElement('button'); b.className = 'btn btn-ghost btn-sm';
    b.title = title; b.textContent = text; b.addEventListener('click', handler); return b;
}

//  Output Files
function updateOutputFiles() {
    const outputs    = dashboardData.outputs ?? [];
    const countBadge = document.getElementById('outputCount');
    countBadge.textContent = `${outputs.length} file${outputs.length !== 1 ? 's' : ''}`;
    const groupSelect = document.getElementById('outputGroupFilter');
    if (groupSelect) {
        const groups = [...new Set(outputs.map(f => f.subdir || '(root)'))].sort();
        const existing = [...groupSelect.options].map(o => o.value);
        groups.forEach(g => {
            if (!existing.includes(g)) {
                const opt = document.createElement('option'); opt.value = g; opt.textContent = g; groupSelect.appendChild(opt);
            }
        });
    }
    renderOutputFiles(outputs);
}

function filterOutputFiles() {
    const sel = document.getElementById('outputGroupFilter');
    activeOutputGroup = sel?.value ?? 'all';
    const outputs = dashboardData.outputs ?? [];
    const filtered = activeOutputGroup === 'all' ? outputs : outputs.filter(f => (f.subdir || '(root)') === activeOutputGroup);
    renderOutputFiles(filtered);
}

function renderOutputFiles(outputs) {
    const container = document.getElementById('outputFiles');
    if (!outputs.length) { container.replaceChildren(buildEmptyState('◫', 'No output files found.')); return; }
    const groups = {};
    outputs.forEach(f => { const key = f.subdir || '(root)'; (groups[key] = groups[key] || []).push(f); });
    const frag = document.createDocumentFragment();
    Object.entries(groups).sort(([a], [b]) => a.localeCompare(b)).forEach(([groupName, files]) => {
        const header = document.createElement('div'); header.className = 'output-group-header';
        header.innerHTML = `<span class="output-group-icon">📁</span><span class="output-group-name">${escHtml(groupName)}</span><span class="output-group-count">${files.length} file${files.length !== 1 ? 's' : ''}</span>`;
        frag.appendChild(header);
        files.forEach(file => {
            const item = document.createElement('div');
            item.className = 'file-item'; item.setAttribute('role', 'listitem'); item.setAttribute('tabindex', '0');
            item.title = `${file.name} — ${formatFileSize(file.size ?? 0)}`;
            item.addEventListener('click',   () => openOutputFile(file));
            item.addEventListener('keydown', e => { if (e.key === 'Enter') openOutputFile(file); });
            const icon   = document.createElement('div'); icon.className = 'file-icon'; icon.setAttribute('aria-hidden', 'true'); icon.textContent = file.icon ?? '📄';
            const nameEl = document.createElement('div'); nameEl.className = 'file-name'; nameEl.textContent = file.name.split('/').pop() ?? '—';
            const meta   = document.createElement('div'); meta.className = 'file-meta'; meta.appendChild(document.createTextNode(formatFileSize(file.size ?? 0)));
            const tsEl = document.createElement('div'); tsEl.className = 'file-ts'; tsEl.appendChild(buildTimeEl(file.timestamp)); meta.appendChild(tsEl);
            const btnRow  = document.createElement('div'); btnRow.className = 'file-btn-row';
            const viewBtn = document.createElement('button'); viewBtn.className = 'btn btn-ghost btn-sm file-view-btn'; viewBtn.textContent = '👁 View'; viewBtn.title = 'View file'; viewBtn.addEventListener('click', e => { e.stopPropagation(); openOutputFile(file); });
            const shareBtn = document.createElement('button'); shareBtn.className = 'btn btn-ghost btn-sm file-share-btn'; shareBtn.textContent = '↗'; shareBtn.title = 'Share'; shareBtn.addEventListener('click', e => { e.stopPropagation(); openShareModal(file); });
            btnRow.appendChild(viewBtn); btnRow.appendChild(shareBtn);
            item.appendChild(icon); item.appendChild(nameEl); item.appendChild(meta); item.appendChild(btnRow);
            frag.appendChild(item);
        });
    });
    container.replaceChildren(frag);
}

function openOutputFile(fileObj) {
    stopTail(); currentLogFile = fileObj;
    showModal(fileObj.name, fileObj.dir ?? 'outputs', fileObj.name_param ?? fileObj.name, null);
}

//  History
function updateHistory() { renderHistoryRows(dashboardData.history ?? []); }

function filterHistory() {
    const cat    = document.getElementById('scriptFilter')?.value ?? 'all';
    const status = document.getElementById('statusFilter')?.value ?? 'all';
    const src    = document.getElementById('sourceFilter')?.value ?? 'all';
    let f = dashboardData.history ?? [];
    if (cat    !== 'all') f = f.filter(i => i.category === cat);
    if (status !== 'all') f = f.filter(i => i.status   === status);
    if (src    !== 'all') f = f.filter(i => (i.source ?? 'script') === src);
    renderHistoryRows(f);
}

function renderHistoryRows(items) {
    const tbody = document.getElementById('historyTable');
    if (!items?.length) {
        const tr = document.createElement('tr'), td = document.createElement('td');
        td.setAttribute('colspan', '9'); td.className = 'empty-row'; td.textContent = 'No matching results';
        tr.appendChild(td); tbody.replaceChildren(tr); return;
    }
    const frag = document.createDocumentFragment();
    items.forEach(item => {
        const tr = document.createElement('tr');
        const cells = [
            () => { const td = document.createElement('td'); td.appendChild(buildTimeEl(item.timestamp)); return td; },
            () => { const td = document.createElement('td'); td.className = 'td-script'; td.textContent = item.name ?? '—'; return td; },
            () => {
                const td = document.createElement('td');
                const span = document.createElement('span');
                span.className = `log-type-tag type-${sanitizeClass(item.source ?? 'script')}`;
                span.textContent = (item.source ?? 'script') === 'tool' ? 'TOOL' : 'SCRIPT';
                td.appendChild(span); return td;
            },
            () => {
                const td = document.createElement('td'), span = document.createElement('span');
                span.className = `cat-badge cat-${sanitizeClass(item.category ?? 'other')}`;
                span.textContent = item.category ?? '—'; td.appendChild(span); return td;
            },
            () => {
                const td = document.createElement('td'), span = document.createElement('span');
                span.className = `status ${sanitizeClass(item.status)}`;
                span.textContent = (item.status ?? 'unknown').toUpperCase(); td.appendChild(span); return td;
            },
            () => { const td = document.createElement('td'); td.textContent = item.duration ?? '—'; return td; },
            () => { const td = document.createElement('td'); td.className = 'td-muted'; td.textContent = formatFileSize(item.size ?? 0); return td; },
            () => {
                // Format column (NEW)
                const td = document.createElement('td');
                const span = document.createElement('span');
                span.className = `log-fmt-tag ${item.log_format === 'jsonl' ? 'fmt-jsonl' : 'fmt-log'}`;
                span.textContent = item.log_format === 'jsonl' ? 'JSON' : 'LOG';
                td.appendChild(span); return td;
            },
            () => {
                const td = document.createElement('td');
                const viewBtn = makeBtn('View', 'View log', () => openLogByName(item.log_name ?? item.name, item.name, item.log_format));
                td.appendChild(viewBtn);
                if (item.log_name) {
                    const tb = makeBtn('⟳', 'Live tail', () => openTail({ dir: 'logs', name_param: item.log_name, name: item.log_name }));
                    tb.style.marginLeft = '4px'; td.appendChild(tb);
                }
                const sb = makeBtn('↗', 'Share', () => openShareModal(item)); sb.style.marginLeft = '4px'; td.appendChild(sb);
                return td;
            },
        ];
        cells.forEach(fn => tr.appendChild(fn())); frag.appendChild(tr);
    });
    tbody.replaceChildren(frag);
}

//  Log Viewer Modal — with structured JSON view
function openLog(logObj) { stopTail(); currentLogFile = logObj; showModal(logObj.name, logObj.dir, logObj.name_param, logObj.log_format); }

function openLogByName(logName, displayName, logFormat) {
    const log = (dashboardData.logs ?? []).find(l => l.name === logName || l.name_param === logName);
    if (log)      openLog(log);
    else if (logName) openLog({ name: logName, dir: 'logs', name_param: logName, log_format: logFormat ?? 'legacy' });
    else showToast(`No log found for ${displayName}`, 'error');
}

let _currentLogFormat = 'legacy';

async function showModal(displayName, dir, nameParam, logFormat) {
    const modal     = document.getElementById('logModal');
    const content   = document.getElementById('logContent');
    const title     = document.getElementById('modalTitle');
    const meta      = document.getElementById('modalMeta');
    const tailBadge = document.getElementById('tailBadge');
    const vmToggle  = document.getElementById('viewModeToggle');
    const fmtBadge  = document.getElementById('logFormatBadge');

    _currentLogFormat = logFormat ?? 'legacy';
    currentViewMode   = 'raw';

    title.textContent = displayName ?? 'Viewer';
    meta.textContent  = `${dir}/${nameParam}`;
    content.textContent = 'Loading…';
    tailBadge?.classList.remove('active');
    modal.classList.add('active');
    trapFocus(modal);

    // Show/hide structured view toggle
    const isJsonl = _currentLogFormat === 'jsonl';
    if (vmToggle) vmToggle.style.display = isJsonl ? 'flex' : 'none';
    if (fmtBadge) {
        fmtBadge.textContent   = isJsonl ? 'STRUCTURED' : 'PLAIN TEXT';
        fmtBadge.className     = `log-format-badge ${isJsonl ? 'fmt-jsonl' : 'fmt-log'}`;
    }
    updateViewModeBtns();

    try {
        // For .jsonl files also pre-fetch parsed records for the structured view
        if (isJsonl) {
            const streamRes = await fetch(`/api/log-stream?dir=${encodeURIComponent(dir)}&name=${encodeURIComponent(nameParam)}&limit=500`);
            if (streamRes.ok) {
                const streamData = await streamRes.json();
                currentLogRecords = streamData.records ?? [];
            }
        } else {
            currentLogRecords = null;
        }

        const res = await fetch(`/api/file?dir=${encodeURIComponent(dir)}&name=${encodeURIComponent(nameParam)}`);
        if (res.ok) {
            const text = await res.text();
            content.textContent = text;
        } else {
            content.textContent = await buildFallbackContent(displayName);
        }
        content.scrollTop = content.scrollHeight;
    } catch {
        content.textContent = 'Server not reachable.\n\nStart it with:\n  cd dashboard && python3 server.py';
    }
}

// Structured view mode toggle
function setViewMode(mode) {
    currentViewMode = mode;
    updateViewModeBtns();
    if (mode === 'parsed' && currentLogRecords) {
        renderStructuredLog(currentLogRecords);
    } else {
        // Restore raw pre element
        const body = document.getElementById('modalBody');
        if (!body.querySelector('pre#logContent')) {
            body.innerHTML = '<pre id="logContent" tabindex="0"></pre>';
        }
        if (currentLogFile) {
            // Re-fetch raw text
            const { dir, name_param, name } = currentLogFile;
            fetch(`/api/file?dir=${encodeURIComponent(dir ?? 'logs')}&name=${encodeURIComponent(name_param ?? name)}`)
                .then(r => r.ok ? r.text() : 'Could not load file.')
                .then(t => { const el = document.getElementById('logContent'); if (el) { el.textContent = t; el.scrollTop = el.scrollHeight; } })
                .catch(() => {});
        }
    }
}

function updateViewModeBtns() {
    document.getElementById('vmRaw')?.classList.toggle('active',    currentViewMode === 'raw');
    document.getElementById('vmParsed')?.classList.toggle('active', currentViewMode === 'parsed');
}

function renderStructuredLog(records) {
    const body = document.getElementById('modalBody');
    if (!body) return;

    const wrapper = document.createElement('div');
    wrapper.className = 'structured-log';

    const _levelColor = { DEBUG: 'var(--text-muted)', INFO: 'var(--cyan)', SUCCESS: 'var(--green)', WARNING: 'var(--amber)', ERROR: 'var(--red)', CRITICAL: 'var(--red)' };
    const _levelBg    = { DEBUG: 'transparent', INFO: 'var(--cyan-dim)', SUCCESS: 'var(--green-dim)', WARNING: 'var(--amber-dim)', ERROR: 'var(--red-dim)', CRITICAL: 'var(--red-dim)' };

    records.forEach(r => {
        const row = document.createElement('div');
        row.className = 'sl-row';

        const level = (r.level ?? 'INFO').toUpperCase();
        const ts    = r.timestamp ? r.timestamp.replace('T', ' ').replace('Z', '') : '';
        const data  = r.data ?? {};
        const isSection  = data.type === 'section';
        const isFinding  = data.type === 'finding';
        const isMetric   = data.type === 'metric';

        if (isSection) {
            row.className = 'sl-row sl-section';
            row.innerHTML = `<span class="sl-section-title">${escHtml(r.message)}</span>`;
        } else {
            row.innerHTML = `
                <span class="sl-ts">${escHtml(ts)}</span>
                <span class="sl-level" style="color:${_levelColor[level] ?? 'var(--text)'};background:${_levelBg[level] ?? 'transparent'}">${level}</span>
                <span class="sl-msg ${isFinding ? 'sl-finding' : ''} ${isMetric ? 'sl-metric' : ''}">${escHtml(r.message)}</span>
                ${Object.keys(data).length > 0 ? `<span class="sl-expand" title="Toggle data">⊕</span>` : ''}`;

            if (Object.keys(data).length > 0) {
                const dataEl = document.createElement('div');
                dataEl.className = 'sl-data hidden';
                dataEl.innerHTML = Object.entries(data).map(([k, v]) =>
                    `<span class="sl-kv"><span class="sl-dk">${escHtml(k)}</span>=<span class="sl-dv">${escHtml(v)}</span></span>`
                ).join('');
                row.appendChild(dataEl);
                row.querySelector('.sl-expand')?.addEventListener('click', () => dataEl.classList.toggle('hidden'));
            }
        }
        wrapper.appendChild(row);
    });

    if (!records.length) {
        wrapper.innerHTML = '<div class="empty-state"><p>No structured records found.</p></div>';
    }

    body.replaceChildren(wrapper);
}

async function openTail(logObj) {
    stopTail(); currentLogFile = logObj;
    const modal     = document.getElementById('logModal');
    const content   = document.getElementById('logContent');
    const title     = document.getElementById('modalTitle');
    const meta      = document.getElementById('modalMeta');
    const tailBadge = document.getElementById('tailBadge');
    const vmToggle  = document.getElementById('viewModeToggle');
    const fmtBadge  = document.getElementById('logFormatBadge');

    // Restore pre element if structured view was active
    const body = document.getElementById('modalBody');
    if (!body.querySelector('pre#logContent')) {
        body.innerHTML = '<pre id="logContent" tabindex="0"></pre>';
    }

    title.textContent = `⟳ LIVE — ${logObj.name_param ?? logObj.name}`;
    meta.textContent  = `${logObj.dir ?? 'logs'}/${logObj.name_param ?? logObj.name}`;
    document.getElementById('logContent').textContent = 'Connecting to live tail…';
    tailBadge?.classList.add('active');
    if (vmToggle) vmToggle.style.display = 'none';
    if (fmtBadge) fmtBadge.textContent = '';
    modal.classList.add('active'); trapFocus(modal);

    async function fetchTail() {
        try {
            const res = await fetch(`/api/tail?dir=${encodeURIComponent(logObj.dir ?? 'logs')}&name=${encodeURIComponent(logObj.name_param ?? logObj.name)}&lines=120`);
            if (!res.ok) { document.getElementById('logContent').textContent = 'File not found or server error.'; return; }
            const data = await res.json();
            if (data.mtime !== tailLastMtime) {
                tailLastMtime = data.mtime;
                const el = document.getElementById('logContent');
                if (el) { el.textContent = data.lines.join('\n'); el.scrollTop = el.scrollHeight; }
            }
        } catch {}
    }
    await fetchTail();
    tailInterval = setInterval(fetchTail, TAIL_POLL_MS);
}

function stopTail() {
    if (tailInterval) { clearInterval(tailInterval); tailInterval = null; }
    document.getElementById('tailBadge')?.classList.remove('active');
}

function closeModal() {
    stopTail();
    document.getElementById('logModal').classList.remove('active');
    currentLogFile = null; currentLogRecords = null; currentViewMode = 'raw';
}

async function copyLogContent() {
    const text = document.getElementById('logContent')?.textContent ?? '';
    try { await navigator.clipboard.writeText(text); showToast('Copied to clipboard', 'success'); }
    catch { showToast('Copy failed — try selecting manually', 'error'); }
}

function downloadCurrentLog() { if (currentLogFile) downloadFile(currentLogFile); }

async function buildFallbackContent(name) {
    return `=== Demo / offline view for: ${name} ===\n\n[INFO] Server returned a non-OK response.\n[INFO] Start: cd dashboard && python3 server.py\n[INFO] Then refresh the dashboard.\n`;
}

//  Share Modal
let _shareTarget = null;
function openShareModal(item) {
    _shareTarget = item;
    const modal = document.getElementById('shareModal'); if (!modal) return;
    const name  = item?.name ?? item?.log_name ?? 'unknown';
    const text  = buildShareText(item);
    document.getElementById('shareTitle').textContent       = name;
    document.getElementById('sharePreviewText').textContent = text;
    document.getElementById('emailSubject').value = `🔒 CyberDeck Report: ${name}`;
    document.getElementById('emailBody').value    = text;
    document.getElementById('emailTo').value      = '';
    modal.classList.add('active'); trapFocus(modal);
}

function buildShareText(item) {
    const lines = ['📊 Networking & Cybersecurity Automation Toolkit — Execution Report', ''];
    if (item?.name)      lines.push(`Script/Tool: ${item.name}`);
    if (item?.category)  lines.push(`Category:    ${item.category}`);
    if (item?.status)    lines.push(`Status:      ${item.status.toUpperCase()}`);
    if (item?.duration)  lines.push(`Duration:    ${item.duration}`);
    if (item?.size)      lines.push(`Size:        ${formatFileSize(item.size)}`);
    if (item?.timestamp) lines.push(`Time:        ${new Date(item.timestamp).toLocaleString()}`);
    lines.push('', '— Generated by CyberDeck Dashboard');
    return lines.join('\n');
}

function closeShareModal() { document.getElementById('shareModal')?.classList.remove('active'); _shareTarget = null; }
function shareToTwitter()  { if (!_shareTarget) return; window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(`🔒 CyberDeck: ${_shareTarget.name ?? ''} | Status: ${(_shareTarget.status ?? '').toUpperCase()} | #CyberSecurity`)}`, '_blank', 'noopener'); }
function shareToLinkedIn() { if (!_shareTarget) return; window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(window.location.href)}`, '_blank', 'noopener'); }
function shareToReddit()   { if (!_shareTarget) return; window.open(`https://reddit.com/submit?url=${encodeURIComponent(window.location.href)}&title=${encodeURIComponent(`CyberDeck — ${_shareTarget.name ?? ''}`)}`, '_blank', 'noopener'); }
async function copyShareLink() {
    const text = document.getElementById('sharePreviewText')?.textContent ?? '';
    try { await navigator.clipboard.writeText(text); showToast('Copied to clipboard', 'success'); }
    catch { showToast('Copy failed', 'error'); }
}
async function sendShareEmail() {
    const to      = document.getElementById('emailTo')?.value?.trim();
    const subject = document.getElementById('emailSubject')?.value?.trim();
    const body    = document.getElementById('emailBody')?.value?.trim();
    if (!to) { showToast('Please enter an email address', 'error'); return; }
    const btn = document.getElementById('sendEmailBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
    try {
        const res = await fetch('/api/notify-email', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to, subject, body }) });
        const data = await res.json();
        if (data.sent) { showToast(`Email sent to ${to}`, 'success'); closeShareModal(); }
        else showToast(data.error ?? 'Email failed. Configure SMTP in server.', 'error');
    } catch { showToast('Server not reachable', 'error'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Send Email'; } }
}

//  Alert Modal
function openAlertModal() {
    const modal = document.getElementById('alertModal'); if (!modal) return;
    const d = sysStatsData?.thresholds;
    if (d) {
        setInputVal('alertCpuWarn',  d.cpu_warn  ?? 70);
        setInputVal('alertCpuCrit',  d.cpu_crit  ?? 90);
        setInputVal('alertMemWarn',  d.mem_warn  ?? 75);
        setInputVal('alertMemCrit',  d.mem_crit  ?? 90);
        setInputVal('alertDiskWarn', d.disk_warn ?? 80);
        setInputVal('alertDiskCrit', d.disk_crit ?? 95);
    }
    modal.classList.add('active'); trapFocus(modal);
}
function closeAlertModal() { document.getElementById('alertModal')?.classList.remove('active'); }
async function saveAlertSettings() {
    const payload = {
        cpu_warn:  +getInputVal('alertCpuWarn'),  cpu_crit:  +getInputVal('alertCpuCrit'),
        mem_warn:  +getInputVal('alertMemWarn'),  mem_crit:  +getInputVal('alertMemCrit'),
        disk_warn: +getInputVal('alertDiskWarn'), disk_crit: +getInputVal('alertDiskCrit'),
        email_to:  getInputVal('alertEmailTo'),
        email_notify: document.getElementById('alertEmailNotify')?.checked ?? false,
    };
    try {
        const res = await fetch('/api/alert-settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        if (res.ok) { showToast('Alert settings saved', 'success'); closeAlertModal(); }
        else showToast('Save failed', 'error');
    } catch { showToast('Server not reachable', 'error'); }
}

//  Search
async function runSearch(query) {
    const panel   = document.getElementById('searchResults');
    const counter = document.getElementById('searchCount');
    if (!panel) return;
    if (!query || query.trim().length < 2) { clearSearchResults(); return; }
    panel.classList.add('active');
    panel.innerHTML = '<div class="search-loading">Searching…</div>';
    try {
        const res = await fetch(`/api/search?q=${encodeURIComponent(query.trim())}&limit=40`);
        if (!res.ok) throw new Error();
        const data = await res.json();
        if (counter) counter.textContent = data.total > 0 ? `${data.total} hit${data.total !== 1 ? 's' : ''}` : '';
        if (!data.results.length) { panel.innerHTML = '<div class="search-empty">No matches found.</div>'; return; }
        const frag = document.createDocumentFragment();
        data.results.forEach(r => {
            const row = document.createElement('div'); row.className = 'search-result-row';
            row.addEventListener('click', () => {
                const log = (dashboardData.logs ?? []).find(l => l.name === r.file || l.name_param === r.file);
                openLog(log ?? { name: r.file, dir: r.dir ?? 'logs', name_param: r.file, log_format: r.is_json ? 'jsonl' : 'legacy' });
                clearSearchResults();
            });
            row.innerHTML = `<div class="sr-file">${escHtml(r.file)} <span class="sr-line">line ${r.line}</span>${r.is_json ? '<span class="fmt-jsonl" style="margin-left:4px;font-size:0.58rem;padding:0.06rem 0.28rem">JSON</span>' : ''}</div>
              <div class="sr-content">${highlightMatch(escHtml(r.content), query)}</div>`;
            frag.appendChild(row);
        });
        panel.innerHTML = ''; panel.appendChild(frag);
    } catch {
        panel.innerHTML = '<div class="search-empty">Search unavailable — start server.py first.</div>';
    }
}

function highlightMatch(text, query) { return text.replace(new RegExp(`(${escHtml(query)})`, 'gi'), '<mark>$1</mark>'); }
function clearSearchResults() { const p = document.getElementById('searchResults'), c = document.getElementById('searchCount'); if (p) { p.innerHTML = ''; p.classList.remove('active'); } if (c) c.textContent = ''; }

//  Download
async function downloadFile(fileObj) {
    const dir  = fileObj.dir ?? 'logs';
    const name = fileObj.name_param ?? fileObj.name;
    try {
        const res = await fetch(`/api/file?dir=${encodeURIComponent(dir)}&name=${encodeURIComponent(name)}`);
        if (res.ok) {
            const blob = await res.blob(), url = URL.createObjectURL(blob);
            const a = Object.assign(document.createElement('a'), { href: url, download: name.split('/').pop() });
            document.body.appendChild(a); a.click(); URL.revokeObjectURL(url); a.remove();
            showToast(`Downloaded: ${name.split('/').pop()}`, 'success');
        } else showToast('Download failed — server returned error', 'error');
    } catch { showToast('Server not running — start server.py first', 'error'); }
}

//  Refresh
async function refreshDashboard() {
    const el = document.getElementById('liveStatus'); if (el) el.textContent = 'Refreshing…';
    await Promise.all([loadDashboardData(), loadMetrics(), loadSystemStats(), loadFindings(), loadSessions()]);
    if (el) el.textContent = autoRefreshOn ? 'Live' : 'Paused';
    showToast('Dashboard refreshed', 'success');
}

function toggleAutoRefresh() {
    autoRefreshOn = !autoRefreshOn;
    sessionStorage.setItem('autoRefresh', autoRefreshOn);
    applyAutoRefreshState();
    showToast(autoRefreshOn ? 'Auto-refresh enabled' : 'Auto-refresh paused');
}

function applyAutoRefreshState() {
    clearInterval(refreshTimer);
    const btn       = document.getElementById('autoRefreshBtn');
    const indicator = document.querySelector('.live-indicator');
    const el        = document.getElementById('liveStatus');
    if (autoRefreshOn) {
        refreshTimer = setInterval(() => { loadDashboardData(); loadMetrics(); loadFindings(); loadSessions(); }, REFRESH_MS);
        btn?.setAttribute('aria-pressed', 'true');
        indicator?.classList.remove('paused');
        if (el) el.textContent = 'Live';
    } else {
        btn?.setAttribute('aria-pressed', 'false');
        indicator?.classList.add('paused');
        if (el) el.textContent = 'Paused';
    }
}

//  Export
function exportReport() {
    const ts = new Date().toLocaleString(), d = dashboardData, s = d.stats ?? {}, m = metricsData ?? {};
    let report = `╔══════════════════════════════════════════════════╗\n║  CyberDeck — Security Report                    ║\n║  Generated: ${ts.padEnd(37)}║\n╚══════════════════════════════════════════════════╝\n\n`;
    report += `STATISTICS\n${'═'.repeat(40)}\n`;
    report += `Total Scans: ${s.total ?? 0}\nSuccessful: ${s.successful ?? 0}\nWarnings: ${s.warnings ?? 0}\nFailed: ${s.failed ?? 0}\nSuccess Rate: ${m.success_rate ?? '—'}%\n\n`;

    if (findingsData.length) {
        report += `SECURITY FINDINGS (${findingsData.length})\n${'═'.repeat(40)}\n`;
        findingsData.forEach(f => { report += `[${(f.severity ?? '').toUpperCase()}] ${f.title}\n  Detail: ${f.detail}\n  Module: ${f.module}  Time: ${f.timestamp}\n\n`; });
    }

    if (sysStatsData?.available) {
        const sys = sysStatsData;
        report += `SYSTEM STATS\n${'═'.repeat(40)}\n`;
        report += `CPU: ${sys.cpu?.percent}% (${sys.cpu?.level?.toUpperCase()})\nMemory: ${sys.memory?.percent}% used\nDisk: ${sys.disk?.percent}% — ${sys.disk?.free_gb?.toFixed(1)} GB free\n\n`;
    }

    report += `EXECUTION HISTORY\n${'═'.repeat(40)}\n`;
    (d.history ?? []).forEach(i => { report += `${i.name}  [${(i.source ?? 'script').toUpperCase()}]  ${(i.status ?? '').toUpperCase()}  ${i.duration}  ${i.timestamp}\n`; });
    report += `\n${'═'.repeat(50)}\nEnd of Report\n`;

    const blob = new Blob([report], { type: 'text/plain' }), url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: `cyberdeck_report_${getTimestamp()}.txt` });
    document.body.appendChild(a); a.click(); URL.revokeObjectURL(url); a.remove();
    showToast('Report exported', 'success');
}

//  UI Helpers
function updateLastUpdate() {
    const el = document.getElementById('lastUpdate'); if (!el) return;
    const n = new Date(); el.textContent = n.toLocaleTimeString(); el.dateTime = n.toISOString();
}

let toastTimeout = null;
function showToast(message, type = '') {
    const t = document.getElementById('toast'); if (!t) return;
    clearTimeout(toastTimeout); t.textContent = message;
    t.className = `toast${type ? ` toast-${type}` : ''} show`;
    toastTimeout = setTimeout(() => t.classList.remove('show'), 3200);
}

function trapFocus(el) {
    const sel = 'button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])';
    const f = el.querySelectorAll(sel); if (!f.length) return;
    const first = f[0], last = f[f.length - 1]; first.focus();
    const h = e => {
        if (e.key !== 'Tab') return;
        if (e.shiftKey) { if (document.activeElement === first) { e.preventDefault(); last.focus(); } }
        else { if (document.activeElement === last) { e.preventDefault(); first.focus(); } }
        if (!el.classList.contains('active')) el.removeEventListener('keydown', h);
    };
    el.addEventListener('keydown', h);
}

function buildEmptyState(glyph, message) {
    const d = document.createElement('div'); d.className = 'empty-state';
    const i = document.createElement('div'); i.className = 'empty-glyph'; i.setAttribute('aria-hidden', 'true'); i.textContent = glyph;
    const p = document.createElement('p'); p.textContent = message;
    d.appendChild(i); d.appendChild(p); return d;
}
function buildTimeEl(iso) {
    const el = document.createElement('time'); el.dateTime = iso ?? ''; el.textContent = formatTimestampText(iso); el.title = iso ? new Date(iso).toLocaleString() : ''; return el;
}
function setText(id, val)      { const el = document.getElementById(id); if (el) el.textContent = String(val); }
function setInputVal(id, val)  { const el = document.getElementById(id); if (el) el.value = val; }
function getInputVal(id)       { return document.getElementById(id)?.value ?? ''; }
function cap(s)                { return s.charAt(0).toUpperCase() + s.slice(1); }
function formatTimestampText(iso) {
    if (!iso) return '—'; const d = new Date(iso); if (isNaN(d)) return '—';
    const diff = Date.now() - d.getTime();
    if (diff < 60_000)     return 'Just now';
    if (diff < 3_600_000)  return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return d.toLocaleString();
}
function formatFileSize(bytes) {
    if (bytes < 1_024)     return `${bytes} B`;
    if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1)} KB`;
    return `${(bytes / 1_048_576).toFixed(1)} MB`;
}
function getTimestamp() {
    const n = new Date();
    return [n.getFullYear(), String(n.getMonth() + 1).padStart(2,'0'), String(n.getDate()).padStart(2,'0'), '_', String(n.getHours()).padStart(2,'0'), String(n.getMinutes()).padStart(2,'0'), String(n.getSeconds()).padStart(2,'0')].join('');
}
function escHtml(s) { return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function sanitizeClass(s) { return (s ?? '').replace(/[^a-z0-9-_]/gi,'').toLowerCase(); }