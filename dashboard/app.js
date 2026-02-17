/**
 * CyberDeck Dashboard — app.js
 *
 * Key improvements over the original:
 *  - All dynamic HTML uses DOM APIs (textContent / createElement) — no
 *    innerHTML with raw data, eliminating XSS vectors from file names /
 *    log paths.
 *  - Auto-refresh is now user-toggleable (persists via localStorage).
 *  - Dual category + status filter on the history table.
 *  - Stat bar widths animate on update.
 *  - Toast notification system replaces alert().
 *  - Copy-to-clipboard in the log modal.
 *  - Keyboard trap on the modal (Tab / Shift-Tab cycle within it).
 *  - formatTimestamp() returns a <time datetime="…"> element, not a string.
 *  - getTimestamp() centralised and shared.
 *  - Graceful undefined guards throughout.
 */

'use strict';

//  State
let dashboardData = {
    logs: [],
    outputs: [],
    history: [],
    stats: { total: 0, successful: 0, warnings: 0, failed: 0 }
};

let currentLogFile  = null;
let autoRefreshOn   = localStorage.getItem('autoRefresh') !== 'false';
let refreshTimer    = null;
const REFRESH_MS    = 30_000;

//  Bootstrap
document.addEventListener('DOMContentLoaded', () => {
    loadDashboardData();
    applyAutoRefreshState();

    // Close modal on backdrop click
    document.getElementById('logModal').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) closeModal();
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            refreshDashboard();
        }
    });
});

//  Data loading
async function loadDashboardData() {
    try {
        const res = await fetch('/api/dashboard-data');
        if (res.ok) {
            dashboardData = await res.json();
        } else {
            loadDemoData();
        }
    } catch {
        loadDemoData();
    }
    updateDashboard();
}

function loadDemoData() {
    dashboardData = {
        logs:    buildDemoLogs(),
        outputs: buildDemoOutputs(),
        history: buildDemoHistory(),
        stats:   { total: 15, successful: 12, warnings: 2, failed: 1 }
    };
}

function buildDemoLogs() {
    const scripts = [
        'detect_suspicious_net_linux.sh',
        'system_info.sh',
        'secure_system.sh',
        'forensic_collect.sh',
        'web_recon.sh'
    ];
    return scripts.map((script, i) => ({
        name:      `${script}_${getTimestamp()}.log`,
        script,
        timestamp: new Date(Date.now() - i * 3_600_000).toISOString(),
        size:      Math.floor(Math.random() * 50_000) + 1_000,
        path:      `logs/${script}_${getTimestamp()}.log`
    }));
}

function buildDemoOutputs() {
    return [
        { name: 'system_report.txt',   icon: '📄', size: 15_234 },
        { name: 'network_scan.json',   icon: '🔍', size:  8_765 },
        { name: 'security_audit.html', icon: '🔒', size: 23_456 },
        { name: 'forensic_data.zip',   icon: '📦', size: 156_789 },
        { name: 'recon_results.csv',   icon: '📊', size:  4_321 }
    ].map(o => ({
        ...o,
        timestamp: new Date(Date.now() - Math.random() * 86_400_000).toISOString(),
        path:      `output/${o.name}`
    }));
}

function buildDemoHistory() {
    return [
        { name: 'detect_suspicious_net_linux.sh', category: 'network',  status: 'success', duration: '2m 34s' },
        { name: 'system_info.sh',                 category: 'security', status: 'success', duration: '1m 12s' },
        { name: 'secure_system.sh',               category: 'security', status: 'success', duration: '3m 45s' },
        { name: 'forensic_collect.sh',            category: 'forensic', status: 'warning', duration: '5m 23s' },
        { name: 'web_recon.sh',                   category: 'recon',    status: 'success', duration: '4m 01s' },
        { name: 'detect_suspicious_net_linux.sh', category: 'network',  status: 'error',   duration: '0m 15s' }
    ].map((item, i) => ({
        ...item,
        timestamp: new Date(Date.now() - i * 7_200_000).toISOString()
    }));
}

//  Master update
function updateDashboard() {
    updateStats();
    updateRecentActivity();
    updateLogFiles();
    updateOutputFiles();
    updateHistory();
    updateLastUpdate();
}

//  Stats
function updateStats() {
    const { total, successful, warnings, failed } = dashboardData.stats ?? {};
    setText('totalScans',     total     ?? 0);
    setText('successfulScans', successful ?? 0);
    setText('warningScans',   warnings   ?? 0);
    setText('failedScans',    failed     ?? 0);

    // Animate bar widths — proportional to total, clamped to 100 %
    const safeTotal = total || 1;
    setBarWidth('barTotal',   100);
    setBarWidth('barSuccess', ((successful ?? 0) / safeTotal) * 100);
    setBarWidth('barWarning', ((warnings   ?? 0) / safeTotal) * 100);
    setBarWidth('barFailed',  ((failed     ?? 0) / safeTotal) * 100);
}

function setBarWidth(id, pct) {
    const el = document.getElementById(id);
    if (el) el.style.width = Math.min(Math.max(pct, 0), 100) + '%';
}

//  Recent Activity
function updateRecentActivity() {
    const container = document.getElementById('recentActivity');
    const history   = dashboardData.history ?? [];

    if (history.length === 0) {
        container.replaceChildren(buildEmptyState('⬡', 'No activity yet. Run a script to get started.'));
        return;
    }

    const frag = document.createDocumentFragment();
    history.slice(0, 5).forEach(item => {
        const div = document.createElement('div');
        div.className = `activity-item ${sanitizeClass(item.status)}`;
        div.setAttribute('role', 'article');

        const header = document.createElement('div');
        header.className = 'activity-header';

        const title = document.createElement('span');
        title.className = 'activity-title';
        title.textContent = item.name ?? '—';

        const time = document.createElement('span');
        time.className = 'activity-time';
        time.appendChild(buildTimeEl(item.timestamp));

        header.appendChild(title);
        header.appendChild(time);

        const desc = document.createElement('div');
        desc.className = 'activity-description';
        desc.innerHTML =
            `Status: <strong>${escHtml((item.status ?? '—').toUpperCase())}</strong> · ` +
            `Duration: ${escHtml(item.duration ?? '—')} · ` +
            `Category: ${escHtml(item.category ?? '—')}`;

        div.appendChild(header);
        div.appendChild(desc);
        frag.appendChild(div);
    });
    container.replaceChildren(frag);
}

//  Log Files
function updateLogFiles() {
    const container  = document.getElementById('logFiles');
    const countBadge = document.getElementById('logCount');
    const logs       = dashboardData.logs ?? [];

    countBadge.textContent = `${logs.length} file${logs.length !== 1 ? 's' : ''}`;

    if (logs.length === 0) {
        container.replaceChildren(buildEmptyState('◫', 'No log files available.'));
        return;
    }

    const frag = document.createDocumentFragment();
    logs.forEach(log => {
        const item = document.createElement('div');
        item.className = 'log-item';
        item.setAttribute('role', 'listitem');
        item.setAttribute('tabindex', '0');
        item.setAttribute('aria-label', `View log: ${log.name}`);
        item.addEventListener('click', () => viewLog(log.path, log.name));
        item.addEventListener('keydown', e => { if (e.key === 'Enter') viewLog(log.path, log.name); });

        const info = document.createElement('div');
        info.className = 'log-info';

        const name = document.createElement('div');
        name.className = 'log-name';
        name.textContent = `◧ ${log.name ?? 'unknown'}`;

        const meta = document.createElement('div');
        meta.className = 'log-meta';
        meta.appendChild(buildTimeEl(log.timestamp));
        meta.appendChild(document.createTextNode(` · ${formatFileSize(log.size ?? 0)}`));

        info.appendChild(name);
        info.appendChild(meta);

        const actions = document.createElement('div');
        actions.className = 'log-actions';
        const dlBtn = document.createElement('button');
        dlBtn.className = 'btn btn-ghost btn-sm';
        dlBtn.setAttribute('aria-label', `Download ${log.name}`);
        dlBtn.textContent = '↓';
        dlBtn.addEventListener('click', e => {
            e.stopPropagation();
            downloadFile(log.path, log.name);
        });
        actions.appendChild(dlBtn);

        item.appendChild(info);
        item.appendChild(actions);
        frag.appendChild(item);
    });
    container.replaceChildren(frag);
}

//  Output Files
function updateOutputFiles() {
    const container  = document.getElementById('outputFiles');
    const countBadge = document.getElementById('outputCount');
    const outputs    = dashboardData.outputs ?? [];

    countBadge.textContent = `${outputs.length} file${outputs.length !== 1 ? 's' : ''}`;

    if (outputs.length === 0) {
        container.replaceChildren(buildEmptyState('◫', 'No output files generated yet.'));
        return;
    }

    const frag = document.createDocumentFragment();
    outputs.forEach(file => {
        const item = document.createElement('div');
        item.className = 'file-item';
        item.setAttribute('role', 'listitem');
        item.setAttribute('tabindex', '0');
        item.setAttribute('aria-label', `Download ${file.name}`);
        item.addEventListener('click',   () => downloadFile(file.path, file.name));
        item.addEventListener('keydown', e => { if (e.key === 'Enter') downloadFile(file.path, file.name); });

        const icon = document.createElement('div');
        icon.className = 'file-icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = file.icon ?? '📄';

        const name = document.createElement('div');
        name.className = 'file-name';
        name.textContent = file.name ?? '—';

        const size = document.createElement('div');
        size.className = 'file-size';
        size.textContent = formatFileSize(file.size ?? 0);

        item.appendChild(icon);
        item.appendChild(name);
        item.appendChild(size);
        frag.appendChild(item);
    });
    container.replaceChildren(frag);
}

//  Execution History
function updateHistory() {
    renderHistoryRows(dashboardData.history ?? []);
}

function filterHistory() {
    const catFilter    = document.getElementById('scriptFilter')?.value  ?? 'all';
    const statusFilter = document.getElementById('statusFilter')?.value  ?? 'all';
    let   filtered     = dashboardData.history ?? [];

    if (catFilter    !== 'all') filtered = filtered.filter(i => i.category === catFilter);
    if (statusFilter !== 'all') filtered = filtered.filter(i => i.status   === statusFilter);

    renderHistoryRows(filtered);
}

function renderHistoryRows(items) {
    const tbody = document.getElementById('historyTable');

    if (!items || items.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.setAttribute('colspan', '6');
        td.className = 'empty-row';
        td.textContent = 'No matching results';
        tr.appendChild(td);
        tbody.replaceChildren(tr);
        return;
    }

    const frag = document.createDocumentFragment();
    items.forEach(item => {
        const tr = document.createElement('tr');

        // Timestamp
        const tdTime = document.createElement('td');
        tdTime.appendChild(buildTimeEl(item.timestamp));
        tr.appendChild(tdTime);

        // Script name
        const tdName = document.createElement('td');
        tdName.textContent = item.name ?? '—';
        tr.appendChild(tdName);

        // Category
        const tdCat = document.createElement('td');
        const catSpan = document.createElement('span');
        catSpan.className = 'cat-badge';
        catSpan.textContent = item.category ?? '—';
        tdCat.appendChild(catSpan);
        tr.appendChild(tdCat);

        // Status
        const tdStatus = document.createElement('td');
        const statusSpan = document.createElement('span');
        statusSpan.className = `status ${sanitizeClass(item.status)}`;
        statusSpan.textContent = (item.status ?? 'unknown').toUpperCase();
        tdStatus.appendChild(statusSpan);
        tr.appendChild(tdStatus);

        // Duration
        const tdDur = document.createElement('td');
        tdDur.textContent = item.duration ?? '—';
        tr.appendChild(tdDur);

        // Actions
        const tdAct = document.createElement('td');
        const btn = document.createElement('button');
        btn.className = 'btn btn-ghost btn-sm';
        btn.textContent = 'View Log';
        btn.setAttribute('aria-label', `View log for ${item.name}`);
        btn.addEventListener('click', () => viewScriptLog(item.name));
        tdAct.appendChild(btn);
        tr.appendChild(tdAct);

        frag.appendChild(tr);
    });
    tbody.replaceChildren(frag);
}

//  Log Modal
async function viewLog(path, name) {
    currentLogFile = { path, name };

    const modal   = document.getElementById('logModal');
    const content = document.getElementById('logContent');
    const title   = document.getElementById('modalTitle');
    const meta    = document.getElementById('modalMeta');

    title.textContent = name ?? 'Log Viewer';
    meta.textContent  = path ?? '—';
    content.textContent = 'Loading…';
    modal.classList.add('active');
    trapFocus(modal);

    try {
        const res = await fetch(`/api/file?path=${encodeURIComponent(path)}`);
        if (res.ok) {
            content.textContent = await res.text();
        } else {
            content.textContent = demoLogContent(name);
        }
    } catch {
        content.textContent =
            'Error loading log file.\n\n' +
            'To view real logs, start the Python server:\n' +
            '  cd dashboard && python3 server.py';
    }
}

function viewScriptLog(scriptName) {
    const log = (dashboardData.logs ?? []).find(l => l.script === scriptName);
    if (log) viewLog(log.path, log.name);
    else showToast(`No log found for ${scriptName}`, 'error');
}

function closeModal() {
    const modal = document.getElementById('logModal');
    modal.classList.remove('active');
    currentLogFile = null;
}

async function copyLogContent() {
    const text = document.getElementById('logContent')?.textContent ?? '';
    try {
        await navigator.clipboard.writeText(text);
        showToast('Copied to clipboard', 'success');
    } catch {
        showToast('Copy failed — try selecting manually', 'error');
    }
}

function downloadCurrentLog() {
    if (currentLogFile) downloadFile(currentLogFile.path, currentLogFile.name);
}

//  File download
async function downloadFile(path, name) {
    try {
        const res = await fetch(`/api/file?path=${encodeURIComponent(path)}`);
        if (res.ok) {
            const blob = await res.blob();
            const url  = URL.createObjectURL(blob);
            const a    = Object.assign(document.createElement('a'), { href: url, download: name });
            document.body.appendChild(a);
            a.click();
            URL.revokeObjectURL(url);
            a.remove();
            showToast(`Downloaded: ${name}`, 'success');
        } else {
            showToast('Download unavailable — start the server first', 'error');
        }
    } catch {
        showToast('Server not running — start server.py first', 'error');
    }
}

//  Refresh & Auto-refresh
function refreshDashboard() {
    const statusEl = document.getElementById('liveStatus');
    if (statusEl) statusEl.textContent = 'Refreshing…';
    loadDashboardData().finally(() => {
        if (statusEl) statusEl.textContent = autoRefreshOn ? 'Live' : 'Paused';
    });
}

function toggleAutoRefresh() {
    autoRefreshOn = !autoRefreshOn;
    localStorage.setItem('autoRefresh', autoRefreshOn);
    applyAutoRefreshState();
    showToast(autoRefreshOn ? 'Auto-refresh on' : 'Auto-refresh off');
}

function applyAutoRefreshState() {
    clearInterval(refreshTimer);
    const btn        = document.getElementById('autoRefreshBtn');
    const indicator  = document.querySelector('.live-indicator');
    const statusEl   = document.getElementById('liveStatus');

    if (autoRefreshOn) {
        refreshTimer = setInterval(loadDashboardData, REFRESH_MS);
        btn?.setAttribute('aria-pressed', 'true');
        indicator?.classList.remove('paused');
        if (statusEl) statusEl.textContent = 'Live';
    } else {
        btn?.setAttribute('aria-pressed', 'false');
        indicator?.classList.add('paused');
        if (statusEl) statusEl.textContent = 'Paused';
    }
}

//  Export report
function exportReport() {
    const ts   = new Date().toLocaleString();
    const d    = dashboardData;
    const s    = d.stats ?? {};
    let report =
        `╔══════════════════════════════════════════════════╗\n` +
        `║  Cybersecurity Automation Toolkit — Report      ║\n` +
        `║  Generated: ${ts.padEnd(37)}║\n` +
        `╚══════════════════════════════════════════════════╝\n\n` +
        `STATISTICS\n` + `─`.repeat(40) + `\n` +
        `Total Scans:  ${s.total      ?? 0}\n` +
        `Successful:   ${s.successful ?? 0}\n` +
        `Warnings:     ${s.warnings   ?? 0}\n` +
        `Failed:       ${s.failed     ?? 0}\n\n` +
        `EXECUTION HISTORY\n` + `─`.repeat(40) + `\n`;

    (d.history ?? []).forEach(item => {
        report +=
            `Script:    ${item.name}\n` +
            `Category:  ${item.category}\n` +
            `Status:    ${(item.status ?? '').toUpperCase()}\n` +
            `Duration:  ${item.duration}\n` +
            `Time:      ${formatTimestampText(item.timestamp)}\n` +
            `${'─'.repeat(30)}\n`;
    });

    report += `\nLOG FILES (${(d.logs ?? []).length})\n` + `─`.repeat(40) + `\n`;
    (d.logs ?? []).forEach(l => {
        report += `${l.name}  —  ${formatFileSize(l.size ?? 0)}  —  ${formatTimestampText(l.timestamp)}\n`;
    });

    report += `\nOUTPUT FILES (${(d.outputs ?? []).length})\n` + `─`.repeat(40) + `\n`;
    (d.outputs ?? []).forEach(f => {
        report += `${f.name}  —  ${formatFileSize(f.size ?? 0)}\n`;
    });

    report += `\n${'═'.repeat(50)}\nEnd of Report\n`;

    const blob = new Blob([report], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), {
        href:     url,
        download: `security_report_${getTimestamp()}.txt`
    });
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    a.remove();
    showToast('Report exported', 'success');
}

//  Last-update timestamp
function updateLastUpdate() {
    const el = document.getElementById('lastUpdate');
    if (!el) return;
    const now = new Date();
    el.textContent  = now.toLocaleTimeString();
    el.dateTime     = now.toISOString();
}

//  Toast notifications
let toastTimeout = null;

function showToast(message, type = '') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    clearTimeout(toastTimeout);
    toast.textContent = message;
    toast.className   = `toast${type ? ` toast-${type}` : ''} show`;
    toastTimeout = setTimeout(() => toast.classList.remove('show'), 3000);
}

//  Focus trap for modal
function trapFocus(el) {
    const focusable = el.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (!focusable.length) return;
    const first = focusable[0];
    const last  = focusable[focusable.length - 1];
    first.focus();

    const handler = (e) => {
        if (e.key !== 'Tab') return;
        if (e.shiftKey) {
            if (document.activeElement === first) { e.preventDefault(); last.focus(); }
        } else {
            if (document.activeElement === last)  { e.preventDefault(); first.focus(); }
        }
        if (!el.classList.contains('active')) el.removeEventListener('keydown', handler);
    };
    el.addEventListener('keydown', handler);
}

//  DOM helpers
function buildEmptyState(glyph, message) {
    const div   = document.createElement('div');
    div.className = 'empty-state';
    const icon  = document.createElement('div');
    icon.className = 'empty-glyph';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = glyph;
    const p     = document.createElement('p');
    p.textContent = message;
    div.appendChild(icon);
    div.appendChild(p);
    return div;
}

/**
 * Build a <time datetime="…"> element with a human-relative label.
 * Using a real <time> element is better for screen readers / search engines.
 */
function buildTimeEl(iso) {
    const el       = document.createElement('time');
    el.dateTime    = iso ?? '';
    el.textContent = formatTimestampText(iso);
    return el;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(value);
}

//  Utilities

/** Human-relative timestamp label (plain string, for non-DOM use). */
function formatTimestampText(iso) {
    if (!iso) return '—';
    const date = new Date(iso);
    if (isNaN(date)) return '—';
    const diff = Date.now() - date.getTime();
    if (diff < 60_000)     return 'Just now';
    if (diff < 3_600_000)  return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return date.toLocaleString();
}

function formatFileSize(bytes) {
    if (bytes < 1_024)         return `${bytes} B`;
    if (bytes < 1_048_576)     return `${(bytes / 1_024).toFixed(1)} KB`;
    return `${(bytes / 1_048_576).toFixed(1)} MB`;
}

function getTimestamp() {
    const n = new Date();
    return [
        n.getFullYear(),
        String(n.getMonth() + 1).padStart(2, '0'),
        String(n.getDate()).padStart(2, '0'),
        '_',
        String(n.getHours()).padStart(2, '0'),
        String(n.getMinutes()).padStart(2, '0'),
        String(n.getSeconds()).padStart(2, '0')
    ].join('');
}

/** Minimal HTML escape for inline innerHTML use (activity description). */
function escHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Return a CSS-class-safe version of a status/category string.
 * Prevents injecting arbitrary class names from server data.
 */
function sanitizeClass(str) {
    return (str ?? '').replace(/[^a-z0-9-_]/gi, '').toLowerCase();
}

function demoLogContent(name) {
    return (
        `=== Execution started at ${new Date().toLocaleString()} ===\n\n` +
        `[INFO] Initializing: ${name}\n` +
        `[INFO] Running security checks...\n` +
        `[INFO] Analyzing network traffic...\n` +
        `[SUCCESS] Scan completed successfully\n` +
        `[INFO] Results saved to output directory\n\n` +
        `=== Execution completed at ${new Date().toLocaleString()} with exit code 0 ===`
    );
}