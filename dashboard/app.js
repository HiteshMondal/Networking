'use strict';

// ── State ────────────────────────────────────────────────────────────────────
let dashboardData = { logs:[], outputs:[], history:[], stats:{total:0,successful:0,warnings:0,failed:0}, timeline:[] };
let metricsData       = null;
let sysStatsData      = null;
let currentLogFile    = null;
let tailInterval      = null;
let tailLastMtime     = 0;
let sysStatsInterval  = null;
let autoRefreshOn     = sessionStorage.getItem('autoRefresh') !== 'false';
let refreshTimer      = null;
let searchDebounceTimer = null;
let activeTab         = 'all';
const REFRESH_MS      = 30_000;
const TAIL_POLL_MS    = 3_000;
const SYS_POLL_MS     = 5_000;

// ── Bootstrap ────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadDashboardData();
    loadMetrics();
    loadSystemStats();
    applyAutoRefreshState();

    document.getElementById('logModal').addEventListener('click', e => {
        if (e.target === e.currentTarget) closeModal();
    });
    document.getElementById('shareModal')?.addEventListener('click', e => {
        if (e.target === e.currentTarget) closeShareModal();
    });
    document.getElementById('alertModal')?.addEventListener('click', e => {
        if (e.target === e.currentTarget) closeAlertModal();
    });

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

    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') { closeModal(); closeShareModal(); closeAlertModal(); }
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') { e.preventDefault(); refreshDashboard(); }
        if ((e.ctrlKey || e.metaKey) && e.key === 'f') { e.preventDefault(); document.getElementById('globalSearch')?.focus(); }
    });

    // Start live system stats polling
    sysStatsInterval = setInterval(loadSystemStats, SYS_POLL_MS);
});

// ── Data Loading ─────────────────────────────────────────────────────────────
async function loadDashboardData() {
    try {
        const res = await fetch('/api/dashboard-data');
        dashboardData = res.ok ? await res.json() : (loadDemoData(), dashboardData);
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
        if (res.ok) {
            sysStatsData = await res.json();
            renderSystemStats();
        }
    } catch {}
}

function loadDemoData() {
    const scripts = ['detect_suspicious_net_linux','system_info','secure_system','forensic_collect','web_recon'];
    const tools   = ['network_tools','core_protocols','ip_addressing','networking_basics','security_fundamentals'];
    const all     = [...scripts,...tools];
    dashboardData = {
        logs: all.map((s,i) => ({
            name:`${s}_20240118_12000${i}.log`, script:s,
            timestamp:new Date(Date.now()-i*3_600_000).toISOString(),
            size:Math.floor(Math.random()*50_000)+1_000, dir:'logs',
            name_param:`${s}_20240118_12000${i}.log`,
            source:tools.includes(s)?'tool':'script',
            category:tools.includes(s)?'network':'security',
        })),
        outputs:[
            {name:'system_report.txt',  icon:'📄',size:15_234,dir:'outputs',name_param:'system_report.txt',  timestamp:new Date(Date.now()-3_600_000).toISOString()},
            {name:'network_scan.json',  icon:'🔍',size:8_765, dir:'outputs',name_param:'network_scan.json',  timestamp:new Date(Date.now()-7_200_000).toISOString()},
            {name:'security_audit.html',icon:'🌐',size:23_456,dir:'outputs',name_param:'security_audit.html',timestamp:new Date(Date.now()-10_800_000).toISOString()},
            {name:'forensic_data.zip',  icon:'📦',size:156_789,dir:'outputs',name_param:'forensic_data.zip', timestamp:new Date(Date.now()-14_400_000).toISOString()},
        ],
        history:all.slice(0,8).map((s,i) => ({
            name:s, log_name:`${s}_20240118_12000${i}.log`,
            category:tools.includes(s)?'network':['security','forensic','recon'][i%3],
            status:['success','success','warning','error','success'][i%5],
            duration:`${Math.floor(Math.random()*5)}m ${Math.floor(Math.random()*59)}s`,
            timestamp:new Date(Date.now()-i*7_200_000).toISOString(),
            size:Math.floor(Math.random()*60_000)+500,
        })),
        stats:{total:18,successful:14,warnings:2,failed:2}, timeline:[],
    };
}

// ── Master Update ─────────────────────────────────────────────────────────────
function updateDashboard() {
    updateStats(); updateRecentActivity(); updateLogFiles();
    updateOutputFiles(); updateHistory(); updateLastUpdate(); updateDiskWidget();
}

// ── Stats ─────────────────────────────────────────────────────────────────────
function updateStats() {
    const { total=0, successful=0, warnings=0, failed=0 } = dashboardData.stats ?? {};
    animateCount('totalScans', total); animateCount('successfulScans', successful);
    animateCount('warningScans', warnings); animateCount('failedScans', failed);
    const s = total || 1;
    setBarWidth('barTotal',100); setBarWidth('barSuccess',(successful/s)*100);
    setBarWidth('barWarning',(warnings/s)*100); setBarWidth('barFailed',(failed/s)*100);
}

function animateCount(id, target) {
    const el = document.getElementById(id); if (!el) return;
    const start = parseInt(el.textContent,10)||0; if (start===target) return;
    const dur=600, t0=performance.now();
    const step=ts=>{
        const p=Math.min((ts-t0)/dur,1);
        el.textContent=Math.round(start+(target-start)*easeOut(p));
        if(p<1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}
function easeOut(t) { return 1-(1-t)**3; }
function setBarWidth(id,pct) { const el=document.getElementById(id); if(el) el.style.width=Math.min(Math.max(pct,0),100)+'%'; }

// ── System Stats (NEW) ────────────────────────────────────────────────────────
function renderSystemStats() {
    const d = sysStatsData;
    if (!d?.available) {
        const panel = document.getElementById('sysStatsPanel');
        if (panel) panel.innerHTML = `<div class="sys-unavailable">⚠ Install psutil: <code>pip install psutil --break-system-packages</code></div>`;
        return;
    }

    updateSysMeter('cpu',    d.cpu?.percent,   d.cpu?.level,    `${d.cpu?.count} cores`);
    updateSysMeter('mem',    d.memory?.percent, d.memory?.level, `${formatFileSize((d.memory?.used_mb??0)*1_048_576)} / ${formatFileSize((d.memory?.total_mb??0)*1_048_576)}`);
    updateSysMeter('disk',   d.disk?.percent,   d.disk?.level,   `${d.disk?.free_gb?.toFixed(1)} GB free`);
    updateNetStats(d.network);
    renderTemperatures(d.temperatures);

    // Flash alerts for critical
    ['cpu','memory','disk'].forEach(k => {
        if (d[k]?.level === 'critical') triggerAlert(k, d[k]);
    });
}

function updateSysMeter(key, pct, level, subtitle) {
    const pctEl = document.getElementById(`sys${cap(key)}Pct`);
    const barEl = document.getElementById(`sys${cap(key)}Bar`);
    const subEl = document.getElementById(`sys${cap(key)}Sub`);
    const cardEl = document.getElementById(`sysCard${cap(key)}`);
    if (pctEl) pctEl.textContent = (pct??0).toFixed(1)+'%';
    if (barEl) { barEl.style.width = (pct??0)+'%'; barEl.className=`sys-bar-fill level-${level??'ok'}`; }
    if (subEl) subEl.textContent = subtitle??'';
    if (cardEl) { cardEl.className=`sys-card level-${level??'ok'}`; }
}

function updateNetStats(net) {
    if (!net) return;
    setText('sysNetSent',  formatFileSize(net.bytes_sent??0));
    setText('sysNetRecv',  formatFileSize(net.bytes_recv??0));
    setText('sysNetErrors', (net.errin??0)+(net.errout??0));
    const cardEl = document.getElementById('sysCardNet');
    if (cardEl) cardEl.className = `sys-card level-${net.level??'ok'}`;
}

function renderTemperatures(temps) {
    const el = document.getElementById('sysTemps');
    if (!el) return;
    if (!temps || !Object.keys(temps).length) { el.textContent='—'; return; }
    el.innerHTML = Object.entries(temps).map(([k,v])=>
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

// ── Metrics ───────────────────────────────────────────────────────────────────
function renderMetrics() {
    if (!metricsData) return;
    const rateEl = document.getElementById('successRate');
    if (rateEl) {
        const rate = metricsData.success_rate??0;
        rateEl.textContent = rate+'%';
        const ring = document.getElementById('successRing');
        if (ring) { const c=2*Math.PI*28; ring.style.strokeDasharray=c; ring.style.strokeDashoffset=c*(1-rate/100); }
    }
    const avgEl = document.getElementById('avgDuration');
    if (avgEl) { const s=metricsData.avg_duration_s??0; avgEl.textContent=s>0?`${Math.floor(s/60)}m ${s%60}s`:'—'; }
    renderCategoryChart(metricsData.by_category??{});
    updateDiskWidget();
}

function renderCategoryChart(byCategory) {
    const container = document.getElementById('categoryChart'); if (!container) return;
    const entries = Object.entries(byCategory).sort((a,b)=>b[1]-a[1]);
    const max = entries[0]?.[1]||1;
    const colors = { network:'var(--cyan)',security:'var(--green)',forensic:'var(--amber)',recon:'var(--violet)',system:'var(--teal)',other:'var(--text-muted)' };
    container.innerHTML = '';
    entries.forEach(([cat,count]) => {
        const pct=(count/max)*100, row=document.createElement('div');
        row.className='chart-row';
        row.innerHTML=`<span class="chart-label">${escHtml(cat)}</span>
          <div class="chart-bar-track"><div class="chart-bar-fill" style="width:${pct}%;background:${colors[cat]||'var(--cyan)'}"></div></div>
          <span class="chart-count">${count}</span>`;
        container.appendChild(row);
    });
}

function updateDiskWidget() {
    const disk = metricsData?.disk; if (!disk) return;
    setText('diskLogs',    formatFileSize(disk.logs_bytes??0));
    setText('diskOutputs', formatFileSize(disk.outputs_bytes??0));
    setText('diskTotal',   formatFileSize(disk.total_bytes??0));
}

// ── Recent Activity ───────────────────────────────────────────────────────────
function updateRecentActivity() {
    const container = document.getElementById('recentActivity');
    const history   = dashboardData.history??[];
    if (!history.length) { container.replaceChildren(buildEmptyState('⬡','No activity yet. Run a script to get started.')); return; }
    const frag = document.createDocumentFragment();
    history.slice(0,6).forEach(item => {
        const div = document.createElement('div');
        div.className=`activity-item ${sanitizeClass(item.status)}`;
        div.setAttribute('role','article'); div.style.cursor='pointer';
        div.title='Click to view log';
        div.addEventListener('click',()=>openLogByName(item.log_name,item.name));

        const hdr=document.createElement('div'); hdr.className='activity-header';
        const title=document.createElement('span'); title.className='activity-title'; title.textContent=item.name??'—';
        const badge=document.createElement('span'); badge.className=`source-badge source-${sanitizeClass(item.category??'other')}`; badge.textContent=item.category??'other';
        const timeEl=document.createElement('span'); timeEl.className='activity-time'; timeEl.appendChild(buildTimeEl(item.timestamp));

        // Share button
        const shareBtn=document.createElement('button');
        shareBtn.className='btn btn-ghost btn-sm share-btn'; shareBtn.title='Share'; shareBtn.textContent='↗';
        shareBtn.addEventListener('click',e=>{e.stopPropagation();openShareModal({name:item.name,category:item.category,status:item.status,duration:item.duration,timestamp:item.timestamp});});

        hdr.appendChild(title); hdr.appendChild(badge); hdr.appendChild(timeEl); hdr.appendChild(shareBtn);
        const desc=document.createElement('div'); desc.className='activity-description';
        desc.innerHTML=`Status: <strong class="status-inline ${sanitizeClass(item.status)}">${escHtml((item.status??'—').toUpperCase())}</strong> · Duration: ${escHtml(item.duration??'—')} · Size: ${formatFileSize(item.size??0)}`;
        div.appendChild(hdr); div.appendChild(desc); frag.appendChild(div);
    });
    container.replaceChildren(frag);
}

// ── Log Files ─────────────────────────────────────────────────────────────────
function updateLogFiles(filterTab) {
    activeTab = filterTab??activeTab;
    const container=document.getElementById('logFiles'), countBadge=document.getElementById('logCount');
    let logs=dashboardData.logs??[];
    if (activeTab==='scripts') logs=logs.filter(l=>l.source==='script');
    else if (activeTab==='tools') logs=logs.filter(l=>l.source==='tool');
    countBadge.textContent=`${logs.length} file${logs.length!==1?'s':''}`;
    document.querySelectorAll('.log-tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===activeTab));
    if (!logs.length) { container.replaceChildren(buildEmptyState('◫',`No ${activeTab==='all'?'':activeTab+' '}log files found.`)); return; }
    const frag=document.createDocumentFragment();
    logs.forEach(log => {
        const item=document.createElement('div');
        item.className='log-item'; item.setAttribute('role','listitem');
        item.setAttribute('tabindex','0'); item.setAttribute('aria-label',`View log: ${log.name}`);
        item.addEventListener('click',()=>openLog(log));
        item.addEventListener('keydown',e=>{if(e.key==='Enter')openLog(log);});

        const typeTag=document.createElement('span');
        typeTag.className=`log-type-tag type-${sanitizeClass(log.source??'script')}`;
        typeTag.textContent=log.source==='tool'?'TOOL':'SCRIPT';

        const info=document.createElement('div'); info.className='log-info';
        const name=document.createElement('div'); name.className='log-name'; name.textContent=log.name??'unknown';
        const meta=document.createElement('div'); meta.className='log-meta';
        const catSpan=document.createElement('span'); catSpan.className=`cat-badge-sm cat-${sanitizeClass(log.category??'other')}`; catSpan.textContent=log.category??'other';
        meta.appendChild(catSpan); meta.appendChild(document.createTextNode(' '));
        meta.appendChild(buildTimeEl(log.timestamp));
        meta.appendChild(document.createTextNode(` · ${formatFileSize(log.size??0)}`));
        info.appendChild(name); info.appendChild(meta);

        const actions=document.createElement('div'); actions.className='log-actions';
        const tailBtn=makeBtn('⟳','Live tail',e=>{e.stopPropagation();openTail(log);});
        const dlBtn  =makeBtn('↓','Download',  e=>{e.stopPropagation();downloadFile(log);});
        const shareBtn=makeBtn('↗','Share',    e=>{e.stopPropagation();openShareModal(log);});
        actions.appendChild(tailBtn); actions.appendChild(dlBtn); actions.appendChild(shareBtn);
        item.appendChild(typeTag); item.appendChild(info); item.appendChild(actions);
        frag.appendChild(item);
    });
    container.replaceChildren(frag);
}

function makeBtn(text, title, handler) {
    const b=document.createElement('button'); b.className='btn btn-ghost btn-sm';
    b.title=title; b.textContent=text; b.addEventListener('click',handler); return b;
}

// ── Output Files ──────────────────────────────────────────────────────────────
function updateOutputFiles() {
    const container=document.getElementById('outputFiles'), countBadge=document.getElementById('outputCount');
    const outputs=dashboardData.outputs??[];
    countBadge.textContent=`${outputs.length} file${outputs.length!==1?'s':''}`;
    if (!outputs.length) { container.replaceChildren(buildEmptyState('◫','No output files generated yet.')); return; }
    const frag=document.createDocumentFragment();
    outputs.forEach(file => {
        const item=document.createElement('div');
        item.className='file-item'; item.setAttribute('role','listitem');
        item.setAttribute('tabindex','0'); item.title=`${file.name} — ${formatFileSize(file.size??0)}`;
        item.addEventListener('click',  ()=>downloadFile(file));
        item.addEventListener('keydown',e=>{if(e.key==='Enter')downloadFile(file);});

        const icon=document.createElement('div'); icon.className='file-icon'; icon.setAttribute('aria-hidden','true'); icon.textContent=file.icon??'📄';
        const name=document.createElement('div'); name.className='file-name'; name.textContent=file.name??'—';
        const meta=document.createElement('div'); meta.className='file-meta';
        meta.appendChild(document.createTextNode(formatFileSize(file.size??0)));
        const tsEl=document.createElement('div'); tsEl.className='file-ts'; tsEl.appendChild(buildTimeEl(file.timestamp)); meta.appendChild(tsEl);

        const shareBtn=document.createElement('button'); shareBtn.className='btn btn-ghost btn-sm file-share-btn';
        shareBtn.textContent='↗ Share'; shareBtn.title='Share this file';
        shareBtn.addEventListener('click',e=>{e.stopPropagation();openShareModal(file);});

        item.appendChild(icon); item.appendChild(name); item.appendChild(meta); item.appendChild(shareBtn);
        frag.appendChild(item);
    });
    container.replaceChildren(frag);
}

// ── History ───────────────────────────────────────────────────────────────────
function updateHistory() { renderHistoryRows(dashboardData.history??[]); }

function filterHistory() {
    const cat=document.getElementById('scriptFilter')?.value??'all';
    const status=document.getElementById('statusFilter')?.value??'all';
    const src=document.getElementById('sourceFilter')?.value??'all';
    const toolNames=['network_tools','core_protocols','ip_addressing','network_master','networking_basics','switching_routing','security_fundamentals'];
    let f=dashboardData.history??[];
    if(cat!=='all')f=f.filter(i=>i.category===cat);
    if(status!=='all')f=f.filter(i=>i.status===status);
    if(src!=='all')f=f.filter(i=>{ const t=toolNames.some(n=>(i.log_name??i.name).includes(n)); return src==='tool'?t:!t; });
    renderHistoryRows(f);
}

function renderHistoryRows(items) {
    const tbody=document.getElementById('historyTable');
    if (!items?.length) {
        const tr=document.createElement('tr'), td=document.createElement('td');
        td.setAttribute('colspan','7'); td.className='empty-row'; td.textContent='No matching results';
        tr.appendChild(td); tbody.replaceChildren(tr); return;
    }
    const frag=document.createDocumentFragment();
    items.forEach(item=>{
        const tr=document.createElement('tr');
        const cells=[
            ()=>{ const td=document.createElement('td'); td.appendChild(buildTimeEl(item.timestamp)); return td; },
            ()=>{ const td=document.createElement('td'); td.className='td-script'; td.textContent=item.name??'—'; return td; },
            ()=>{
                const td=document.createElement('td'), span=document.createElement('span');
                span.className=`cat-badge cat-${sanitizeClass(item.category??'other')}`; span.textContent=item.category??'—'; td.appendChild(span); return td;
            },
            ()=>{
                const td=document.createElement('td'), span=document.createElement('span');
                span.className=`status ${sanitizeClass(item.status)}`; span.textContent=(item.status??'unknown').toUpperCase(); td.appendChild(span); return td;
            },
            ()=>{ const td=document.createElement('td'); td.textContent=item.duration??'—'; return td; },
            ()=>{ const td=document.createElement('td'); td.className='td-muted'; td.textContent=formatFileSize(item.size??0); return td; },
            ()=>{
                const td=document.createElement('td');
                const viewBtn=makeBtn('View','View log',()=>openLogByName(item.log_name??item.name,item.name));
                td.appendChild(viewBtn);
                if(item.log_name){
                    const tb=makeBtn('⟳ Tail','Live tail',()=>openTail({dir:'logs',name_param:item.log_name,name:item.log_name}));
                    tb.style.marginLeft='4px'; td.appendChild(tb);
                }
                const sb=makeBtn('↗','Share',()=>openShareModal(item)); sb.style.marginLeft='4px'; td.appendChild(sb);
                return td;
            },
        ];
        cells.forEach(fn=>tr.appendChild(fn())); frag.appendChild(tr);
    });
    tbody.replaceChildren(frag);
}

// ── Log Viewer Modal ──────────────────────────────────────────────────────────
function openLog(logObj) { stopTail(); currentLogFile=logObj; showModal(logObj.name,logObj.dir,logObj.name_param); }

function openLogByName(logName, displayName) {
    const log=(dashboardData.logs??[]).find(l=>l.name===logName||l.name_param===logName);
    if(log) openLog(log);
    else if(logName) openLog({name:logName,dir:'logs',name_param:logName});
    else showToast(`No log found for ${displayName}`,'error');
}

async function showModal(displayName, dir, nameParam) {
    const modal=document.getElementById('logModal'), content=document.getElementById('logContent');
    const title=document.getElementById('modalTitle'), meta=document.getElementById('modalMeta');
    const tailBadge=document.getElementById('tailBadge');
    title.textContent=displayName??'Log Viewer'; meta.textContent=`${dir}/${nameParam}`;
    content.textContent='Loading…'; tailBadge?.classList.remove('active');
    modal.classList.add('active'); trapFocus(modal);
    try {
        const res=await fetch(`/api/file?dir=${encodeURIComponent(dir)}&name=${encodeURIComponent(nameParam)}`);
        content.textContent=res.ok?await res.text():await buildFallbackContent(displayName);
        content.scrollTop=content.scrollHeight;
    } catch { content.textContent='Server not reachable.\n\nStart it with:\n  cd dashboard && python3 server.py'; }
}

async function openTail(logObj) {
    stopTail(); currentLogFile=logObj;
    const modal=document.getElementById('logModal'),content=document.getElementById('logContent');
    const title=document.getElementById('modalTitle'),meta=document.getElementById('modalMeta');
    const tailBadge=document.getElementById('tailBadge');
    title.textContent=`⟳ LIVE — ${logObj.name_param??logObj.name}`; meta.textContent=`${logObj.dir??'logs'}/${logObj.name_param??logObj.name}`;
    content.textContent='Connecting to live tail…'; tailBadge?.classList.add('active');
    modal.classList.add('active'); trapFocus(modal);
    async function fetchTail() {
        try {
            const res=await fetch(`/api/tail?dir=${encodeURIComponent(logObj.dir??'logs')}&name=${encodeURIComponent(logObj.name_param??logObj.name)}&lines=120`);
            if(!res.ok){content.textContent='File not found or server error.';return;}
            const data=await res.json();
            if(data.mtime!==tailLastMtime){tailLastMtime=data.mtime;content.textContent=data.lines.join('\n');content.scrollTop=content.scrollHeight;}
        } catch {}
    }
    await fetchTail(); tailInterval=setInterval(fetchTail,TAIL_POLL_MS);
}

function stopTail() { if(tailInterval){clearInterval(tailInterval);tailInterval=null;} document.getElementById('tailBadge')?.classList.remove('active'); }

function closeModal() { stopTail(); document.getElementById('logModal').classList.remove('active'); currentLogFile=null; }

async function copyLogContent() {
    const text=document.getElementById('logContent')?.textContent??'';
    try { await navigator.clipboard.writeText(text); showToast('Copied to clipboard','success'); }
    catch { showToast('Copy failed — try selecting manually','error'); }
}

function downloadCurrentLog() { if(currentLogFile) downloadFile(currentLogFile); }

async function buildFallbackContent(name) {
    return `=== Demo / offline view for: ${name} ===\n\n[INFO] Server returned a non-OK response.\n[INFO] Start: cd dashboard && python3 server.py\n[INFO] Then refresh the dashboard.\n`;
}

// ── Social Share Modal (NEW) ──────────────────────────────────────────────────
let _shareTarget = null;

function openShareModal(item) {
    _shareTarget = item;
    const modal = document.getElementById('shareModal'); if (!modal) return;
    const name  = item.name ?? item.log_name ?? 'unknown';
    const title = `🔒 CyberDeck Report: ${name}`;
    const text  = buildShareText(item);
    document.getElementById('shareTitle').textContent     = name;
    document.getElementById('sharePreviewText').textContent = text;
    document.getElementById('emailSubject').value = title;
    document.getElementById('emailBody').value    = text;
    document.getElementById('emailTo').value      = '';
    modal.classList.add('active');
    trapFocus(modal);
}

function buildShareText(item) {
    const lines = ['📊 Networking & Cybersecurity Automation Toolkit — Execution Report', ''];
    if (item.name)      lines.push(`Script/Tool: ${item.name}`);
    if (item.category)  lines.push(`Category:    ${item.category}`);
    if (item.status)    lines.push(`Status:      ${item.status.toUpperCase()}`);
    if (item.duration)  lines.push(`Duration:    ${item.duration}`);
    if (item.size)      lines.push(`Size:        ${formatFileSize(item.size)}`);
    if (item.timestamp) lines.push(`Time:        ${new Date(item.timestamp).toLocaleString()}`);
    lines.push('', '— Generated by CyberDeck Dashboard');
    return lines.join('\n');
}

function closeShareModal() { document.getElementById('shareModal')?.classList.remove('active'); _shareTarget=null; }

function shareToTwitter() {
    if (!_shareTarget) return;
    const text = encodeURIComponent(`🔒 CyberDeck Report: ${_shareTarget.name??''} | Status: ${(_shareTarget.status??'').toUpperCase()} | #CyberSecurity #Automation`);
    window.open(`https://twitter.com/intent/tweet?text=${text}`, '_blank', 'noopener');
}

function shareToLinkedIn() {
    if (!_shareTarget) return;
    const url = encodeURIComponent(window.location.href);
    const title = encodeURIComponent(`CyberDeck Security Report — ${_shareTarget.name??''}`);
    window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${url}&title=${title}`, '_blank', 'noopener');
}

function shareToReddit() {
    if (!_shareTarget) return;
    const title = encodeURIComponent(`CyberDeck — ${_shareTarget.name??''} [${(_shareTarget.status??'').toUpperCase()}]`);
    const url   = encodeURIComponent(window.location.href);
    window.open(`https://reddit.com/submit?url=${url}&title=${title}`, '_blank', 'noopener');
}

async function copyShareLink() {
    const text = document.getElementById('sharePreviewText')?.textContent??'';
    try { await navigator.clipboard.writeText(text); showToast('Copied to clipboard','success'); }
    catch { showToast('Copy failed','error'); }
}

async function sendShareEmail() {
    const to      = document.getElementById('emailTo')?.value?.trim();
    const subject = document.getElementById('emailSubject')?.value?.trim();
    const body    = document.getElementById('emailBody')?.value?.trim();
    if (!to) { showToast('Please enter an email address','error'); return; }
    const btn = document.getElementById('sendEmailBtn');
    if (btn) { btn.disabled=true; btn.textContent='Sending…'; }
    try {
        const res = await fetch('/api/notify-email', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({to,subject,body}),
        });
        const data = await res.json();
        if (data.sent) {
            showToast(`Email sent to ${to}`,'success');
            closeShareModal();
        } else {
            showToast(data.error??'Email failed. Configure SMTP in server.','error');
        }
    } catch { showToast('Server not reachable','error'); }
    finally { if(btn){btn.disabled=false;btn.textContent='Send Email';} }
}

// ── Alert Settings Modal (NEW) ─────────────────────────────────────────────────
function openAlertModal() {
    const modal=document.getElementById('alertModal'); if(!modal) return;
    const d=sysStatsData?.thresholds;
    if(d){
        setInputVal('alertCpuWarn', d.cpu_warn??70);
        setInputVal('alertCpuCrit', d.cpu_crit??90);
        setInputVal('alertMemWarn', d.mem_warn??75);
        setInputVal('alertMemCrit', d.mem_crit??90);
        setInputVal('alertDiskWarn',d.disk_warn??80);
        setInputVal('alertDiskCrit',d.disk_crit??95);
    }
    modal.classList.add('active'); trapFocus(modal);
}

function closeAlertModal() { document.getElementById('alertModal')?.classList.remove('active'); }

async function saveAlertSettings() {
    const payload = {
        cpu_warn:  +getInputVal('alertCpuWarn'),
        cpu_crit:  +getInputVal('alertCpuCrit'),
        mem_warn:  +getInputVal('alertMemWarn'),
        mem_crit:  +getInputVal('alertMemCrit'),
        disk_warn: +getInputVal('alertDiskWarn'),
        disk_crit: +getInputVal('alertDiskCrit'),
        email_to:  getInputVal('alertEmailTo'),
        email_notify: document.getElementById('alertEmailNotify')?.checked??false,
    };
    try {
        const res=await fetch('/api/alert-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
        if(res.ok){showToast('Alert settings saved','success');closeAlertModal();}
        else showToast('Save failed','error');
    } catch { showToast('Server not reachable','error'); }
}

// ── Search ────────────────────────────────────────────────────────────────────
async function runSearch(query) {
    const panel=document.getElementById('searchResults'), counter=document.getElementById('searchCount');
    if(!panel) return;
    if(!query||query.trim().length<2){clearSearchResults();return;}
    panel.classList.add('active'); panel.innerHTML='<div class="search-loading">Searching…</div>';
    try {
        const res=await fetch(`/api/search?q=${encodeURIComponent(query.trim())}&limit=40`);
        if(!res.ok) throw new Error();
        const data=await res.json();
        if(counter) counter.textContent=data.total>0?`${data.total} hit${data.total!==1?'s':''}`:'';
        if(!data.results.length){panel.innerHTML='<div class="search-empty">No matches found.</div>';return;}
        const frag=document.createDocumentFragment();
        data.results.forEach(r=>{
            const row=document.createElement('div'); row.className='search-result-row';
            row.addEventListener('click',()=>{ const log=(dashboardData.logs??[]).find(l=>l.name===r.file); openLog(log??{name:r.file,dir:r.dir??'logs',name_param:r.file}); clearSearchResults(); });
            row.innerHTML=`<div class="sr-file">${escHtml(r.file)} <span class="sr-line">line ${r.line}</span></div>
              <div class="sr-content">${highlightMatch(escHtml(r.content),query)}</div>`;
            frag.appendChild(row);
        });
        panel.innerHTML=''; panel.appendChild(frag);
    } catch { panel.innerHTML='<div class="search-empty">Search unavailable — start server.py first.</div>'; }
}

function highlightMatch(text,query){return text.replace(new RegExp(`(${escHtml(query)})`,'gi'),'<mark>$1</mark>');}
function clearSearchResults(){const p=document.getElementById('searchResults'),c=document.getElementById('searchCount');if(p){p.innerHTML='';p.classList.remove('active');}if(c)c.textContent='';}

// ── Download ──────────────────────────────────────────────────────────────────
async function downloadFile(fileObj) {
    const dir=fileObj.dir??'logs', name=fileObj.name_param??fileObj.name;
    try {
        const res=await fetch(`/api/file?dir=${encodeURIComponent(dir)}&name=${encodeURIComponent(name)}`);
        if(res.ok){
            const blob=await res.blob(), url=URL.createObjectURL(blob);
            const a=Object.assign(document.createElement('a'),{href:url,download:name});
            document.body.appendChild(a); a.click(); URL.revokeObjectURL(url); a.remove();
            showToast(`Downloaded: ${name}`,'success');
        } else showToast('Download failed — server returned error','error');
    } catch { showToast('Server not running — start server.py first','error'); }
}

// ── Refresh ───────────────────────────────────────────────────────────────────
async function refreshDashboard() {
    const el=document.getElementById('liveStatus'); if(el) el.textContent='Refreshing…';
    await loadDashboardData(); await loadMetrics(); await loadSystemStats();
    if(el) el.textContent=autoRefreshOn?'Live':'Paused';
    showToast('Dashboard refreshed','success');
}

function toggleAutoRefresh() {
    autoRefreshOn=!autoRefreshOn; sessionStorage.setItem('autoRefresh',autoRefreshOn);
    applyAutoRefreshState(); showToast(autoRefreshOn?'Auto-refresh enabled':'Auto-refresh paused');
}

function applyAutoRefreshState() {
    clearInterval(refreshTimer);
    const btn=document.getElementById('autoRefreshBtn'), indicator=document.querySelector('.live-indicator'), el=document.getElementById('liveStatus');
    if(autoRefreshOn){
        refreshTimer=setInterval(()=>{loadDashboardData();loadMetrics();},REFRESH_MS);
        btn?.setAttribute('aria-pressed','true'); indicator?.classList.remove('paused'); if(el) el.textContent='Live';
    } else {
        btn?.setAttribute('aria-pressed','false'); indicator?.classList.add('paused'); if(el) el.textContent='Paused';
    }
}

// ── Export ────────────────────────────────────────────────────────────────────
function exportReport() {
    const ts=new Date().toLocaleString(), d=dashboardData, s=d.stats??{}, m=metricsData??{};
    let report=`╔══════════════════════════════════════════════════╗\n║  Cybersecurity Automation Toolkit — Report      ║\n║  Generated: ${ts.padEnd(37)}║\n╚══════════════════════════════════════════════════╝\n\nSTATISTICS\n${'─'.repeat(40)}\n`
        +`Total Scans: ${s.total??0}\nSuccessful: ${s.successful??0}\nWarnings: ${s.warnings??0}\nFailed: ${s.failed??0}\nSuccess Rate: ${m.success_rate??'—'}%\nAvg Duration: ${m.avg_duration_s?`${Math.floor(m.avg_duration_s/60)}m ${m.avg_duration_s%60}s`:'—'}\nDisk (Logs): ${formatFileSize(m.disk?.logs_bytes??0)}\nDisk (Output): ${formatFileSize(m.disk?.outputs_bytes??0)}\n\n`;

    if (sysStatsData?.available) {
        const sys=sysStatsData;
        report+=`SYSTEM STATS\n${'─'.repeat(40)}\nCPU: ${sys.cpu?.percent}% (${sys.cpu?.level?.toUpperCase()})\nMemory: ${sys.memory?.percent}% used (${formatFileSize((sys.memory?.used_mb??0)*1_048_576)} / ${formatFileSize((sys.memory?.total_mb??0)*1_048_576)})\nDisk: ${sys.disk?.percent}% used — ${sys.disk?.free_gb?.toFixed(1)} GB free\nNetwork: Sent ${formatFileSize(sys.network?.bytes_sent??0)}, Recv ${formatFileSize(sys.network?.bytes_recv??0)}\n\n`;
    }

    report+=`EXECUTION HISTORY\n${'─'.repeat(40)}\n`;
    (d.history??[]).forEach(i=>{report+=`Script: ${i.name}\nCategory: ${i.category}\nStatus: ${(i.status??'').toUpperCase()}\nDuration: ${i.duration}\nTime: ${i.timestamp}\n${'─'.repeat(30)}\n`;});
    report+=`\nLOG FILES (${(d.logs??[]).length})\n${'─'.repeat(40)}\n`;
    (d.logs??[]).forEach(l=>{report+=`[${(l.source??'script').toUpperCase()}] ${l.name}  —  ${formatFileSize(l.size??0)}  —  ${l.timestamp}\n`;});
    report+=`\nOUTPUT FILES (${(d.outputs??[]).length})\n${'─'.repeat(40)}\n`;
    (d.outputs??[]).forEach(f=>{report+=`${f.name}  —  ${formatFileSize(f.size??0)}\n`;});
    report+=`\n${'═'.repeat(50)}\nEnd of Report\n`;

    const blob=new Blob([report],{type:'text/plain'}), url=URL.createObjectURL(blob);
    const a=Object.assign(document.createElement('a'),{href:url,download:`security_report_${getTimestamp()}.txt`});
    document.body.appendChild(a); a.click(); URL.revokeObjectURL(url); a.remove();
    showToast('Report exported','success');
}

// ── UI Helpers ────────────────────────────────────────────────────────────────
function updateLastUpdate(){const el=document.getElementById('lastUpdate');if(!el)return;const n=new Date();el.textContent=n.toLocaleTimeString();el.dateTime=n.toISOString();}

let toastTimeout=null;
function showToast(message,type=''){
    const t=document.getElementById('toast');if(!t)return;
    clearTimeout(toastTimeout); t.textContent=message;
    t.className=`toast${type?` toast-${type}`:''} show`;
    toastTimeout=setTimeout(()=>t.classList.remove('show'),3200);
}

function trapFocus(el){
    const sel='button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])';
    const f=el.querySelectorAll(sel); if(!f.length)return;
    const first=f[0],last=f[f.length-1]; first.focus();
    const h=e=>{if(e.key!=='Tab')return;if(e.shiftKey){if(document.activeElement===first){e.preventDefault();last.focus();}}else{if(document.activeElement===last){e.preventDefault();first.focus();}}if(!el.classList.contains('active'))el.removeEventListener('keydown',h);};
    el.addEventListener('keydown',h);
}

function buildEmptyState(glyph,message){const d=document.createElement('div');d.className='empty-state';const i=document.createElement('div');i.className='empty-glyph';i.setAttribute('aria-hidden','true');i.textContent=glyph;const p=document.createElement('p');p.textContent=message;d.appendChild(i);d.appendChild(p);return d;}
function buildTimeEl(iso){const el=document.createElement('time');el.dateTime=iso??'';el.textContent=formatTimestampText(iso);el.title=iso?new Date(iso).toLocaleString():'';return el;}
function setText(id,val){const el=document.getElementById(id);if(el)el.textContent=String(val);}
function setInputVal(id,val){const el=document.getElementById(id);if(el)el.value=val;}
function getInputVal(id){return document.getElementById(id)?.value??'';}
function cap(s){return s.charAt(0).toUpperCase()+s.slice(1);}
function formatTimestampText(iso){if(!iso)return'—';const d=new Date(iso);if(isNaN(d))return'—';const diff=Date.now()-d.getTime();if(diff<60_000)return'Just now';if(diff<3_600_000)return`${Math.floor(diff/60_000)}m ago`;if(diff<86_400_000)return`${Math.floor(diff/3_600_000)}h ago`;return d.toLocaleString();}
function formatFileSize(bytes){if(bytes<1_024)return`${bytes} B`;if(bytes<1_048_576)return`${(bytes/1_024).toFixed(1)} KB`;return`${(bytes/1_048_576).toFixed(1)} MB`;}
function getTimestamp(){const n=new Date();return[n.getFullYear(),String(n.getMonth()+1).padStart(2,'0'),String(n.getDate()).padStart(2,'0'),'_',String(n.getHours()).padStart(2,'0'),String(n.getMinutes()).padStart(2,'0'),String(n.getSeconds()).padStart(2,'0')].join('');}
function escHtml(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function sanitizeClass(s){return(s??'').replace(/[^a-z0-9-_]/gi,'').toLowerCase();}