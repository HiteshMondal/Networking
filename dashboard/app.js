// Dashboard State
let dashboardData = {
    logs: [],
    outputs: [],
    history: [],
    stats: {
        total: 0,
        successful: 0,
        warnings: 0,
        failed: 0
    }
};

let currentLogFile = null;

// Initialize dashboard on load
document.addEventListener('DOMContentLoaded', function() {
    loadDashboardData();
    setInterval(loadDashboardData, 30000); // Auto-refresh every 30 seconds
});

// Load all dashboard data
async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard-data');
        if (response.ok) {
            dashboardData = await response.json();
            updateDashboard();
        } else {
            // Fallback to demo data if API not available
            loadDemoData();
        }
    } catch (error) {
        console.log('Loading demo data (server not available)');
        loadDemoData();
    }
}

// Load demo data for testing
function loadDemoData() {
    const now = new Date();
    
    dashboardData = {
        logs: generateDemoLogs(),
        outputs: generateDemoOutputs(),
        history: generateDemoHistory(),
        stats: {
            total: 15,
            successful: 12,
            warnings: 2,
            failed: 1
        }
    };
    
    updateDashboard();
}

// Generate demo logs
function generateDemoLogs() {
    const scripts = [
        'detect_suspicious_net_linux.sh',
        'system_info.sh',
        'secure_system.sh',
        'forensic_collect.sh',
        'web_recon.sh'
    ];
    
    return scripts.map((script, i) => ({
        name: `${script}_${getTimestamp()}.log`,
        script: script,
        timestamp: new Date(Date.now() - i * 3600000).toISOString(),
        size: Math.floor(Math.random() * 50000) + 1000,
        path: `../logs/${script}_${getTimestamp()}.log`
    }));
}

// Generate demo outputs
function generateDemoOutputs() {
    const outputs = [
        { name: 'system_report.txt', icon: '📄', size: 15234 },
        { name: 'network_scan.json', icon: '🔍', size: 8765 },
        { name: 'security_audit.html', icon: '🔒', size: 23456 },
        { name: 'forensic_data.zip', icon: '📦', size: 156789 },
        { name: 'recon_results.csv', icon: '📊', size: 4321 }
    ];
    
    return outputs.map(out => ({
        ...out,
        timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
        path: `../output/${out.name}`
    }));
}

// Generate demo history
function generateDemoHistory() {
    const scripts = [
        { name: 'detect_suspicious_net_linux.sh', category: 'network', status: 'success', duration: '2m 34s' },
        { name: 'system_info.sh', category: 'security', status: 'success', duration: '1m 12s' },
        { name: 'secure_system.sh', category: 'security', status: 'success', duration: '3m 45s' },
        { name: 'forensic_collect.sh', category: 'forensic', status: 'warning', duration: '5m 23s' },
        { name: 'web_recon.sh', category: 'recon', status: 'success', duration: '4m 01s' },
        { name: 'detect_suspicious_net_linux.sh', category: 'network', status: 'error', duration: '0m 15s' },
    ];
    
    return scripts.map((script, i) => ({
        ...script,
        timestamp: new Date(Date.now() - i * 7200000).toISOString()
    }));
}

// Update all dashboard components
function updateDashboard() {
    updateStats();
    updateRecentActivity();
    updateLogFiles();
    updateOutputFiles();
    updateHistory();
    updateLastUpdate();
}

// Update statistics cards
function updateStats() {
    document.getElementById('totalScans').textContent = dashboardData.stats.total;
    document.getElementById('successfulScans').textContent = dashboardData.stats.successful;
    document.getElementById('warningScans').textContent = dashboardData.stats.warnings;
    document.getElementById('failedScans').textContent = dashboardData.stats.failed;
}

// Update recent activity
function updateRecentActivity() {
    const container = document.getElementById('recentActivity');
    
    if (!dashboardData.history || dashboardData.history.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📭</div>
                <p>No recent activity. Run a script to get started.</p>
            </div>
        `;
        return;
    }
    
    const recentItems = dashboardData.history.slice(0, 5);
    container.innerHTML = recentItems.map(item => `
        <div class="activity-item ${item.status}">
            <div class="activity-header">
                <span class="activity-title">${item.name}</span>
                <span class="activity-time">${formatTimestamp(item.timestamp)}</span>
            </div>
            <div class="activity-description">
                Status: <strong>${item.status.toUpperCase()}</strong> • 
                Duration: ${item.duration} • 
                Category: ${item.category}
            </div>
        </div>
    `).join('');
}

// Update log files list
function updateLogFiles() {
    const container = document.getElementById('logFiles');
    const countBadge = document.getElementById('logCount');
    
    if (!dashboardData.logs || dashboardData.logs.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📄</div>
                <p>No log files available.</p>
            </div>
        `;
        countBadge.textContent = '0 files';
        return;
    }
    
    countBadge.textContent = `${dashboardData.logs.length} files`;
    
    container.innerHTML = dashboardData.logs.map(log => `
        <div class="log-item" onclick="viewLog('${log.path}', '${log.name}')">
            <div class="log-info">
                <div class="log-name">📝 ${log.name}</div>
                <div class="log-meta">
                    ${formatTimestamp(log.timestamp)} • ${formatFileSize(log.size)}
                </div>
            </div>
            <div class="log-actions">
                <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); downloadFile('${log.path}', '${log.name}')">
                    📥 Download
                </button>
            </div>
        </div>
    `).join('');
}

// Update output files grid
function updateOutputFiles() {
    const container = document.getElementById('outputFiles');
    const countBadge = document.getElementById('outputCount');
    
    if (!dashboardData.outputs || dashboardData.outputs.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📦</div>
                <p>No output files generated yet.</p>
            </div>
        `;
        countBadge.textContent = '0 files';
        return;
    }
    
    countBadge.textContent = `${dashboardData.outputs.length} files`;
    
    container.innerHTML = dashboardData.outputs.map(file => `
        <div class="file-item" onclick="downloadFile('${file.path}', '${file.name}')">
            <div class="file-icon">${file.icon}</div>
            <div class="file-name">${file.name}</div>
            <div class="file-size">${formatFileSize(file.size)}</div>
        </div>
    `).join('');
}

// Update execution history table
function updateHistory() {
    const tbody = document.getElementById('historyTable');
    
    if (!dashboardData.history || dashboardData.history.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No execution history available</td></tr>';
        return;
    }
    
    tbody.innerHTML = dashboardData.history.map(item => `
        <tr>
            <td>${formatTimestamp(item.timestamp)}</td>
            <td>${item.name}</td>
            <td><span class="badge badge-info">${item.category}</span></td>
            <td><span class="status ${item.status}">${item.status.toUpperCase()}</span></td>
            <td>${item.duration}</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="viewScriptLog('${item.name}')">
                    View Log
                </button>
            </td>
        </tr>
    `).join('');
}

// Filter history by category
function filterHistory() {
    const filter = document.getElementById('scriptFilter').value;
    const tbody = document.getElementById('historyTable');
    
    let filtered = dashboardData.history;
    if (filter !== 'all') {
        filtered = dashboardData.history.filter(item => item.category === filter);
    }
    
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No matching results</td></tr>';
        return;
    }
    
    tbody.innerHTML = filtered.map(item => `
        <tr>
            <td>${formatTimestamp(item.timestamp)}</td>
            <td>${item.name}</td>
            <td><span class="badge badge-info">${item.category}</span></td>
            <td><span class="status ${item.status}">${item.status.toUpperCase()}</span></td>
            <td>${item.duration}</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="viewScriptLog('${item.name}')">
                    View Log
                </button>
            </td>
        </tr>
    `).join('');
}

// View log file in modal
async function viewLog(path, name) {
    currentLogFile = { path, name };
    const modal = document.getElementById('logModal');
    const content = document.getElementById('logContent');
    const title = document.getElementById('modalTitle');
    
    title.textContent = name;
    content.textContent = 'Loading...';
    modal.classList.add('active');
    
    try {
        const response = await fetch(`/api/file?path=${encodeURIComponent(path)}`);
        if (response.ok) {
            const text = await response.text();
            content.textContent = text;
        } else {
            content.textContent = `Demo log content for ${name}\n\n` +
                `=== Execution started at ${new Date().toLocaleString()} ===\n\n` +
                `[INFO] Initializing script...\n` +
                `[INFO] Performing security checks...\n` +
                `[INFO] Analyzing network traffic...\n` +
                `[SUCCESS] Scan completed successfully\n` +
                `[INFO] Results saved to output directory\n\n` +
                `=== Execution completed at ${new Date().toLocaleString()} ===`;
        }
    } catch (error) {
        content.textContent = 'Error loading log file. The server may not be running.\n\n' +
            'To view actual logs, start the Python server with:\n' +
            'cd dashboard && python3 server.py';
    }
}

// View script log by name
function viewScriptLog(scriptName) {
    const log = dashboardData.logs.find(l => l.script === scriptName);
    if (log) {
        viewLog(log.path, log.name);
    }
}

// Close modal
function closeModal() {
    document.getElementById('logModal').classList.remove('active');
}

// Download current log
function downloadCurrentLog() {
    if (currentLogFile) {
        downloadFile(currentLogFile.path, currentLogFile.name);
    }
}

// Download file
async function downloadFile(path, name) {
    try {
        const response = await fetch(`/api/file?path=${encodeURIComponent(path)}`);
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = name;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } else {
            alert('File download not available in demo mode. Start the server to enable downloads.');
        }
    } catch (error) {
        alert('Server not running. Start the Python server to download files.');
    }
}

// Refresh dashboard
function refreshDashboard() {
    const badge = document.getElementById('activityBadge');
    badge.textContent = 'Refreshing...';
    
    loadDashboardData();
    
    setTimeout(() => {
        badge.textContent = 'Live';
    }, 1000);
}

// Export report
function exportReport() {
    const report = generateReport();
    const blob = new Blob([report], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_report_${getTimestamp()}.txt`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

// Generate text report
function generateReport() {
    const timestamp = new Date().toLocaleString();
    
    let report = `
╔════════════════════════════════════════════════════════════╗
║   Cybersecurity Automation Toolkit - Summary Report       ║
║   Generated: ${timestamp.padEnd(42)}║
╚════════════════════════════════════════════════════════════╝

STATISTICS
----------
Total Scans:      ${dashboardData.stats.total}
Successful:       ${dashboardData.stats.successful}
Warnings:         ${dashboardData.stats.warnings}
Failed:           ${dashboardData.stats.failed}

RECENT EXECUTIONS
-----------------
`;

    dashboardData.history.forEach(item => {
        report += `
Script:    ${item.name}
Category:  ${item.category}
Status:    ${item.status.toUpperCase()}
Duration:  ${item.duration}
Time:      ${formatTimestamp(item.timestamp)}
---
`;
    });

    report += `
LOG FILES (${dashboardData.logs.length})
---------
`;

    dashboardData.logs.forEach(log => {
        report += `${log.name} - ${formatFileSize(log.size)} - ${formatTimestamp(log.timestamp)}\n`;
    });

    report += `
OUTPUT FILES (${dashboardData.outputs.length})
------------
`;

    dashboardData.outputs.forEach(file => {
        report += `${file.name} - ${formatFileSize(file.size)}\n`;
    });

    report += `
════════════════════════════════════════════════════════════
End of Report
`;

    return report;
}

// Update last update timestamp
function updateLastUpdate() {
    document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
}

// Utility: Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    
    return date.toLocaleString();
}

// Utility: Format file size
function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

// Utility: Get timestamp string
function getTimestamp() {
    const now = new Date();
    return now.getFullYear() +
        String(now.getMonth() + 1).padStart(2, '0') +
        String(now.getDate()).padStart(2, '0') + '_' +
        String(now.getHours()).padStart(2, '0') +
        String(now.getMinutes()).padStart(2, '0') +
        String(now.getSeconds()).padStart(2, '0');
}

// Close modal on outside click
window.onclick = function(event) {
    const modal = document.getElementById('logModal');
    if (event.target === modal) {
        closeModal();
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Escape to close modal
    if (e.key === 'Escape') {
        closeModal();
    }
    
    // Ctrl/Cmd + R to refresh
    if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
        e.preventDefault();
        refreshDashboard();
    }
});