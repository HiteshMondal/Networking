let currentPlatform = 'linux';
        let activeScans = 0;
        let threatsDetected = 0;

        const tools = {
            security: [
                {
                    name: 'Secure System',
                    script: 'secure_system',
                    description: 'Harden system security settings and configurations',
                    status: 'ready'
                },
                {
                    name: 'Detect Suspicious Network',
                    script: 'detect_suspicious_net',
                    description: 'Monitor and detect suspicious network activities',
                    status: 'ready'
                },
                {
                    name: 'Revert Security',
                    script: 'revert_security',
                    description: 'Restore original security settings',
                    status: 'ready'
                }
            ],
            forensic: [
                {
                    name: 'Forensic Collection',
                    script: 'forensic_collect',
                    description: 'Collect system artifacts for forensic analysis',
                    status: 'ready'
                },
                {
                    name: 'System Information',
                    script: 'system_info',
                    description: 'Gather comprehensive system information',
                    status: 'ready'
                }
            ],
            recon: [
                {
                    name: 'Web Reconnaissance',
                    script: 'web_recon',
                    description: 'Perform web-based reconnaissance and enumeration',
                    status: 'ready'
                }
            ]
        };

        function selectPlatform(platform) {
            currentPlatform = platform;
            document.querySelectorAll('.platform-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            logToTerminal(`Platform switched to ${platform.toUpperCase()}`, 'info');
            renderTools();
        }

        function renderTools() {
            renderToolSection('securityTools', tools.security);
            renderToolSection('forensicTools', tools.forensic);
            renderToolSection('reconTools', tools.recon);
        }

        function renderToolSection(elementId, toolList) {
            const container = document.getElementById(elementId);
            container.innerHTML = '';

            toolList.forEach((tool, index) => {
                const card = document.createElement('div');
                card.className = 'tool-card';
                card.innerHTML = `
                    <div class="tool-header">
                        <div class="tool-name">${tool.name}</div>
                        <div class="tool-status status-${tool.status}">${tool.status.toUpperCase()}</div>
                    </div>
                    <div class="tool-description">${tool.description}</div>
                    <div class="tool-actions">
                        <button class="btn btn-primary" onclick="runTool('${tool.script}', '${tool.name}')">
                            ▶️ Run
                        </button>
                        <button class="btn btn-secondary" onclick="viewScript('${tool.script}')">
                            📄 View
                        </button>
                    </div>
                `;
                container.appendChild(card);
            });
        }

        function runTool(script, name) {
            const ext = currentPlatform === 'windows' ? 'bat' : 'sh';
            const path = `scripts/${script}_${currentPlatform === 'windows' ? 'windows' : 'linux'}.${ext}`;
            
            logToTerminal(`Executing: ${name} (${path})`, 'info');
            activeScans++;
            document.getElementById('activeScans').textContent = activeScans;
            
            // Simulate execution
            setTimeout(() => {
                const success = Math.random() > 0.3;
                if (success) {
                    logToTerminal(`✓ ${name} completed successfully`, 'info');
                    const threats = Math.floor(Math.random() * 5);
                    if (threats > 0) {
                        threatsDetected += threats;
                        document.getElementById('threatsDetected').textContent = threatsDetected;
                        logToTerminal(`⚠️ Found ${threats} potential issue(s)`, 'warning');
                    }
                } else {
                    logToTerminal(`✗ ${name} encountered an error`, 'error');
                }
                activeScans--;
                document.getElementById('activeScans').textContent = activeScans;
                updateLastScan();
            }, 2000 + Math.random() * 3000);
        }

        function viewScript(script) {
            const ext = currentPlatform === 'windows' ? 'bat' : 'sh';
            const path = `scripts/${script}_${currentPlatform === 'windows' ? 'windows' : 'linux'}.${ext}`;
            logToTerminal(`Script location: ${path}`, 'info');
        }

        function logToTerminal(message, type = 'info') {
            const terminal = document.getElementById('terminalOutput');
            const time = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            entry.className = `log-entry log-${type}`;
            entry.innerHTML = `<span class="log-time">[${time}]</span> ${message}`;
            terminal.appendChild(entry);
            terminal.scrollTop = terminal.scrollHeight;
        }

        function updateLastScan() {
            const now = new Date();
            const timeStr = now.toLocaleTimeString();
            document.getElementById('lastScan').textContent = timeStr;
        }

        // Initialize dashboard
        renderTools();
        logToTerminal('Dashboard loaded. All systems operational.', 'info');