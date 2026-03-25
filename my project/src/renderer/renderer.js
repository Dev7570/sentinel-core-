/**
 * Sentinel-Core AV — Renderer Process
 * UI logic, panel management, data binding, and event handling.
 */

// ─── App Controller ──────────────────────────────────────────────
const App = {
    isScanning: false,
    scanPaused: false,
    gameModeActive: false,
    activityLog: [],

    // ── Initialize ───────────────────────────────────────────────
    async init() {
        this.setupNavigation();
        this.setupEventListeners();
        this.setupDragAndDrop();
        await this.refreshDashboard();
        await this.loadSettings();
    },

    // ── Navigation ───────────────────────────────────────────────
    setupNavigation() {
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const panel = btn.dataset.panel;
                if (panel) this.navigateTo(panel);
            });
        });
    },

    navigateTo(panelName) {
        // Deactivate all
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));

        // Activate target
        const btn = document.querySelector(`.nav-btn[data-panel="${panelName}"]`);
        const panel = document.getElementById(`panel${this.capitalize(panelName)}`);

        if (btn) btn.classList.add('active');
        if (panel) panel.classList.add('active');

        this.currentPanel = panelName;

        // Refresh panel data
        switch (panelName) {
            case 'dashboard': this.refreshDashboard(); break;
            case 'devices': this.refreshDevices(); break;
            case 'threats': this.refreshThreats(); break;
            case 'quarantine': this.refreshQuarantine(); break;
        }
    },

    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    },

    // ── Event Listeners (from Main Process) ──────────────────────
    setupEventListeners() {
        if (!window.sentinel) return;

        window.sentinel.on('usb-attached', (device) => {
            this.addActivity('info', `USB connected: ${device.deviceName} (${device.driveLetter})`);
            this.refreshDevices();
            this.updateDeviceBadge();
        });

        window.sentinel.on('usb-detached', (device) => {
            this.addActivity('info', `USB removed: ${device.deviceName || 'Unknown'}`);
            this.refreshDevices();
            this.updateDeviceBadge();
        });

        window.sentinel.on('scan-started', (data) => {
            this.showScanProgress(true);
        });

        window.sentinel.on('scan-progress', (data) => {
            this.updateScanProgress(data);
        });

        window.sentinel.on('scan-complete', (data) => {
            this.showScanProgress(false);
            this.showScanResults(data.results);
            this.refreshDashboard();
        });

        window.sentinel.on('scan-error', (data) => {
            this.showScanProgress(false);
            this.showToast('danger', 'Scan Error', data.error);
        });

        window.sentinel.on('toast', (data) => {
            this.showToast(data.type, data.title, data.message);
        });

        window.sentinel.on('navigate', (panel) => {
            this.navigateTo(panel);
        });

        window.sentinel.on('game-mode-changed', (isActive) => {
            this.gameModeActive = isActive;
            const banner = document.getElementById('gameModeBanner');
            if (banner) banner.style.display = isActive ? 'flex' : 'none';
        });

        window.sentinel.on('ransomware-alert', (event) => {
            this.showRansomwareAlert(event);
        });

        window.sentinel.on('trigger-quick-scan', () => {
            this.triggerQuickScan();
        });

        window.sentinel.on('update-available', (info) => {
            this.showToast('info', 'Update Available', 'A new version of Sentinel-Core AV is downloading in the background.');
            this.addActivity('info', `Update available: v${info?.version || 'new'}`);
        });

        window.sentinel.on('update-downloaded', (info) => {
            const msg = `Version ${info?.version || 'new'} is ready. <br><button class="btn btn-primary btn-sm" onclick="window.sentinel.installUpdate()" style="margin-top:10px">Restart & Install</button>`;
            this.showToast('success', 'Update Ready', msg);
            this.addActivity('info', `Update v${info?.version || 'new'} complete and ready to install.`);
        });

        // Special USB Interception Modal handling
        window.sentinel.on('usb-interception-prompt', (device) => {
            this.currentInterceptionDevice = device;
            document.getElementById('usbInterceptionMessage').textContent = `Drive ${device.driveLetter || device.deviceName} has been connected. What would you like to do?`;
            document.getElementById('usbInterceptionModal').style.display = 'flex';
        });

        document.getElementById('btnUsbIgnore')?.addEventListener('click', () => {
            document.getElementById('usbInterceptionModal').style.display = 'none';
        });
        document.getElementById('btnUsbQuickScan')?.addEventListener('click', async () => {
            document.getElementById('usbInterceptionModal').style.display = 'none';
            if (this.currentInterceptionDevice) {
                await window.sentinel.updateSettings({ scanDepth: 'quick' });
                this.startScan(this.currentInterceptionDevice.driveLetter + '\\');
            }
        });
        document.getElementById('btnUsbFullScan')?.addEventListener('click', async () => {
            document.getElementById('usbInterceptionModal').style.display = 'none';
            if (this.currentInterceptionDevice) {
                await window.sentinel.updateSettings({ scanDepth: 'full' });
                this.startScan(this.currentInterceptionDevice.driveLetter + '\\');
            }
        });
    },

    // ── Drag & Drop ──────────────────────────────────────────────
    setupDragAndDrop() {
        const dropZone = document.getElementById('scanDropZone');
        if (!dropZone) return;

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('drag-over');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                const path = files[0].path;
                if (path) this.startScan(path);
            }
        });
    },

    // ── Dashboard ────────────────────────────────────────────────
    async refreshDashboard(isManualClick = false) {
        if (!window.sentinel) return;

        const btnIcon = document.querySelector('#btnRefreshDashboard svg');
        if (isManualClick && btnIcon) {
            btnIcon.classList.add('spin-animation');
        }

        try {
            const stats = await window.sentinel.getStats();
            document.getElementById('valTotalScans').textContent = this.formatNumber(stats.totalScans || 0);
            document.getElementById('valFilesScanned').textContent = this.formatNumber(stats.totalFilesScanned || 0);
            document.getElementById('valThreatsFound').textContent = this.formatNumber(stats.totalThreats || 0);
            document.getElementById('valQuarantined').textContent = this.formatNumber(stats.quarantineCount || 0);

            // Update threat badge
            if (stats.recentThreats > 0) {
                const badge = document.getElementById('threatBadge');
                badge.textContent = stats.recentThreats;
                badge.style.display = 'inline';
            }
            
            if (isManualClick) {
                this.showToast('success', 'Dashboard Refreshed', 'Security metrics and activity logs updated.');
            }
        } catch (err) {
            // Stats unavailable
        } finally {
            if (isManualClick && btnIcon) {
                setTimeout(() => btnIcon.classList.remove('spin-animation'), 600);
            }
        }

    this.renderActivityList();
    },

    scrollToActivity() {
        const activityCard = document.querySelector('.activity-card');
        const content = document.querySelector('.main-content');
        if (activityCard && content) {
            content.scrollTo({
                top: activityCard.offsetTop - 20,
                behavior: 'smooth'
            });
        }
    },

    // ── Devices Panel ────────────────────────────────────────────
    async refreshDevices() {
        if (!window.sentinel) return;

        const btnIcon = document.querySelector('#btnRefreshDevices svg');
        if (btnIcon) btnIcon.classList.add('spin-animation');

        const grid = document.getElementById('devicesGrid');
        try {
            const devices = await window.sentinel.getDevices();
            this.updateDeviceBadge(devices.length);

            if (devices.length === 0) {
                grid.innerHTML = `
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="currentColor" stroke-width="1" opacity="0.2"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/></svg>
                        <h3>No USB Devices Detected</h3>
                        <p>Plug in a USB drive to start monitoring and scanning.</p>
                    </div>`;
                this.showToast('info', 'Devices Refreshed', 'No mounted USB drives found.');
                return;
            }

            grid.innerHTML = devices.map(d => this.renderDeviceCard(d)).join('');
            this.showToast('success', 'Devices Refreshed', `Successfully scanned ${devices.length} hardware mount(s).`);
        } catch {
            // Keep existing content
        } finally {
            if (btnIcon) {
                setTimeout(() => btnIcon.classList.remove('spin-animation'), 600);
            }
        }
    },

    renderDeviceCard(device) {
        const totalGB = (device.totalSize / (1024 ** 3)).toFixed(1);
        const freeGB = (device.freeSpace / (1024 ** 3)).toFixed(1);
        const usedPercent = device.totalSize > 0
            ? Math.round(((device.totalSize - device.freeSpace) / device.totalSize) * 100)
            : 0;

        return `
            <div class="device-card">
                <div class="device-header">
                    <div class="device-icon">
                        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/></svg>
                    </div>
                    <div>
                        <div class="device-name">${this.escapeHtml(device.deviceName)}</div>
                        <div class="device-letter">${this.escapeHtml(device.driveLetter)}</div>
                    </div>
                </div>
                <div class="device-stats">
                    <span>${freeGB} GB free</span>
                    <span>${totalGB} GB total</span>
                </div>
                <div class="device-bar">
                    <div class="device-bar-fill" style="width: ${usedPercent}%"></div>
                </div>
                <div class="device-actions">
                    <button class="btn btn-primary btn-sm" onclick="App.startScan('${this.escapeHtml(device.driveLetter)}\\\\')">
                        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        Scan
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="App.deployHoneypot('${this.escapeHtml(device.driveLetter)}')">
                        🍯 Honeypot
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="App.ejectDevice('${this.escapeHtml(device.driveLetter)}')">
                        ⏏ Eject
                    </button>
                </div>
            </div>`;
    },

    updateDeviceBadge(count) {
        const badge = document.getElementById('deviceBadge');
        if (count === undefined) {
            if (window.sentinel) {
                window.sentinel.getDevices().then(devices => {
                    badge.textContent = devices.length;
                    badge.style.display = devices.length > 0 ? 'inline' : 'none';
                });
            }
            return;
        }
        badge.textContent = count;
        badge.style.display = count > 0 ? 'inline' : 'none';
    },

    // ── Scanning ─────────────────────────────────────────────────
    async startScan(scanPath) {
        if (this.isScanning) {
            this.showToast('info', 'Scan in Progress', 'Please wait for the current scan to finish.');
            return;
        }

        this.isScanning = true;
        this.navigateTo('scan');
        this.showScanProgress(true);
        this.addActivity('info', `Scan started: ${scanPath}`);

        try {
            await window.sentinel.startScan(scanPath);
        } catch (err) {
            this.showToast('danger', 'Scan Failed', err.message);
            this.showScanProgress(false);
        }
        this.isScanning = false;
    },

    async togglePauseScan() {
        if (!this.isScanning || !window.sentinel) return;
        
        const btnText = document.getElementById('textPauseScan');
        const iconPause = document.getElementById('iconPause');
        const iconResume = document.getElementById('iconResume');

        this.scanPaused = !this.scanPaused;

        if (this.scanPaused) {
            btnText.textContent = 'Resume';
            iconPause.style.display = 'none';
            iconResume.style.display = 'inline-block';
            this.showToast('warning', 'Scan Paused', 'Background processing suspended.');
            this.addActivity('warning', 'Scan manually paused.');
            await window.sentinel.pauseScan();
        } else {
            btnText.textContent = 'Pause';
            iconPause.style.display = 'inline-block';
            iconResume.style.display = 'none';
            this.showToast('success', 'Scan Resumed', 'Background processing resumed.');
            this.addActivity('info', 'Scan resumed.');
            await window.sentinel.resumeScan();
        }
    },

    async cancelScan() {
        if (!this.isScanning || !window.sentinel) return;
        this.addActivity('info', 'Canceling scan...');
        this.showToast('info', 'Canceling', 'Stopping the scan engine...');

        this.scanPaused = false;
        const btnText = document.getElementById('textPauseScan');
        const iconPause = document.getElementById('iconPause');
        const iconResume = document.getElementById('iconResume');
        if (btnText) btnText.textContent = 'Pause';
        if (iconPause) iconPause.style.display = 'inline-block';
        if (iconResume) iconResume.style.display = 'none';

        await window.sentinel.cancelScan();
    },

    async triggerQuickScan() {
        if (!window.sentinel) return;
        const devices = await window.sentinel.getDevices();
        if (devices.length === 0) {
            this.showToast('info', 'No USB Drives', 'Please connect a USB drive to scan.');
            return;
        }
        this.startScan(devices[0].driveLetter + '\\');
    },

    async browseScan() {
        if (!window.sentinel) return;
        const folder = await window.sentinel.browseFolder();
        if (folder) this.startScan(folder);
    },

    showScanProgress(show) {
        const card = document.getElementById('scanProgressCard');
        const dropZone = document.getElementById('scanDropZone');
        const results = document.getElementById('scanResults');

        if (show) {
            if (card) card.style.display = 'block';
            if (dropZone) dropZone.style.display = 'none';
            if (results) results.style.display = 'none';
            
            document.getElementById('scanProgressBar').style.width = '0%';
            document.getElementById('scanPercentage').textContent = '0%';
            document.getElementById('scanCurrentFile').textContent = 'Preparing...';
            document.getElementById('scanFileCount').textContent = '0 / 0';
        } else {
            if (card) card.style.display = 'none';
            // Always show drop zone when progress is hidden
            if (dropZone) dropZone.style.display = 'block';
        }
    },

    updateScanProgress(data) {
        document.getElementById('scanProgressBar').style.width = data.percentage + '%';
        document.getElementById('scanPercentage').textContent = data.percentage + '%';
        document.getElementById('scanCurrentFile').textContent = data.currentFile || '';
        document.getElementById('scanFileCount').textContent = `${data.current} / ${data.total}`;
    },

    showScanResults(results) {
        const container = document.getElementById('scanResults');
        const list = document.getElementById('resultsList');
        const dropZone = document.getElementById('scanDropZone');
        const progressCard = document.getElementById('scanProgressCard');

        // Hide progress and ALWAYS ensure drop zone is visible
        if (progressCard) progressCard.style.display = 'none';
        if (dropZone) dropZone.style.display = 'block';

        const clean = results.filter(r => r.verdict === 'CLEAN').length;
        const suspicious = results.filter(r => r.verdict === 'SUSPICIOUS').length;
        const malicious = results.filter(r => r.verdict === 'MALICIOUS').length;

        document.getElementById('pillClean').textContent = `${clean} Clean`;
        document.getElementById('pillSuspicious').textContent = `${suspicious} Suspicious`;
        document.getElementById('pillMalicious').textContent = `${malicious} Malicious`;

        // Show only non-clean results, or first 20 if all clean
        const displayResults = results.filter(r => r.verdict !== 'CLEAN');
        const toShow = displayResults.length > 0 ? displayResults : results.slice(0, 20);

        list.innerHTML = toShow.map(r => `
            <div class="result-item ${(r.verdict || '').toLowerCase()}">
                <div class="result-verdict ${r.verdict}"></div>
                <div class="result-info">
                    <div class="result-name">${this.escapeHtml(r.fileName)}</div>
                    <div class="result-path">${this.escapeHtml(r.filePath)}</div>
                </div>
                <div class="result-explanation">
                    ${r.explanation ? r.explanation.summary || '' : r.verdict}
                </div>
            </div>
        `).join('');

        if (container) container.style.display = 'block';

        this.addActivity(
            malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean',
            `Scan complete: ${clean} clean, ${suspicious} suspicious, ${malicious} malicious`
        );
    },

    clearScanResults() {
        const container = document.getElementById('scanResults');
        const dropZone = document.getElementById('scanDropZone');
        if (container) container.style.display = 'none';
        if (dropZone) dropZone.style.display = 'block';
        this.showToast('info', 'View Cleared', 'Ready for a new scan.');
    },

    // ── Threats Panel ────────────────────────────────────────────
    async refreshThreats() {
        if (!window.sentinel) return;

        const list = document.getElementById('threatsList');
        try {
            const threats = await window.sentinel.getThreats(100);

            if (!threats || threats.length === 0) {
                list.innerHTML = `
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="currentColor" stroke-width="1" opacity="0.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                        <h3>No Threats Found</h3>
                        <p>Your system is clean. All scans came back negative.</p>
                    </div>`;
                return;
            }

            list.innerHTML = threats.map(t => {
                const severity = t.severity || 'MEDIUM';
                const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };
                return `
                    <div class="threat-card">
                        <div class="threat-severity ${severity}">
                            ${icons[severity] || '🟡'}
                        </div>
                        <div class="threat-info">
                            <div class="threat-name">${this.escapeHtml(t.threat_name || t.threatName || 'Unknown Threat')}</div>
                            <div class="threat-file">${this.escapeHtml(t.file_path || t.filePath || '')}</div>
                            <div class="threat-meta">
                                <span class="threat-tag ${t.verdict}">${t.verdict}</span>
                                <span>${severity}</span>
                                <span>${this.formatDate(t.timestamp)}</span>
                            </div>
                        </div>
                    </div>`;
            }).join('');
        } catch {
            // Keep existing
        }
    },

    // ── Quarantine Panel ─────────────────────────────────────────
    async refreshQuarantine() {
        if (!window.sentinel) return;

        const list = document.getElementById('quarantineList');
        try {
            const items = await window.sentinel.getQuarantined();

            if (!items || items.length === 0) {
                list.innerHTML = `
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24" width="64" height="64" fill="none" stroke="currentColor" stroke-width="1" opacity="0.2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        <h3>Quarantine Vault Empty</h3>
                        <p>No files are currently quarantined.</p>
                    </div>`;
                return;
            }

            list.innerHTML = items.map(q => `
                <div class="quarantine-card">
                    <div class="quarantine-icon">
                        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    </div>
                    <div class="quarantine-info">
                        <div class="quarantine-name">${this.escapeHtml(q.file_name || q.fileName)}</div>
                        <div class="quarantine-path">${this.escapeHtml(q.original_path || q.originalPath)}</div>
                        <div class="quarantine-meta">
                            <span>🛡 ${this.escapeHtml(q.threat_name || q.threatName)}</span>
                            <span>📦 ${this.formatSize(q.file_size || q.fileSize)}</span>
                            <span>📅 ${this.formatDate(q.quarantined_at || q.quarantinedAt)}</span>
                        </div>
                    </div>
                    <div class="quarantine-actions">
                        <button class="btn btn-ghost btn-sm" onclick="App.restoreFile('${q.quarantine_id || q.quarantineId}')" title="Restore file">
                            ↩ Restore
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="App.deleteQuarantined('${q.quarantine_id || q.quarantineId}')" title="Permanently delete">
                            🗑 Delete
                        </button>
                    </div>
                </div>
            `).join('');
        } catch {
            // Keep existing
        }
    },

    async restoreFile(quarantineId) {
        if (!window.sentinel) return;
        const result = await window.sentinel.restoreFile(quarantineId);
        if (result.success) {
            this.showToast('success', 'File Restored', `File restored to: ${result.restoredTo}`);
            this.refreshQuarantine();
            this.refreshDashboard();
        } else {
            this.showToast('danger', 'Restore Failed', result.error);
        }
    },

    async deleteQuarantined(quarantineId) {
        if (!window.sentinel) return;
        const result = await window.sentinel.deleteQuarantined(quarantineId);
        if (result.success) {
            this.showToast('success', 'Deleted', 'File permanently destroyed from vault.');
            this.refreshQuarantine();
            this.refreshDashboard();
        } else {
            this.showToast('danger', 'Delete Failed', result.error);
        }
    },

    // ── Device Actions ───────────────────────────────────────────
    async ejectDevice(driveLetter) {
        if (!window.sentinel) return;
        const result = await window.sentinel.ejectDevice(driveLetter);
        if (result.success) {
            this.showToast('success', 'Device Ejected', result.message);
            this.addActivity('info', `Safely ejected ${driveLetter}`);
            this.refreshDevices();
        } else {
            this.showToast('danger', 'Eject Failed', result.error);
        }
    },

    async deployHoneypot(driveLetter) {
        if (!window.sentinel) return;
        const result = await window.sentinel.deployHoneypot(driveLetter);
        if (result.success) {
            this.showToast('success', 'Honeypot Deployed', `${result.filesDeployed} canary files placed on ${driveLetter}`);
            this.addActivity('info', `Honeypot deployed on ${driveLetter}`);
        } else {
            this.showToast('danger', 'Honeypot Failed', result.error);
        }
    },

    // ── Settings ─────────────────────────────────────────────────
    async loadSettings() {
        if (!window.sentinel) return;
        try {
            const settings = await window.sentinel.getSettings();
            if (settings.autoScan !== undefined) document.getElementById('settAutoScan').checked = settings.autoScan === 'true';
            if (settings.scanDepth) document.getElementById('settScanDepth').value = settings.scanDepth;
            if (settings.virusTotalKey) document.getElementById('settVTKey').value = settings.virusTotalKey;
            if (settings.gameModeAuto !== undefined) document.getElementById('settGameMode').checked = settings.gameModeAuto === 'true';
            if (settings.quarantineRetentionDays) document.getElementById('settRetention').value = settings.quarantineRetentionDays;
            if (settings.notificationsEnabled !== undefined) document.getElementById('settNotifications').checked = settings.notificationsEnabled === 'true';
            if (settings.telemetryEnabled !== undefined) document.getElementById('settTelemetry').checked = settings.telemetryEnabled === 'true';
        } catch {}
    },

    async saveSettings() {
        if (!window.sentinel) return;
        const settings = {
            autoScan: document.getElementById('settAutoScan').checked.toString(),
            scanDepth: document.getElementById('settScanDepth').value,
            virusTotalKey: document.getElementById('settVTKey').value,
            gameModeAuto: document.getElementById('settGameMode').checked.toString(),
            quarantineRetentionDays: document.getElementById('settRetention').value,
            notificationsEnabled: document.getElementById('settNotifications').checked.toString(),
            telemetryEnabled: document.getElementById('settTelemetry').checked.toString()
        };

        await window.sentinel.updateSettings(settings);
        this.showToast('success', 'Settings Saved', 'Your preferences have been updated.');
    },

    // ── Game Mode ────────────────────────────────────────────────
    async toggleGameMode() {
        if (!window.sentinel) return;
        this.gameModeActive = !this.gameModeActive;
        await window.sentinel.toggleGameMode(this.gameModeActive);

        const banner = document.getElementById('gameModeBanner');
        banner.style.display = this.gameModeActive ? 'flex' : 'none';

        this.showToast(
            this.gameModeActive ? 'info' : 'success',
            this.gameModeActive ? 'Game Mode On' : 'Game Mode Off',
            this.gameModeActive
                ? 'Scan intensity reduced for better gaming performance.'
                : 'Full protection restored.'
        );
    },

    // ── Export ────────────────────────────────────────────────────
    async exportReport() {
        if (!window.sentinel) return;
        const result = await window.sentinel.exportReport('json');
        if (result.success) {
            this.showToast('success', 'Report Exported', `Saved to: ${result.path}`);
        }
    },

    // ── Ransomware Alert ─────────────────────────────────────────
    showRansomwareAlert(event) {
        const modal = document.getElementById('ransomwareModal');
        const msg = document.getElementById('ransomwareMessage');
        msg.textContent = event.message || 'A canary file was modified.';
        modal.style.display = 'flex';
        this.addActivity('malicious', `🚨 RANSOMWARE ALERT on ${event.drive}`);
    },

    dismissRansomwareAlert() {
        document.getElementById('ransomwareModal').style.display = 'none';
    },

    // ── Activity Log ─────────────────────────────────────────────
    addActivity(type, message) {
        this.activityLog.unshift({
            type,
            message,
            time: Date.now()
        });
        if (this.activityLog.length > 50) this.activityLog.pop();
        if (this.currentPanel === 'dashboard') this.renderActivityList();
    },

    renderActivityList() {
        const list = document.getElementById('activityList');
        if (!list) return;

        if (this.activityLog.length === 0) {
            list.innerHTML = `
                <div class="activity-empty">
                    <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                    <p>No recent activity. Plug in a USB drive to start scanning.</p>
                </div>`;
            return;
        }

        list.innerHTML = this.activityLog.slice(0, 15).map(a => `
            <div class="activity-item">
                <div class="activity-dot ${a.type}"></div>
                <span class="activity-text">${this.escapeHtml(a.message)}</span>
                <span class="activity-time">${this.formatTime(a.time)}</span>
            </div>
        `).join('');
    },

    // ── Toast System ─────────────────────────────────────────────
    showToast(type, title, message) {
        const container = document.getElementById('toastContainer');
        const icons = {
            success: '✅',
            danger: '⛔',
            info: 'ℹ️',
            critical: '🚨'
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || 'ℹ️'}</div>
            <div class="toast-content">
                <div class="toast-title">${this.escapeHtml(title)}</div>
                <div class="toast-message">${this.escapeHtml(message)}</div>
            </div>
            <button class="toast-close" onclick="this.parentElement.classList.add('hiding'); setTimeout(() => this.parentElement.remove(), 300)">×</button>
        `;

        container.appendChild(toast);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add('hiding');
                setTimeout(() => toast.remove(), 300);
            }
        }, 5000);
    },

    // ── Utilities ────────────────────────────────────────────────
    capitalize(str) {
        if (!str) return '';
        return str.charAt(0).toUpperCase() + str.slice(1);
    },

    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return String(num);
    },

    formatSize(bytes) {
        if (!bytes) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        let i = 0;
        let size = bytes;
        while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
        return size.toFixed(1) + ' ' + units[i];
    },

    formatDate(timestamp) {
        if (!timestamp) return '';
        const d = new Date(timestamp);
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    },

    formatTime(timestamp) {
        if (!timestamp) return '';
        const d = new Date(timestamp);
        return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    }
};

// ─── Start App ───────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => App.init());
