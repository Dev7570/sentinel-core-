const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog, shell } = require('electron');

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (require('electron-squirrel-startup')) {
    app.quit();
}

const { autoUpdater } = require('electron-updater');
const path = require('path');
const UsbMonitor = require('../engine/usb-monitor');
const Scanner = require('../engine/scanner');
const Arbiter = require('../engine/arbiter');
const Quarantine = require('../engine/quarantine');
const Watchdog = require('../engine/watchdog');
const Honeypot = require('../engine/honeypot');
const ThreatDB = require('../engine/threat-db');
const GameMode = require('../engine/game-mode');
const RealtimeWatcher = require('../engine/realtime-watcher');

let mainWindow;
let tray;
let usbMonitor;
let scanner;
let arbiter;
let quarantine;
let watchdog;
let honeypot;
let threatDB;
let gameMode;
let realtimeWatcher;

// ─── App Data Path (set lazily after app ready) ──────────────────
let APP_DATA_DIR = null;


// ─── Create Main Window ──────────────────────────────────────────
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        minWidth: 1024,
        minHeight: 700,
        frame: false,
        transparent: false,
        backgroundColor: '#0a0e1a',
        icon: path.join(__dirname, '..', '..', 'assets', 'icon.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: false
        },
        titleBarStyle: 'hidden',
        titleBarOverlay: {
            color: '#0a0e1a',
            symbolColor: '#00e5ff',
            height: 36
        }
    });

    mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

    mainWindow.on('close', (e) => {
        if (!app.isQuitting) {
            e.preventDefault();
            mainWindow.hide();
        }
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// ─── System Tray ─────────────────────────────────────────────────
function createTray() {
    const iconPath = path.join(__dirname, '..', '..', 'assets', 'icon.png');
    let trayIcon;
    try {
        trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
    } catch {
        trayIcon = nativeImage.createEmpty();
    }

    tray = new Tray(trayIcon);
    tray.setToolTip('Sentinel-Core AV — Protection Active');

    const contextMenu = Menu.buildFromTemplate([
        {
            label: '🛡️ Sentinel-Core AV',
            enabled: false,
        },
        { type: 'separator' },
        {
            label: 'Open Dashboard',
            click: () => {
                if (mainWindow) {
                    mainWindow.show();
                    mainWindow.focus();
                }
            }
        },
        {
            label: 'Quick Scan USB',
            click: () => sendToRenderer('trigger-quick-scan')
        },
        {
            label: 'Scan History',
            click: () => {
                if (mainWindow) {
                    mainWindow.show();
                    sendToRenderer('navigate', 'threats');
                }
            }
        },
        { type: 'separator' },
        {
            label: 'Game Mode',
            type: 'checkbox',
            checked: false,
            click: (menuItem) => {
                if (gameMode) gameMode.setManualOverride(menuItem.checked);
                sendToRenderer('game-mode-changed', menuItem.checked);
            }
        },
        { type: 'separator' },
        {
            label: 'Quit Sentinel-Core',
            click: () => {
                app.isQuitting = true;
                app.quit();
            }
        }
    ]);

    tray.setContextMenu(contextMenu);
    tray.on('double-click', () => {
        if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
        }
    });
}

// ─── Initialize Engine Modules ───────────────────────────────────
function initializeEngines() {
    // Threat Database (must be first)
    threatDB = new ThreatDB(APP_DATA_DIR);

    // Quarantine Vault
    quarantine = new Quarantine(APP_DATA_DIR, threatDB);

    // Scanner
    scanner = new Scanner(threatDB);

    // Arbiter
    arbiter = new Arbiter();

    // USB Monitor
    usbMonitor = new UsbMonitor();
    usbMonitor.on('device-added', (device) => {
        sendToRenderer('usb-attached', device);
        
        // Auto-focus the app and show the Interception Modal for premium UX
        if (mainWindow) {
            if (mainWindow.isMinimized()) mainWindow.restore();
            mainWindow.show();
            mainWindow.focus();
        }
        sendToRenderer('usb-interception-prompt', device);

        if (!gameMode || !gameMode.isActive()) {
            sendToRenderer('toast', {
                type: 'info',
                title: 'USB Device Detected',
                message: `Drive ${device.driveLetter || device.deviceName} connected.`
            });
        }
    });
    usbMonitor.on('device-removed', (device) => {
        sendToRenderer('usb-detached', device);
    });

    // Honeypot
    honeypot = new Honeypot(threatDB);
    honeypot.on('canary-triggered', (event) => {
        sendToRenderer('toast', {
            type: 'critical',
            title: '🚨 Ransomware Alert!',
            message: `Canary file modified on ${event.drive}. Possible ransomware activity detected!`
        });
        sendToRenderer('ransomware-alert', event);
    });

    // Game Mode
    gameMode = new GameMode();
    gameMode.on('mode-changed', (isActive) => {
        sendToRenderer('game-mode-changed', isActive);
    });

    // Watchdog
    watchdog = new Watchdog();
    watchdog.start();

    // Realtime Watcher
    realtimeWatcher = new RealtimeWatcher();
    if (threatDB.getSettings().realtimeEnabled === 'true') {
        realtimeWatcher.start();
    }
    
    realtimeWatcher.on('file-created', async (filePath) => {
        if (!scanner || !arbiter) return;
        try {
            const result = await scanner.scanFile(filePath);
            const verdict = arbiter.evaluate(result);
            
            if (verdict === 'MALICIOUS') {
                await quarantine.quarantineFile(filePath, { ...result, verdict });
                threatDB.logThreat({ ...result, verdict });
                sendToRenderer('toast', {
                    type: 'danger',
                    title: 'System Protection',
                    message: `Intercepted and quarantined newly created malicious file: ${path.basename(filePath)}`
                });
            } else if (verdict === 'SUSPICIOUS') {
                threatDB.logThreat({ ...result, verdict });
                sendToRenderer('toast', {
                    type: 'warning',
                    title: 'System Protection',
                    message: `Suspicious file intercepted on disk: ${path.basename(filePath)}`
                });
            }
        } catch (err) { }
    });

    usbMonitor.startMonitoring();
    gameMode.startMonitoring();
}

// ─── IPC Handlers ────────────────────────────────────────────────
function setupIPC() {
    // Auto Updater
    autoUpdater.on('update-available', (info) => sendToRenderer('update-available', info));
    autoUpdater.on('update-downloaded', (info) => sendToRenderer('update-downloaded', info));
    ipcMain.handle('install-update', () => autoUpdater.quitAndInstall());

    // Window controls
    ipcMain.handle('window-minimize', () => mainWindow?.minimize());
    ipcMain.handle('window-maximize', () => {
        if (mainWindow?.isMaximized()) mainWindow.unmaximize();
        else mainWindow?.maximize();
    });
    ipcMain.handle('window-close', () => mainWindow?.hide());

    // Get connected USB devices
    ipcMain.handle('get-devices', async () => {
        return usbMonitor ? usbMonitor.getDevices() : [];
    });

    // Start scan on a path
    ipcMain.handle('start-scan', async (event, scanPath) => {
        if (!scanner || !arbiter) return { error: 'Engine not ready' };

        const scanId = Date.now().toString(36);
        sendToRenderer('scan-started', { scanId, path: scanPath });

        try {
            const results = await scanner.scanDirectory(scanPath, (progress) => {
                sendToRenderer('scan-progress', { scanId, ...progress });
            });

            const verdicts = results.map(r => ({
                ...r,
                verdict: arbiter.evaluate(r),
                explanation: arbiter.explain(r)
            }));

            // Auto-quarantine malicious files
            const threats = verdicts.filter(v => v.verdict === 'MALICIOUS');
            for (const threat of threats) {
                await quarantine.quarantineFile(threat.filePath, threat);
            }

            // Log to database
            threatDB.logScan({
                scanId,
                path: scanPath,
                totalFiles: results.length,
                threats: threats.length,
                suspicious: verdicts.filter(v => v.verdict === 'SUSPICIOUS').length,
                timestamp: Date.now()
            });

            for (const threat of verdicts.filter(v => v.verdict !== 'CLEAN')) {
                threatDB.logThreat(threat);
            }

            sendToRenderer('scan-complete', { scanId, results: verdicts });

            if (threats.length > 0) {
                sendToRenderer('toast', {
                    type: 'danger',
                    title: `${threats.length} Threat(s) Found!`,
                    message: `Scan complete. ${threats.length} malicious file(s) quarantined.`
                });
            } else {
                sendToRenderer('toast', {
                    type: 'success',
                    title: 'Scan Complete',
                    message: `All ${results.length} files are clean.`
                });
            }

            return { scanId, results: verdicts };
        } catch (err) {
            sendToRenderer('scan-error', { scanId, error: err.message });
            return { error: err.message };
        }
    });

    // Cancel in-progress scan
    ipcMain.handle('cancel-scan', async () => {
        if (scanner) {
            scanner.cancelScan();
            return { success: true };
        }
        return { success: false };
    });

    ipcMain.handle('pause-scan', async () => {
        if (scanner) {
            scanner.pauseScan();
            return { success: true };
        }
        return { success: false };
    });

    ipcMain.handle('resume-scan', async () => {
        if (scanner) {
            scanner.resumeScan();
            return { success: true };
        }
        return { success: false };
    });

    // Get threat history
    ipcMain.handle('get-threats', async (event, limit = 100) => {
        return threatDB ? threatDB.getRecentThreats(limit) : [];
    });

    // Get scan history
    ipcMain.handle('get-scan-history', async (event, limit = 50) => {
        return threatDB ? threatDB.getScanHistory(limit) : [];
    });

    // Get stats
    ipcMain.handle('get-stats', async () => {
        return threatDB ? threatDB.getStats() : {};
    });

    // Quarantine operations
    ipcMain.handle('get-quarantined', async () => {
        return quarantine ? quarantine.getQuarantinedFiles() : [];
    });

    ipcMain.handle('restore-file', async (event, quarantineId) => {
        return quarantine ? quarantine.restoreFile(quarantineId) : { error: 'Not available' };
    });

    ipcMain.handle('delete-quarantined', async (event, quarantineId) => {
        return quarantine ? quarantine.permanentDelete(quarantineId) : { error: 'Not available' };
    });

    // Safe eject
    ipcMain.handle('eject-device', async (event, driveLetter) => {
        return usbMonitor ? usbMonitor.safeEject(driveLetter) : { error: 'Not available' };
    });

    // Settings
    ipcMain.handle('get-settings', async () => {
        return threatDB ? threatDB.getSettings() : {};
    });

    ipcMain.handle('update-settings', async (event, settings) => {
        if (threatDB) threatDB.updateSettings(settings);
        
        if (settings.realtimeEnabled === 'true' && realtimeWatcher) {
            realtimeWatcher.start();
        } else if (settings.realtimeEnabled === 'false' && realtimeWatcher) {
            realtimeWatcher.stop();
        }
        
        return { success: true };
    });

    // Export report
    ipcMain.handle('export-report', async (event, format) => {
        const data = threatDB.exportData(format);
        const { filePath } = await dialog.showSaveDialog(mainWindow, {
            defaultPath: `sentinel-report-${Date.now()}.${format}`,
            filters: [
                { name: format.toUpperCase(), extensions: [format] }
            ]
        });
        if (filePath) {
            require('fs').writeFileSync(filePath, data);
            return { success: true, path: filePath };
        }
        return { cancelled: true };
    });

    // Open folder in explorer
    ipcMain.handle('open-folder', async (event, folderPath) => {
        shell.openPath(folderPath);
    });

    // Browse for folder
    ipcMain.handle('browse-folder', async () => {
        const result = await dialog.showOpenDialog(mainWindow, {
            properties: ['openDirectory']
        });
        return result.canceled ? null : result.filePaths[0];
    });

    // Game mode
    ipcMain.handle('get-game-mode', async () => {
        return gameMode ? gameMode.isActive() : false;
    });

    ipcMain.handle('toggle-game-mode', async (event, enabled) => {
        if (gameMode) gameMode.setManualOverride(enabled);
        return { success: true };
    });

    // Deploy honeypot
    ipcMain.handle('deploy-honeypot', async (event, driveLetter) => {
        return honeypot ? honeypot.deploy(driveLetter) : { error: 'Not available' };
    });
}

// ─── Helpers ─────────────────────────────────────────────────────
function sendToRenderer(channel, data) {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send(channel, data);
    }
}

// ─── App Lifecycle ───────────────────────────────────────────────
app.whenReady().then(() => {
    APP_DATA_DIR = path.join(app.getPath('userData'), 'SentinelCoreAV');
    createWindow();
    createTray();
    initializeEngines();
    setupIPC();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });

    // Quietly check for updates in the background on startup
    autoUpdater.checkForUpdatesAndNotify().catch((err) => console.log('Update check skipped:', err.message));
});

app.on('window-all-closed', () => {
    // Keep running in tray on Windows
    if (process.platform !== 'darwin' && app.isQuitting) {
        app.quit();
    }
});

app.on('before-quit', () => {
    app.isQuitting = true;
    if (usbMonitor) usbMonitor.stopMonitoring();
    if (gameMode) gameMode.stopMonitoring();
    if (watchdog) watchdog.stop();
    if (honeypot) honeypot.stopAll();
});
