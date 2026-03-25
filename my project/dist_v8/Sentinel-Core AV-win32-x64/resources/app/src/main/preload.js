const { contextBridge, ipcRenderer } = require('electron');

// ─── Secure Bridge: Renderer ↔ Main Process ─────────────────────
contextBridge.exposeInMainWorld('sentinel', {
    // Window controls
    minimize: () => ipcRenderer.invoke('window-minimize'),
    maximize: () => ipcRenderer.invoke('window-maximize'),
    close: () => ipcRenderer.invoke('window-close'),

    // USB Devices
    getDevices: () => ipcRenderer.invoke('get-devices'),
    ejectDevice: (driveLetter) => ipcRenderer.invoke('eject-device', driveLetter),

    // Scanning
    startScan: (path) => ipcRenderer.invoke('start-scan', path),
    cancelScan: () => ipcRenderer.invoke('cancel-scan'),
    pauseScan: () => ipcRenderer.invoke('pause-scan'),
    resumeScan: () => ipcRenderer.invoke('resume-scan'),
    browseFolder: () => ipcRenderer.invoke('browse-folder'),

    // Threats & History
    getThreats: (limit) => ipcRenderer.invoke('get-threats', limit),
    getScanHistory: (limit) => ipcRenderer.invoke('get-scan-history', limit),
    getStats: () => ipcRenderer.invoke('get-stats'),

    // Quarantine
    getQuarantined: () => ipcRenderer.invoke('get-quarantined'),
    restoreFile: (id) => ipcRenderer.invoke('restore-file', id),
    deleteQuarantined: (id) => ipcRenderer.invoke('delete-quarantined', id),

    // Settings
    getSettings: () => ipcRenderer.invoke('get-settings'),
    updateSettings: (settings) => ipcRenderer.invoke('update-settings', settings),

    // Reports
    exportReport: (format) => ipcRenderer.invoke('export-report', format),

    // Auto-Updater
    installUpdate: () => ipcRenderer.invoke('install-update'),

    // Game Mode
    getGameMode: () => ipcRenderer.invoke('get-game-mode'),
    toggleGameMode: (enabled) => ipcRenderer.invoke('toggle-game-mode', enabled),

    // Honeypot
    deployHoneypot: (driveLetter) => ipcRenderer.invoke('deploy-honeypot', driveLetter),

    // Utils
    openFolder: (path) => ipcRenderer.invoke('open-folder', path),

    // Event listeners from main process
    on: (channel, callback) => {
        const validChannels = [
            'usb-attached', 'usb-detached', 'usb-interception-prompt',
            'scan-started', 'scan-progress', 'scan-complete', 'scan-error',
            'toast', 'navigate',
            'game-mode-changed', 'ransomware-alert',
            'trigger-quick-scan',
            'update-available', 'update-downloaded'
        ];
        if (validChannels.includes(channel)) {
            const subscription = (event, ...args) => callback(...args);
            ipcRenderer.on(channel, subscription);
            return () => ipcRenderer.removeListener(channel, subscription);
        }
    },

    removeAllListeners: (channel) => {
        ipcRenderer.removeAllListeners(channel);
    }
});
