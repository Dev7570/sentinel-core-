const chokidar = require('chokidar');
const EventEmitter = require('events');
const os = require('os');
const path = require('path');
const fs = require('fs');

/**
 * RealtimeWatcher — Monitors highly targeted directories (Downloads, Desktop)
 * Instantly intercepts newly created files and pipes them to the scanning engine.
 */
class RealtimeWatcher extends EventEmitter {
    constructor() {
        super();
        this.watcher = null;
        this.enabled = false;
        
        const home = os.homedir();
        this.watchDirs = [
            path.join(home, 'Downloads'),
            path.join(home, 'Desktop')
        ];
        
        // Ignore temporary browser download extensions
        this.ignoreExts = new Set(['.crdownload', '.part', '.tmp', '.download']);
    }

    start() {
        if (this.enabled) return;
        this.enabled = true;
        
        // Ensure directories exist before watching
        const validDirs = this.watchDirs.filter(d => {
            try { return fs.existsSync(d) && fs.statSync(d).isDirectory(); } 
            catch { return false; }
        });

        if (validDirs.length === 0) return;

        this.watcher = chokidar.watch(validDirs, {
            ignored: /(^|[\/\\])\../, // ignore dotfiles
            persistent: true,
            ignoreInitial: true, // Only monitor newly created files, don't scan existing
            depth: 2
        });

        // Trigger on both file creation and when a file finishes downloading (rename)
        this.watcher.on('add', (filePath) => this._handleFile(filePath));
    }

    stop() {
        if (!this.enabled || !this.watcher) return;
        this.watcher.close();
        this.watcher = null;
        this.enabled = false;
    }

    _handleFile(filePath) {
        const ext = path.extname(filePath).toLowerCase();
        
        // Skip temporary files that are still streaming
        if (this.ignoreExts.has(ext)) return;
        
        // Wait a brief moment for file write locks / OS handles to be released
        setTimeout(() => {
            this.emit('file-created', filePath);
        }, 1500);
    }
}

module.exports = RealtimeWatcher;
