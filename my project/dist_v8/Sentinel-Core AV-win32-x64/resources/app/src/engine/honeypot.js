const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const chokidar = require('chokidar');

/**
 * Honeypot — Ransomware tripwire canary files
 * Creates hidden sentinel files on monitored drives.
 * If these files are modified/encrypted, it triggers an instant ransomware alert.
 */
class Honeypot extends EventEmitter {
    constructor(threatDB) {
        super();
        this.threatDB = threatDB;
        this.watchers = new Map(); // driveLetter → chokidar watcher
        this.CANARY_FILES = [
            '.canary_data',
            'Documents/.system_canary.dat',
            'Important/.backup_verify.dat'
        ];
        this.CANARY_CONTENT = 'SENTINEL-CORE-CANARY-v1:' + Date.now() + ':DO_NOT_MODIFY';
    }

    // ─── Deploy Canary Files ─────────────────────────────────────
    deploy(driveLetter) {
        try {
            const basePath = driveLetter.endsWith('\\') ? driveLetter : driveLetter + '\\';

            const deployedFiles = [];
            for (const canaryRelPath of this.CANARY_FILES) {
                const fullPath = path.join(basePath, canaryRelPath);
                const dir = path.dirname(fullPath);

                // Create directory if needed
                if (!fs.existsSync(dir)) {
                    fs.mkdirSync(dir, { recursive: true });
                }

                // Write canary file
                fs.writeFileSync(fullPath, this.CANARY_CONTENT, 'utf8');

                // Try to hide the file on Windows
                try {
                    require('child_process').execSync(`attrib +h +s "${fullPath}"`, { stdio: 'ignore' });
                } catch {}

                deployedFiles.push(fullPath);
            }

            // Start watching canary files
            this._watchCanaries(driveLetter, deployedFiles);

            // Log event
            if (this.threatDB) {
                this.threatDB.logCanaryEvent({
                    drive: driveLetter,
                    action: 'deployed',
                    files: deployedFiles.length,
                    timestamp: Date.now()
                });
            }

            return { success: true, filesDeployed: deployedFiles.length };
        } catch (err) {
            return { success: false, error: err.message };
        }
    }

    // ─── Watch Canary Files ──────────────────────────────────────
    _watchCanaries(driveLetter, filePaths) {
        // Stop existing watcher for this drive
        if (this.watchers.has(driveLetter)) {
            this.watchers.get(driveLetter).close();
        }

        const watcher = chokidar.watch(filePaths, {
            persistent: true,
            ignoreInitial: true,
            awaitWriteFinish: { stabilityThreshold: 500 }
        });

        watcher.on('change', (changedPath) => {
            this._onCanaryTriggered(driveLetter, changedPath, 'modified');
        });

        watcher.on('unlink', (deletedPath) => {
            this._onCanaryTriggered(driveLetter, deletedPath, 'deleted');
        });

        this.watchers.set(driveLetter, watcher);
    }

    // ─── Canary Triggered ────────────────────────────────────────
    _onCanaryTriggered(driveLetter, filePath, action) {
        const event = {
            drive: driveLetter,
            file: filePath,
            action,
            timestamp: Date.now(),
            severity: 'CRITICAL',
            message: `Ransomware canary ${action}! Possible encryption attack on drive ${driveLetter}`
        };

        // Log to database
        if (this.threatDB) {
            this.threatDB.logCanaryEvent(event);
        }

        // Emit alert
        this.emit('canary-triggered', event);
    }

    // ─── Stop Watching a Drive ───────────────────────────────────
    stopDrive(driveLetter) {
        if (this.watchers.has(driveLetter)) {
            this.watchers.get(driveLetter).close();
            this.watchers.delete(driveLetter);
        }
    }

    // ─── Stop All Watchers ───────────────────────────────────────
    stopAll() {
        for (const [, watcher] of this.watchers) {
            watcher.close();
        }
        this.watchers.clear();
    }
}

module.exports = Honeypot;
