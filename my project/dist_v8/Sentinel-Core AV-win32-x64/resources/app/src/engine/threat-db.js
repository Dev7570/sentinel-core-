const path = require('path');
const fs = require('fs');

/**
 * ThreatDB — SQLite database for threat intelligence, scan history, and quarantine records.
 * Uses sql.js (pure JS WASM SQLite) for zero-native-dependency operation.
 */
class ThreatDB {
    constructor(appDataDir) {
        this.dbDir = appDataDir;
        this.dbPath = path.join(this.dbDir, 'sentinel.db');
        this.db = null;
        this._ready = false;

        if (!fs.existsSync(this.dbDir)) {
            fs.mkdirSync(this.dbDir, { recursive: true });
        }

        this._initDatabase();
    }

    // ─── Initialize Database ─────────────────────────────────────
    async _initDatabase() {
        try {
            const initSqlJs = require('sql.js');
            const SQL = await initSqlJs();

            // Load existing DB or create new
            if (fs.existsSync(this.dbPath)) {
                const buffer = fs.readFileSync(this.dbPath);
                this.db = new SQL.Database(buffer);
            } else {
                this.db = new SQL.Database();
            }

            this._createTables();
            this._ready = true;
            this._save();
        } catch (err) {
            console.warn('sql.js unavailable, using in-memory fallback:', err.message);
            this._initFallbackStorage();
            this._ready = true;
        }
    }

    _createTables() {
        this.db.run(`
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,
                path TEXT,
                total_files INTEGER,
                threats INTEGER,
                suspicious INTEGER,
                timestamp INTEGER
            )
        `);
        this.db.run(`
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                file_name TEXT,
                file_hash TEXT,
                file_size INTEGER,
                verdict TEXT,
                threat_name TEXT,
                severity TEXT,
                explanation TEXT,
                scan_id TEXT,
                timestamp INTEGER
            )
        `);
        this.db.run(`
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarantine_id TEXT UNIQUE,
                original_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                file_hash TEXT,
                threat_name TEXT,
                threat_category TEXT,
                severity TEXT,
                encrypted_path TEXT,
                quarantined_at INTEGER
            )
        `);
        this.db.run(`
            CREATE TABLE IF NOT EXISTS canary_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                drive TEXT,
                file TEXT,
                action TEXT,
                severity TEXT,
                message TEXT,
                timestamp INTEGER
            )
        `);
        this.db.run(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        `);

        // Insert default settings
        const defaults = {
            autoScan: 'true', scanDepth: 'full', virusTotalKey: '',
            gameModeAuto: 'true', telemetryEnabled: 'false',
            quarantineRetentionDays: '30', notificationsEnabled: 'true', theme: 'dark',
            realtimeEnabled: 'false'
        };
        for (const [key, value] of Object.entries(defaults)) {
            this.db.run('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', [key, value]);
        }
    }

    _save() {
        if (this.db) {
            try {
                const data = this.db.export();
                const buffer = Buffer.from(data);
                fs.writeFileSync(this.dbPath, buffer);
            } catch {}
        }
    }

    // ─── Fallback In-Memory Storage ──────────────────────────────
    _initFallbackStorage() {
        this._memory = {
            scans: [], threats: [], quarantine: [], canaryEvents: [],
            settings: {
                autoScan: 'true', scanDepth: 'full', virusTotalKey: '',
                gameModeAuto: 'true', telemetryEnabled: 'false',
                quarantineRetentionDays: '30', notificationsEnabled: 'true', theme: 'dark',
                realtimeEnabled: 'false'
            }
        };
    }

    // ─── Helper: query all rows ──────────────────────────────────
    _queryAll(sql, params = []) {
        if (!this.db) return [];
        try {
            const stmt = this.db.prepare(sql);
            stmt.bind(params);
            const rows = [];
            while (stmt.step()) {
                const row = stmt.getAsObject();
                rows.push(row);
            }
            stmt.free();
            return rows;
        } catch { return []; }
    }

    _queryOne(sql, params = []) {
        const rows = this._queryAll(sql, params);
        return rows.length > 0 ? rows[0] : null;
    }

    _queryScalar(sql, params = []) {
        if (!this.db) return 0;
        try {
            const stmt = this.db.prepare(sql);
            stmt.bind(params);
            if (stmt.step()) {
                const val = stmt.get()[0];
                stmt.free();
                return val;
            }
            stmt.free();
            return 0;
        } catch { return 0; }
    }

    // ─── Scan Logging ────────────────────────────────────────────
    logScan(scan) {
        if (this.db) {
            this.db.run(
                'INSERT OR REPLACE INTO scans (scan_id, path, total_files, threats, suspicious, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
                [scan.scanId, scan.path, scan.totalFiles, scan.threats, scan.suspicious, scan.timestamp]
            );
            this._save();
        } else if (this._memory) {
            this._memory.scans.unshift(scan);
        }
    }

    getScanHistory(limit = 50) {
        if (this.db) return this._queryAll('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', [limit]);
        return (this._memory?.scans || []).slice(0, limit);
    }

    // ─── Threat Logging ──────────────────────────────────────────
    logThreat(threat) {
        if (this.db) {
            this.db.run(
                'INSERT INTO threats (file_path, file_name, file_hash, file_size, verdict, threat_name, severity, explanation, scan_id, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    threat.filePath, threat.fileName, threat.hash, threat.fileSize,
                    threat.verdict,
                    threat.signatureMatch?.name || 'Heuristic Detection',
                    threat.signatureMatch?.severity || 'MEDIUM',
                    JSON.stringify(threat.explanation || {}),
                    threat.scanId || null,
                    threat.scanTime || Date.now()
                ]
            );
            this._save();
        } else if (this._memory) {
            this._memory.threats.unshift(threat);
        }
    }

    getRecentThreats(limit = 100) {
        if (this.db) return this._queryAll('SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?', [limit]);
        return (this._memory?.threats || []).slice(0, limit);
    }

    // ─── Quarantine Records ──────────────────────────────────────
    addQuarantineRecord(record) {
        if (this.db) {
            this.db.run(
                'INSERT INTO quarantine (quarantine_id, original_path, file_name, file_size, file_hash, threat_name, threat_category, severity, encrypted_path, quarantined_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [record.quarantineId, record.originalPath, record.fileName, record.fileSize, record.fileHash, record.threatName, record.threatCategory, record.severity, record.encryptedPath, record.quarantinedAt]
            );
            this._save();
        } else if (this._memory) {
            this._memory.quarantine.push(record);
        }
    }

    getQuarantineRecords() {
        if (this.db) return this._queryAll('SELECT * FROM quarantine ORDER BY quarantined_at DESC');
        return this._memory?.quarantine || [];
    }

    getQuarantineRecord(quarantineId) {
        if (this.db) return this._queryOne('SELECT * FROM quarantine WHERE quarantine_id = ?', [quarantineId]);
        return this._memory?.quarantine.find(r => r.quarantineId === quarantineId) || null;
    }

    removeQuarantineRecord(quarantineId) {
        if (this.db) {
            this.db.run('DELETE FROM quarantine WHERE quarantine_id = ?', [quarantineId]);
            this._save();
        } else if (this._memory) {
            this._memory.quarantine = this._memory.quarantine.filter(r => r.quarantineId !== quarantineId);
        }
    }

    // ─── Canary Events ───────────────────────────────────────────
    logCanaryEvent(event) {
        if (this.db) {
            this.db.run(
                'INSERT INTO canary_events (drive, file, action, severity, message, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
                [event.drive, event.file || null, event.action, event.severity || 'INFO', event.message || null, event.timestamp]
            );
            this._save();
        } else if (this._memory) {
            this._memory.canaryEvents.push(event);
        }
    }

    // ─── Settings ────────────────────────────────────────────────
    getSettings() {
        if (this.db) {
            const rows = this._queryAll('SELECT * FROM settings');
            const settings = {};
            for (const row of rows) settings[row.key] = row.value;
            return settings;
        }
        return this._memory?.settings || {};
    }

    updateSettings(settings) {
        if (this.db) {
            for (const [key, value] of Object.entries(settings)) {
                this.db.run('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', [key, String(value)]);
            }
            this._save();
        } else if (this._memory) {
            Object.assign(this._memory.settings, settings);
        }
    }

    // ─── Statistics ──────────────────────────────────────────────
    getStats() {
        if (this.db) {
            return {
                totalScans: this._queryScalar('SELECT COUNT(*) FROM scans'),
                totalThreats: this._queryScalar('SELECT COUNT(*) FROM threats'),
                quarantineCount: this._queryScalar('SELECT COUNT(*) FROM quarantine'),
                recentThreats: this._queryScalar('SELECT COUNT(*) FROM threats WHERE timestamp > ?', [Date.now() - 7 * 24 * 60 * 60 * 1000]),
                totalFilesScanned: this._queryScalar('SELECT SUM(total_files) FROM scans') || 0,
                lastScan: this._queryOne('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1')
            };
        }
        return {
            totalScans: this._memory?.scans.length || 0,
            totalThreats: this._memory?.threats.length || 0,
            quarantineCount: this._memory?.quarantine.length || 0,
            recentThreats: 0, totalFilesScanned: 0, lastScan: null
        };
    }

    // ─── Export Data ─────────────────────────────────────────────
    exportData(format = 'json') {
        const data = {
            exportDate: new Date().toISOString(),
            appVersion: '1.0.0',
            stats: this.getStats(),
            scans: this.getScanHistory(1000),
            threats: this.getRecentThreats(1000),
            quarantine: this.getQuarantineRecords()
        };
        if (format === 'csv') return this._toCSV(data.threats);
        return JSON.stringify(data, null, 2);
    }

    _toCSV(threats) {
        const header = 'File Path,File Name,Verdict,Threat Name,Severity,Timestamp\n';
        const rows = threats.map(t =>
            `"${t.file_path || t.filePath}","${t.file_name || t.fileName}","${t.verdict}","${t.threat_name || ''}","${t.severity || ''}","${new Date(t.timestamp).toISOString()}"`
        ).join('\n');
        return header + rows;
    }
}

module.exports = ThreatDB;
