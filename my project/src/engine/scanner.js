const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

// ─── Bundled Signature & Rule Data ───────────────────────────────
let SIGNATURES = {};
let YARA_RULES = [];

try { SIGNATURES = require('../data/signatures.json'); } catch {}
try { YARA_RULES = require('../data/yara-rules.json'); } catch {}

class Scanner {
    constructor(threatDB) {
        this.threatDB = threatDB;
        this.negativeCache = new Set(); // known safe hashes
        this.scanState = 'stopped'; // 'scanning', 'paused', 'stopped'

        // Suspicious extensions
        this.DANGEROUS_EXTS = new Set([
            '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs',
            '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi',
            '.dll', '.sys', '.inf', '.reg', '.hta', '.cpl', '.lnk'
        ]);

        // Double extension patterns
        this.DOUBLE_EXT_REGEX = /\.(jpg|png|pdf|doc|docx|txt|mp3|mp4)\.(exe|bat|cmd|scr|vbs|js|ps1)$/i;

        // EICAR test string signature
        this.EICAR_HASH = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    }

    // ─── Scan Control ────────────────────────────────────────────
    pauseScan() {
        if (this.scanState === 'scanning') this.scanState = 'paused';
    }

    resumeScan() {
        if (this.scanState === 'paused') this.scanState = 'scanning';
    }

    cancelScan() {
        this.scanState = 'stopped';
    }

    // ─── Scan Directory ──────────────────────────────────────────
    async scanDirectory(dirPath, progressCallback) {
        this.scanState = 'scanning';
        const results = [];

        try {
            // Yield briefly to UI to show scanning status
            if (progressCallback) {
                progressCallback({
                    current: 0,
                    total: 0,
                    percentage: 0,
                    currentFile: 'Discovering files to scan...',
                    currentPath: dirPath
                });
            }

            const files = await this._walkDirectory(dirPath);
            const totalFiles = files.length;

            let lastProgressTime = Date.now();
            
            for (let i = 0; i < files.length; i++) {
                if (this.scanState === 'stopped') break;

                // Yield to the Node.js event loop properly every 20 files
                if (i % 20 === 0) await new Promise(resolve => setTimeout(resolve, 1));

                // ─── PAUSE ARCHITECTURE ───
                // Suspend the main thread indefinitely without consuming CPU until resumed or cancelled
                while (this.scanState === 'paused') {
                    await new Promise(resolve => setTimeout(resolve, 300));
                }

                // Double check after waking up from pause
                if (this.scanState === 'stopped') break;

                const filePath = files[i];
                const result = await this.scanFile(filePath);
                results.push(result);

                if (progressCallback) {
                    const now = Date.now();
                    // Throttle IPC signals to 20 frames per second (50ms) to completely prevent Chromium UI freezes
                    if (now - lastProgressTime > 50 || i === files.length - 1) {
                        progressCallback({
                            current: i + 1,
                            total: totalFiles,
                            percentage: Math.round(((i + 1) / totalFiles) * 100),
                            currentFile: path.basename(filePath),
                            currentPath: filePath
                        });
                        lastProgressTime = now;
                    }
                }
            }
        } finally {
            this.scanState = 'stopped';
        }

        return results;
    }

    // ─── Scan Single File ────────────────────────────────────────
    async scanFile(filePath) {
        const result = {
            filePath,
            fileName: path.basename(filePath),
            fileSize: 0,
            hash: '',
            signatureMatch: null,
            yaraMatches: [],
            heuristicFlags: [],
            virusTotalResult: null,
            scanTime: Date.now()
        };

        try {
            const stats = await fs.promises.stat(filePath);
            result.fileSize = stats.size;

            // Skip very large files (> 100MB)
            if (stats.size > 100 * 1024 * 1024) {
                result.heuristicFlags.push('FILE_TOO_LARGE_SKIPPED');
                return result;
            }

            // Compute SHA-256 hash using async I/O to avoid blocking the main thread
            const fileBuffer = await fs.promises.readFile(filePath);
            result.hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

            // Check negative cache (known safe)
            if (this.negativeCache.has(result.hash)) {
                return result;
            }

            // 1. Signature scan
            result.signatureMatch = this._signatureScan(result.hash, result.fileName);

            // 2. YARA-style pattern matching
            result.yaraMatches = this._yaraPatternScan(fileBuffer, filePath);

            // 3. Heuristic analysis
            result.heuristicFlags = this._heuristicScan(filePath, fileBuffer, stats);

            // 4. VirusTotal Cloud Sync
            if (this.threatDB) {
                const settings = this.threatDB.getSettings();
                if (settings && settings.virusTotalKey && settings.virusTotalKey.trim() !== '') {
                    result.virusTotalResult = await this._virusTotalScan(result.hash, settings.virusTotalKey.trim());
                }
            }

            // If clean, add to negative cache
            if (!result.signatureMatch && result.yaraMatches.length === 0 && result.heuristicFlags.length === 0) {
                this.negativeCache.add(result.hash);
            }

        } catch (err) {
            result.error = err.message;
        }

        return result;
    }

    // ─── Signature Scan ──────────────────────────────────────────
    _signatureScan(hash, fileName) {
        // Check EICAR test
        if (hash === this.EICAR_HASH) {
            return { name: 'EICAR-Test-File', severity: 'HIGH', category: 'test' };
        }

        // Check bundled signature DB
        if (SIGNATURES[hash]) {
            return SIGNATURES[hash];
        }

        // Check known malicious filenames
        const knownMalicious = {
            'autorun.inf': { name: 'Autorun.Worm', severity: 'MEDIUM', category: 'worm' },
            'desktop.ini.exe': { name: 'FolderMask.Trojan', severity: 'HIGH', category: 'trojan' },
            'recycler.exe': { name: 'Recycler.Worm', severity: 'HIGH', category: 'worm' }
        };

        const lower = fileName.toLowerCase();
        if (knownMalicious[lower]) return knownMalicious[lower];

        return null;
    }

    // ─── YARA-Style Pattern Scan ─────────────────────────────────
    _yaraPatternScan(buffer, filePath) {
        const matches = [];
        const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1024 * 512)); // first 512KB

        // Built-in rules
        const builtinRules = [
            {
                name: 'SuspiciousAutorun',
                pattern: /\[autorun\]\s*open\s*=/i,
                severity: 'HIGH',
                description: 'Autorun.inf with executable payload'
            },
            {
                name: 'PowerShellDownloader',
                pattern: /powershell.*(?:Invoke-WebRequest|wget|curl|DownloadString|Net\.WebClient)/i,
                severity: 'CRITICAL',
                description: 'PowerShell script with download capability'
            },
            {
                name: 'BatchObfuscation',
                pattern: /%[a-z]:[~\d,]+%/i,
                severity: 'MEDIUM',
                description: 'Obfuscated batch script variable manipulation'
            },
            {
                name: 'VBScriptShell',
                pattern: /WScript\.Shell|Shell\.Application|CreateObject.*Scripting/i,
                severity: 'HIGH',
                description: 'VBScript with shell access'
            },
            {
                name: 'Base64Payload',
                pattern: /(?:FromBase64String|atob|base64_decode)\s*\(/i,
                severity: 'MEDIUM',
                description: 'Encoded payload execution'
            },
            {
                name: 'RegistryModification',
                pattern: /reg\s+add\s+.*\\CurrentVersion\\Run/i,
                severity: 'HIGH',
                description: 'Registry autostart modification'
            },
            {
                name: 'SuspiciousEXEInArchive',
                pattern: /\.zip|\.rar|\.7z/i,
                severity: 'LOW',
                description: 'Archive containing suspicious content'
            },
            {
                name: 'CryptoMiner',
                pattern: /stratum\+tcp|xmrig|coinhive|cryptonight/i,
                severity: 'CRITICAL',
                description: 'Cryptocurrency mining indicators'
            },
            {
                name: 'KeyloggerPattern',
                pattern: /GetAsyncKeyState|SetWindowsHookEx.*WH_KEYBOARD/i,
                severity: 'CRITICAL',
                description: 'Keylogger API usage detected'
            }
        ];

        // Check built-in rules
        for (const rule of builtinRules) {
            if (rule.pattern.test(content)) {
                matches.push({
                    ruleName: rule.name,
                    severity: rule.severity,
                    description: rule.description
                });
            }
        }

        // Check external YARA rules
        for (const rule of YARA_RULES) {
            try {
                const regex = new RegExp(rule.pattern, rule.flags || 'i');
                if (regex.test(content)) {
                    matches.push({
                        ruleName: rule.name,
                        severity: rule.severity,
                        description: rule.description
                    });
                }
            } catch {}
        }

        return matches;
    }

    // ─── Heuristic Analysis ──────────────────────────────────────
    _heuristicScan(filePath, buffer, stats) {
        const flags = [];
        const ext = path.extname(filePath).toLowerCase();
        const fileName = path.basename(filePath);

        // Double extension check
        if (this.DOUBLE_EXT_REGEX.test(fileName)) {
            flags.push({
                type: 'DOUBLE_EXTENSION',
                severity: 'HIGH',
                detail: `Suspicious double extension: ${fileName}`
            });
        }

        // Hidden executable check
        if (this.DANGEROUS_EXTS.has(ext)) {
            try {
                const winAttrs = fs.statSync(filePath);
                // Check if hidden
                if (fileName.startsWith('.') || (winAttrs.mode & 0o200) === 0) {
                    flags.push({
                        type: 'HIDDEN_EXECUTABLE',
                        severity: 'HIGH',
                        detail: `Hidden executable detected: ${fileName}`
                    });
                }
            } catch {}
        }

        // Executable in root of USB
        if (this.DANGEROUS_EXTS.has(ext) && path.dirname(filePath).match(/^[A-Z]:\\?$/i)) {
            flags.push({
                type: 'ROOT_EXECUTABLE',
                severity: 'MEDIUM',
                detail: `Executable in USB root: ${fileName}`
            });
        }

        // Unusually small executable (possible dropper)
        if (this.DANGEROUS_EXTS.has(ext) && stats.size < 10240 && stats.size > 0) {
            flags.push({
                type: 'TINY_EXECUTABLE',
                severity: 'LOW',
                detail: `Very small executable (${stats.size} bytes): possible dropper`
            });
        }

        // PE header check for non-standard extensions
        if (!this.DANGEROUS_EXTS.has(ext) && buffer.length >= 2) {
            if (buffer[0] === 0x4D && buffer[1] === 0x5A) { // MZ header
                flags.push({
                    type: 'DISGUISED_EXECUTABLE',
                    severity: 'CRITICAL',
                    detail: `File ${fileName} has PE header but non-executable extension`
                });
            }
        }

        // Recently created files (within last 5 minutes of scan) — possible dropper activity
        const ageMinutes = (Date.now() - stats.mtimeMs) / 60000;
        if (ageMinutes < 5 && this.DANGEROUS_EXTS.has(ext)) {
            flags.push({
                type: 'FRESHLY_CREATED',
                severity: 'MEDIUM',
                detail: `Executable created ${Math.round(ageMinutes)} minutes ago`
            });
        }

        return flags;
    }

    // ─── Walk Directory ──────────────────────────────────────────
    async _walkDirectory(dirPath) {
        const files = [];
        if (this.scanState === 'stopped') return files;

        try {
            const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
            
            // Periodically yield to the event loop if the array of entries is very large
            if (entries.length > 500) await new Promise(resolve => setTimeout(resolve, 0));

            for (const entry of entries) {
                if (this.scanState === 'stopped') break;

                const fullPath = path.join(dirPath, entry.name);
                try {
                    if (entry.isDirectory()) {
                        if (entry.name === '$RECYCLE.BIN' || entry.name === 'System Volume Information') continue;
                        const subFiles = await this._walkDirectory(fullPath);
                        files.push(...subFiles);
                    } else if (entry.isFile()) {
                        files.push(fullPath);
                    }
                } catch {}
            }
        } catch {}
        return files;
    }

    // ─── Direct Cancel (Legacy Support) ──────────────────────────
    cancelScan() {
        this.scanState = 'stopped';
    }

    // ─── VirusTotal Cloud Scan ───────────────────────────────────
    _virusTotalScan(hash, apiKey) {
        return new Promise((resolve) => {
            const options = {
                hostname: 'www.virustotal.com',
                port: 443,
                path: `/api/v3/files/${hash}`,
                method: 'GET',
                headers: {
                    'x-apikey': apiKey,
                    'Accept': 'application/json'
                }
            };

            const req = https.request(options, (res) => {
                // Return null on Rate Limit (429) or Not Found (404)
                if (res.statusCode !== 200) {
                    res.resume();
                    return resolve(null);
                }

                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const parsed = JSON.parse(data);
                        const stats = parsed.data.attributes.last_analysis_stats;
                        resolve({
                            malicious: stats.malicious || 0,
                            suspicious: stats.suspicious || 0,
                            undetected: stats.undetected || 0,
                            harmless: stats.harmless || 0,
                            link: `https://www.virustotal.com/gui/file/${hash}`
                        });
                    } catch {
                        resolve(null);
                    }
                });
            });

            req.on('error', () => resolve(null));
            // 2000ms timeout for network lookups to prevent massive slowdowns
            req.setTimeout(2000, () => { req.destroy(); resolve(null); });
            req.end();
        });
    }
}

module.exports = Scanner;
