const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Quarantine Vault — AES-256-GCM encrypted file isolation
 * Implements the security hardening from Gemini improvements.
 */
class Quarantine {
    constructor(appDataDir, threatDB) {
        this.vaultDir = path.join(appDataDir, 'quarantine_vault');
        this.threatDB = threatDB;
        this._ensureVaultDir();
        this._initKey();
    }

    _ensureVaultDir() {
        if (!fs.existsSync(this.vaultDir)) {
            fs.mkdirSync(this.vaultDir, { recursive: true });
        }
    }

    // ─── Key Management ──────────────────────────────────────────
    _initKey() {
        const keyPath = path.join(this.vaultDir, '.vault_key');
        if (fs.existsSync(keyPath)) {
            this.encryptionKey = Buffer.from(fs.readFileSync(keyPath, 'utf8'), 'hex');
        } else {
            this.encryptionKey = crypto.randomBytes(32);
            fs.writeFileSync(keyPath, this.encryptionKey.toString('hex'), 'utf8');
            // Hide the key file on Windows
            try {
                require('child_process').execSync(`attrib +h "${keyPath}"`, { stdio: 'ignore' });
            } catch {}
        }
    }

    // ─── Quarantine a File ───────────────────────────────────────
    async quarantineFile(filePath, threatInfo) {
        try {
            if (!fs.existsSync(filePath)) {
                return { success: false, error: 'File not found' };
            }

            const fileBuffer = fs.readFileSync(filePath);
            const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

            // Encrypt with AES-256-GCM
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
            const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
            const authTag = cipher.getAuthTag();

            // Save encrypted file
            const quarantineId = `q_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
            const encryptedPath = path.join(this.vaultDir, `${quarantineId}.vault`);

            // Pack: [IV 16 bytes][AuthTag 16 bytes][Encrypted data]
            const packed = Buffer.concat([iv, authTag, encrypted]);
            fs.writeFileSync(encryptedPath, packed);

            // Remove original file
            fs.unlinkSync(filePath);

            // Log to database
            const record = {
                quarantineId,
                originalPath: filePath,
                fileName: path.basename(filePath),
                fileSize: fileBuffer.length,
                fileHash,
                threatName: threatInfo?.signatureMatch?.name || threatInfo?.verdict || 'Unknown',
                threatCategory: threatInfo?.signatureMatch?.category || 'unknown',
                severity: this._getHighestSeverity(threatInfo),
                encryptedPath,
                quarantinedAt: Date.now()
            };

            if (this.threatDB) {
                this.threatDB.addQuarantineRecord(record);
            }

            return { success: true, quarantineId, record };
        } catch (err) {
            return { success: false, error: err.message };
        }
    }

    // ─── Restore File ────────────────────────────────────────────
    async restoreFile(quarantineId) {
        try {
            const record = this.threatDB
                ? this.threatDB.getQuarantineRecord(quarantineId)
                : null;

            if (!record) {
                return { success: false, error: 'Quarantine record not found' };
            }

            const encryptedPath = path.join(this.vaultDir, `${quarantineId}.vault`);
            if (!fs.existsSync(encryptedPath)) {
                return { success: false, error: 'Encrypted file not found in vault' };
            }

            // Read and unpack
            const packed = fs.readFileSync(encryptedPath);
            const iv = packed.subarray(0, 16);
            const authTag = packed.subarray(16, 32);
            const encrypted = packed.subarray(32);

            // Decrypt with AES-256-GCM
            const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
            decipher.setAuthTag(authTag);
            const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

            // Restore to original location
            const restoreDir = path.dirname(record.originalPath);
            if (!fs.existsSync(restoreDir)) {
                fs.mkdirSync(restoreDir, { recursive: true });
            }
            fs.writeFileSync(record.originalPath, decrypted);

            // Remove from vault
            fs.unlinkSync(encryptedPath);

            // Update database
            if (this.threatDB) {
                this.threatDB.removeQuarantineRecord(quarantineId);
            }

            return { success: true, restoredTo: record.originalPath };
        } catch (err) {
            return { success: false, error: err.message };
        }
    }

    // ─── Permanent Delete ────────────────────────────────────────
    async permanentDelete(quarantineId) {
        try {
            const encryptedPath = path.join(this.vaultDir, `${quarantineId}.vault`);
            if (fs.existsSync(encryptedPath)) {
                // Secure delete: overwrite with random bytes before unlink
                const size = fs.statSync(encryptedPath).size;
                const randomBuffer = crypto.randomBytes(size);
                fs.writeFileSync(encryptedPath, randomBuffer);
                fs.unlinkSync(encryptedPath);
            }

            if (this.threatDB) {
                this.threatDB.removeQuarantineRecord(quarantineId);
            }

            return { success: true };
        } catch (err) {
            return { success: false, error: err.message };
        }
    }

    // ─── Get Quarantined Files ───────────────────────────────────
    getQuarantinedFiles() {
        return this.threatDB ? this.threatDB.getQuarantineRecords() : [];
    }

    // ─── Auto-Cleanup Old Files ──────────────────────────────────
    cleanupOld(daysOld = 30) {
        const cutoff = Date.now() - (daysOld * 24 * 60 * 60 * 1000);
        const records = this.getQuarantinedFiles();

        let cleaned = 0;
        for (const record of records) {
            if (record.quarantinedAt < cutoff) {
                this.permanentDelete(record.quarantineId);
                cleaned++;
            }
        }
        return { cleaned };
    }

    // ─── Helper ──────────────────────────────────────────────────
    _getHighestSeverity(threatInfo) {
        const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        let highest = 0;

        if (threatInfo?.signatureMatch?.severity) {
            highest = Math.max(highest, severities.indexOf(threatInfo.signatureMatch.severity));
        }
        if (threatInfo?.yaraMatches) {
            for (const m of threatInfo.yaraMatches) {
                highest = Math.max(highest, severities.indexOf(m.severity));
            }
        }
        if (threatInfo?.heuristicFlags) {
            for (const f of threatInfo.heuristicFlags) {
                highest = Math.max(highest, severities.indexOf(f.severity));
            }
        }
        return severities[highest] || 'MEDIUM';
    }
}

module.exports = Quarantine;
