const EventEmitter = require('events');
const { exec } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');

class UsbMonitor extends EventEmitter {
    constructor() {
        super();
        this.devices = new Map();
        this.pollInterval = null;
        this.POLL_MS = 3000;
    }

    // ─── Start Monitoring ────────────────────────────────────────
    startMonitoring() {
        this._pollDrives();
        this.pollInterval = setInterval(() => this._pollDrives(), this.POLL_MS);
    }

    stopMonitoring() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }

    // ─── Poll Drives (Windows) ───────────────────────────────────
    async _pollDrives() {
        if (os.platform() !== 'win32') return;

        try {
            const drives = await this._getWindowsDrives();
            const currentLetters = new Set(drives.map(d => d.driveLetter));
            const knownLetters = new Set(this.devices.keys());

            // Detect new drives
            for (const drive of drives) {
                if (!knownLetters.has(drive.driveLetter)) {
                    this.devices.set(drive.driveLetter, drive);
                    this.emit('device-added', drive);
                }
            }

            // Detect removed drives
            for (const letter of knownLetters) {
                if (!currentLetters.has(letter)) {
                    const removed = this.devices.get(letter);
                    this.devices.delete(letter);
                    this.emit('device-removed', removed);
                }
            }
        } catch (err) {
            // Silently continue polling
        }
    }

    // ─── Get Windows Removable Drives ────────────────────────────
    _getWindowsDrives() {
        return new Promise((resolve, reject) => {
            const ps = `Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | Select-Object DeviceID, VolumeName, Size, FreeSpace | ConvertTo-Json`;
            exec(`powershell -NoProfile -Command "${ps}"`, (err, stdout) => {
                if (err) return resolve([]);
                try {
                    let data = JSON.parse(stdout || '[]');
                    if (!Array.isArray(data)) data = [data];
                    const drives = data.filter(d => d && d.DeviceID).map(d => ({
                        driveLetter: d.DeviceID,
                        deviceName: d.VolumeName || 'USB Drive',
                        totalSize: d.Size || 0,
                        freeSpace: d.FreeSpace || 0,
                        type: 'removable',
                        connectedAt: Date.now()
                    }));
                    resolve(drives);
                } catch {
                    resolve([]);
                }
            });
        });
    }

    // ─── Get Current Devices ─────────────────────────────────────
    getDevices() {
        return Array.from(this.devices.values());
    }

    // ─── Safe Eject ──────────────────────────────────────────────
    safeEject(driveLetter) {
        return new Promise((resolve) => {
            if (os.platform() === 'win32') {
                const letter = driveLetter.replace(':', '').replace('\\', '');
                const ps = `$vol = Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter -eq '${letter}:' }; if($vol) { $vol.Dismount($false, $false) }`;
                exec(`powershell -NoProfile -Command "${ps}"`, (err) => {
                    if (err) {
                        resolve({ success: false, error: 'Could not safely eject. Close all files on the drive first.' });
                    } else {
                        this.devices.delete(driveLetter);
                        resolve({ success: true, message: `Drive ${driveLetter} safely ejected.` });
                    }
                });
            } else {
                exec(`umount ${driveLetter}`, (err) => {
                    resolve(err
                        ? { success: false, error: err.message }
                        : { success: true, message: `Drive ${driveLetter} ejected.` }
                    );
                });
            }
        });
    }
}

module.exports = UsbMonitor;
