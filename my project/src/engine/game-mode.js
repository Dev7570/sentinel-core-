const EventEmitter = require('events');
const { exec } = require('child_process');
const os = require('os');

/**
 * Game Mode — Adaptive resource throttling
 * Monitors for running games and heavy applications.
 * When detected, reduces scan intensity to avoid impacting performance.
 */
class GameMode extends EventEmitter {
    constructor() {
        super();
        this.active = false;
        this.manualOverride = false;
        this.pollInterval = null;
        this.POLL_MS = 15000; // Check every 15 seconds

        // Known game processes and heavy apps
        this.GAME_PROCESSES = new Set([
            // Games
            'csgo.exe', 'cs2.exe', 'valorant.exe', 'fortnite.exe',
            'gta5.exe', 'gtav.exe', 'rdr2.exe', 'cyberpunk2077.exe',
            'eldenring.exe', 'cod.exe', 'modernwarfare.exe',
            'apex_legends.exe', 'pubg.exe', 'minecraft.exe',
            'javaw.exe', 'dota2.exe', 'overwatch.exe',
            'league of legends.exe', 'rocketleague.exe',
            'witcher3.exe', 'baldur.exe', 'starfield.exe',
            // Heavy apps
            'premiere pro.exe', 'afterfx.exe', 'davinciresolve.exe',
            'blender.exe', 'unreal editor.exe', 'unity.exe',
            'obs64.exe', 'obs32.exe',
            // Streaming
            'streamlabs obs.exe',
        ]);

        // GPU-intensive process detection threshold
        this.GPU_THRESHOLD_MB = 500;
    }

    // ─── Start Monitoring ────────────────────────────────────────
    startMonitoring() {
        this._checkProcesses();
        this.pollInterval = setInterval(() => this._checkProcesses(), this.POLL_MS);
    }

    stopMonitoring() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }

    // ─── Check Running Processes ─────────────────────────────────
    _checkProcesses() {
        if (this.manualOverride) return;
        if (os.platform() !== 'win32') return;

        exec('tasklist /FO CSV /NH', { maxBuffer: 1024 * 512 }, (err, stdout) => {
            if (err) return;

            const processes = stdout.split('\n')
                .map(line => {
                    const match = line.match(/"([^"]+)"/);
                    return match ? match[1].toLowerCase() : null;
                })
                .filter(Boolean);

            const gameDetected = processes.some(p => this.GAME_PROCESSES.has(p));

            if (gameDetected && !this.active) {
                this.active = true;
                this.emit('mode-changed', true);
            } else if (!gameDetected && this.active && !this.manualOverride) {
                this.active = false;
                this.emit('mode-changed', false);
            }
        });
    }

    // ─── Manual Override ─────────────────────────────────────────
    setManualOverride(enabled) {
        this.manualOverride = enabled;
        this.active = enabled;
        this.emit('mode-changed', enabled);
    }

    // ─── Status ──────────────────────────────────────────────────
    isActive() {
        return this.active;
    }

    getStatus() {
        return {
            active: this.active,
            manualOverride: this.manualOverride
        };
    }
}

module.exports = GameMode;
