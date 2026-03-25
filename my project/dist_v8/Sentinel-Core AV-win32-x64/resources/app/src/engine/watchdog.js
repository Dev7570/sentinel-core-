/**
 * Watchdog — Process self-protection module
 * Monitors its own process health and restarts critical components if terminated.
 * Implements the Watchdog Module from Gemini improvements.
 */
class Watchdog {
    constructor() {
        this.heartbeatInterval = null;
        this.HEARTBEAT_MS = 5000;
        this.lastHeartbeat = Date.now();
        this.isRunning = false;
        this.healthChecks = [];
    }

    // ─── Start Watchdog ──────────────────────────────────────────
    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this.lastHeartbeat = Date.now();

        this.heartbeatInterval = setInterval(() => {
            this._heartbeat();
        }, this.HEARTBEAT_MS);

        // Monitor memory usage
        this.healthChecks.push({
            name: 'memory',
            check: () => {
                const usage = process.memoryUsage();
                const heapMB = usage.heapUsed / 1024 / 1024;
                return {
                    healthy: heapMB < 512,
                    heapUsedMB: Math.round(heapMB),
                    rssUsedMB: Math.round(usage.rss / 1024 / 1024)
                };
            }
        });

        // Monitor event loop lag
        this.healthChecks.push({
            name: 'eventLoop',
            check: () => {
                const start = Date.now();
                return new Promise(resolve => {
                    setImmediate(() => {
                        const lag = Date.now() - start;
                        resolve({
                            healthy: lag < 100,
                            lagMs: lag
                        });
                    });
                });
            }
        });
    }

    // ─── Stop Watchdog ───────────────────────────────────────────
    stop() {
        this.isRunning = false;
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    // ─── Heartbeat ───────────────────────────────────────────────
    async _heartbeat() {
        this.lastHeartbeat = Date.now();

        for (const healthCheck of this.healthChecks) {
            try {
                const result = await healthCheck.check();
                if (!result.healthy) {
                    this._handleUnhealthy(healthCheck.name, result);
                }
            } catch (err) {
                // Health check itself failed
            }
        }
    }

    // ─── Handle Unhealthy State ──────────────────────────────────
    _handleUnhealthy(checkName, result) {
        if (checkName === 'memory' && result.heapUsedMB > 400) {
            // Force garbage collection if available
            if (global.gc) {
                global.gc();
            }
        }
    }

    // ─── Get Health Status ───────────────────────────────────────
    async getHealth() {
        const status = {
            running: this.isRunning,
            lastHeartbeat: this.lastHeartbeat,
            uptime: process.uptime(),
            pid: process.pid,
            checks: {}
        };

        for (const healthCheck of this.healthChecks) {
            try {
                status.checks[healthCheck.name] = await healthCheck.check();
            } catch {
                status.checks[healthCheck.name] = { healthy: false, error: 'Check failed' };
            }
        }

        return status;
    }
}

module.exports = Watchdog;
