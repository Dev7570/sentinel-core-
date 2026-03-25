/**
 * Arbiter — Weighted scoring engine
 * Combines results from multiple scan engines to produce a final verdict.
 * Implements the "Arbiter Logic" from Gemini improvements to reduce false positives (<0.1%).
 */
class Arbiter {
    constructor() {
        // Weights for each detection engine
        this.weights = {
            signature: 0.95,  // Known malware hash match
            yara: 0.70,       // Pattern rule match
            heuristic: 0.50,  // Behavioral/structural red flags
            virusTotal: 0.98  // Cloud consensus (if available)
        };

        // Severity multipliers
        this.severityMultiplier = {
            'CRITICAL': 1.0,
            'HIGH': 0.85,
            'MEDIUM': 0.60,
            'LOW': 0.30
        };

        // Verdict thresholds
        this.MALICIOUS_THRESHOLD = 0.70;
        this.SUSPICIOUS_THRESHOLD = 0.35;
    }

    // ─── Evaluate Scan Result ────────────────────────────────────
    evaluate(scanResult) {
        const score = this.computeScore(scanResult);

        if (score >= this.MALICIOUS_THRESHOLD) return 'MALICIOUS';
        if (score >= this.SUSPICIOUS_THRESHOLD) return 'SUSPICIOUS';
        return 'CLEAN';
    }

    // ─── Compute Threat Score ────────────────────────────────────
    computeScore(scanResult) {
        let totalScore = 0;
        let maxPossible = 0;

        // Signature engine score
        if (scanResult.signatureMatch) {
            const sev = this.severityMultiplier[scanResult.signatureMatch.severity] || 0.5;
            totalScore += this.weights.signature * sev;
        }
        maxPossible += this.weights.signature;

        // YARA engine score (take highest severity match)
        if (scanResult.yaraMatches && scanResult.yaraMatches.length > 0) {
            const maxYaraSev = Math.max(...scanResult.yaraMatches.map(m =>
                this.severityMultiplier[m.severity] || 0.3
            ));
            totalScore += this.weights.yara * maxYaraSev;
            // Bonus for multiple YARA matches (convergence = confidence)
            if (scanResult.yaraMatches.length >= 3) totalScore += 0.15;
        }
        maxPossible += this.weights.yara;

        // Heuristic engine score
        if (scanResult.heuristicFlags && scanResult.heuristicFlags.length > 0) {
            const maxHeurSev = Math.max(...scanResult.heuristicFlags.map(f =>
                this.severityMultiplier[f.severity] || 0.3
            ));
            totalScore += this.weights.heuristic * maxHeurSev;
            // Bonus for multiple heuristic flags (convergence)
            if (scanResult.heuristicFlags.length >= 2) totalScore += 0.15;
            // Extra escalation for double extension (very common USB malware trick)
            if (scanResult.heuristicFlags.some(f => f.type === 'DOUBLE_EXTENSION')) totalScore += 0.10;
        }
        maxPossible += this.weights.heuristic;

        // VirusTotal score (from v3 API)
        if (scanResult.virusTotalResult) {
            const vt = scanResult.virusTotalResult;
            const vtMalicious = vt.malicious || 0;
            const vtTotal = vtMalicious + (vt.suspicious || 0) + (vt.undetected || 0) + (vt.harmless || 0);
            
            // If VT firmly says it's malicious across 3+ engines, auto-escalate heavily
            if (vtMalicious >= 3) {
                totalScore += 2.0; // Instant MALICIOUS verdict guaranteed
            } else if (vtTotal > 0) {
                const vtRatio = (vtMalicious + ((vt.suspicious || 0) * 0.5)) / vtTotal;
                totalScore += this.weights.virusTotal * vtRatio;
            }
        }
        maxPossible += this.weights.virusTotal;

        // Normalize to 0–1 range
        return Math.min(totalScore / maxPossible * 2, 1.0); // amplify since not all engines always fire
    }

    // ─── Generate Explanation ────────────────────────────────────
    explain(scanResult) {
        const reasons = [];
        const score = this.computeScore(scanResult);
        const verdict = this.evaluate(scanResult);

        if (scanResult.signatureMatch) {
            reasons.push({
                engine: 'Signature Database',
                icon: '🔴',
                weight: 'HIGH',
                detail: `Matched known threat: "${scanResult.signatureMatch.name}" (Category: ${scanResult.signatureMatch.category})`
            });
        }

        if (scanResult.yaraMatches && scanResult.yaraMatches.length > 0) {
            for (const match of scanResult.yaraMatches) {
                reasons.push({
                    engine: 'Pattern Analysis (YARA)',
                    icon: match.severity === 'CRITICAL' ? '🔴' : '🟡',
                    weight: match.severity,
                    detail: `Rule "${match.ruleName}": ${match.description}`
                });
            }
        }

        if (scanResult.heuristicFlags && scanResult.heuristicFlags.length > 0) {
            for (const flag of scanResult.heuristicFlags) {
                reasons.push({
                    engine: 'Heuristic Analysis',
                    icon: flag.severity === 'HIGH' || flag.severity === 'CRITICAL' ? '🟠' : '🟡',
                    weight: flag.severity,
                    detail: flag.detail
                });
            }
        }

        if (scanResult.virusTotalResult) {
            const vt = scanResult.virusTotalResult;
            const vtMalicious = vt.malicious || 0;
            const vtTotal = vtMalicious + (vt.suspicious || 0) + (vt.undetected || 0) + (vt.harmless || 0);
            
            reasons.push({
                engine: 'VirusTotal Cloud',
                icon: vtMalicious > 0 ? '🔴' : '🟢',
                weight: vtMalicious >= 3 ? 'HIGH' : vtMalicious > 0 ? 'MEDIUM' : 'NONE',
                detail: `${vtMalicious} out of ${vtTotal} global antivirus engines flagged this file as malicious.`
            });
        }

        return {
            verdict,
            score: Math.round(score * 100),
            reasons,
            summary: reasons.length > 0
                ? `${verdict}: ${reasons.length} indicator(s) found with a combined threat score of ${Math.round(score * 100)}%`
                : 'No threats detected. File appears safe.'
        };
    }
}

module.exports = Arbiter;
