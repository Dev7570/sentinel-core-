/**
 * Sentinel-Core AV — Engine Test Script
 * Tests the scanner + arbiter directly without the Electron UI
 */
const path = require('path');
const Scanner = require('./src/engine/scanner');
const Arbiter = require('./src/engine/arbiter');
const ThreatDB = require('./src/engine/threat-db');
const os = require('os');

const APP_DATA_DIR = path.join(os.tmpdir(), 'sentinel-test');
const TEST_DIR = path.join(__dirname, 'test_scan_folder');

async function runTest() {
    console.log('╔══════════════════════════════════════════════════════╗');
    console.log('║      SENTINEL-CORE AV — ENGINE TEST                 ║');
    console.log('╚══════════════════════════════════════════════════════╝');
    console.log('');

    // Initialize engines
    const threatDB = new ThreatDB(APP_DATA_DIR);
    // Wait a bit for sql.js async init
    await new Promise(r => setTimeout(r, 1000));

    const scanner = new Scanner(threatDB);
    const arbiter = new Arbiter();

    console.log(`📁 Scanning directory: ${TEST_DIR}`);
    console.log('─'.repeat(55));

    try {
        const results = await scanner.scanDirectory(TEST_DIR, (progress) => {
            process.stdout.write(`\r  Scanning: ${progress.percentage}% — ${progress.currentFile || '...'}`);
        });

        console.log('\n');
        console.log('─'.repeat(55));
        console.log(`📊 Scan Complete — ${results.length} files scanned`);
        console.log('─'.repeat(55));
        console.log('');

        let clean = 0, suspicious = 0, malicious = 0;
        const flaggedResults = [];

        for (const result of results) {
            const verdict = arbiter.evaluate(result);
            const explanation = arbiter.explain(result);

            if (verdict === 'CLEAN') {
                clean++;
            } else {
                if (verdict === 'SUSPICIOUS') suspicious++;
                if (verdict === 'MALICIOUS') malicious++;
                flaggedResults.push({ ...result, verdict, explanation });
            }
        }

        // Show clean files
        console.log(`✅ CLEAN:      ${clean} files`);
        console.log(`⚠️  SUSPICIOUS: ${suspicious} files`);
        console.log(`🔴 MALICIOUS:  ${malicious} files`);
        console.log('');

        // Show details for flagged files
        if (flaggedResults.length > 0) {
            console.log('═'.repeat(55));
            console.log('FLAGGED FILES:');
            console.log('═'.repeat(55));

            for (const r of flaggedResults) {
                const icon = r.verdict === 'MALICIOUS' ? '🔴' : '⚠️';
                console.log(`\n${icon} ${r.fileName}`);
                console.log(`   Verdict: ${r.verdict}`);
                console.log(`   Score: ${r.explanation?.score || 'N/A'}`);
                console.log(`   Reason: ${r.explanation?.summary || 'No summary'}`);

                if (r.yaraMatches && r.yaraMatches.length > 0) {
                    console.log(`   YARA Rules: ${r.yaraMatches.map(m => m.ruleName).join(', ')}`);
                }
                if (r.heuristicFlags && r.heuristicFlags.length > 0) {
                    console.log(`   Heuristics: ${r.heuristicFlags.join(', ')}`);
                }
                if (r.signatureMatch) {
                    console.log(`   Signature:  ${r.signatureMatch.name}`);
                }
            }
        }

        console.log('\n');
        console.log('═'.repeat(55));
        console.log(`RESULT: ${malicious > 0 ? '🚨 THREATS DETECTED' : suspicious > 0 ? '⚠️ SUSPICIOUS FILES FOUND' : '✅ ALL CLEAN'}`);
        console.log('═'.repeat(55));

        // Test stats
        console.log('\n📈 Database Stats:');
        const stats = threatDB.getStats();
        console.log(JSON.stringify(stats, null, 2));

    } catch (err) {
        console.error('❌ Scan failed:', err.message);
        console.error(err.stack);
    }
}

runTest().catch(console.error);
