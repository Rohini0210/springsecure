'use strict';

/**
 * SpringSecure integration tests (Node built-in test runner, no dependencies).
 * Run with: npm test   (== node --test tests/)
 *
 * Covers:
 *  (a) static-only scan: R-01 on the vulnerable fixture, nothing on the clean one
 *  (b) --fail-on-high exit codes
 *  (c) --fail-on-medium exit codes
 *  (d) commented-out @RequestBody produces no finding (parser Defect 1 regression)
 *  (e) --url dynamic verification: a candidate with no endpoint metadata is
 *      recorded 'inconclusive', never 'not-exploitable'
 *  (f) dynamic-scanner unit checks: reflection confirms, 401 is inconclusive
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'cli.js');
const FIXTURES = path.join(__dirname, 'fixtures');

function runCli(args) {
    return new Promise((resolve) => {
        execFile(process.execPath, [CLI, ...args], { cwd: ROOT }, (error, stdout, stderr) => {
            resolve({ code: error ? error.code : 0, stdout, stderr });
        });
    });
}

async function scanJson(targetDir, extraArgs = []) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'springsecure-test-'));
    const outFile = path.join(tmp, 'report.json');
    const { code, stdout, stderr } = await runCli([targetDir, '-f', 'json', '-o', outFile, ...extraArgs]);
    assert.equal(code, 0, `cli exited ${code}\nstdout: ${stdout}\nstderr: ${stderr}`);
    const report = JSON.parse(fs.readFileSync(outFile, 'utf-8'));
    fs.rmSync(tmp, { recursive: true, force: true });
    return report;
}

// (a) Static-only scan
test('(a) static scan finds R-01 on the vulnerable fixture', async () => {
    const report = await scanJson(path.join(FIXTURES, 'vulnerable'));
    const r01 = report.vulnerabilities.filter(
        (v) => v.type === 'Direct Entity Binding in Controller');
    assert.equal(r01.length, 1, `expected 1 R-01 finding, got ${JSON.stringify(report.vulnerabilities)}`);
    assert.equal(r01[0].severity, 'HIGH');
});

test('(a) static scan finds nothing on the clean DTO-based fixture', async () => {
    const report = await scanJson(path.join(FIXTURES, 'clean'));
    assert.equal(report.vulnerabilities.length, 0,
        `expected 0 findings, got ${JSON.stringify(report.vulnerabilities)}`);
});

// (b) --fail-on-high
test('(b) --fail-on-high exits 1 with a HIGH finding and 0 without', async () => {
    const withHigh = await runCli([path.join(FIXTURES, 'vulnerable'), '--fail-on-high']);
    assert.equal(withHigh.code, 1, `expected exit 1, got ${withHigh.code}: ${withHigh.stdout}`);
    const clean = await runCli([path.join(FIXTURES, 'clean'), '--fail-on-high']);
    assert.equal(clean.code, 0, `expected exit 0, got ${clean.code}: ${clean.stdout}`);
});

// (c) --fail-on-medium
test('(c) --fail-on-medium exits 1 with MEDIUM+ and 0 on clean', async () => {
    // The vulnerable fixture also carries a MEDIUM (Missing Input Validation).
    const withMedium = await runCli([path.join(FIXTURES, 'vulnerable'), '--fail-on-medium']);
    assert.equal(withMedium.code, 1, `expected exit 1, got ${withMedium.code}: ${withMedium.stdout}`);
    const clean = await runCli([path.join(FIXTURES, 'clean'), '--fail-on-medium']);
    assert.equal(clean.code, 0, `expected exit 0, got ${clean.code}: ${clean.stdout}`);
});

// (d) Defect 1 regression: commented-out @RequestBody
test('(d) commented-out @RequestBody produces no finding', async () => {
    const report = await scanJson(path.join(FIXTURES, 'commented'));
    assert.equal(report.vulnerabilities.length, 0,
        `expected 0 findings, got ${JSON.stringify(report.vulnerabilities)}`);
});

// (e) --url wiring: no endpoint metadata -> inconclusive, not not-exploitable
test('(e) --url marks an R-01 candidate without endpoint metadata inconclusive', async () => {
    // Unreachable base URL; the candidate has no endpoint metadata, so the
    // scanner must record 'inconclusive' without ever making a request.
    const report = await scanJson(path.join(FIXTURES, 'vulnerable'),
        ['--url', 'http://127.0.0.1:1']);
    const r01 = report.vulnerabilities.find(
        (v) => v.type === 'Direct Entity Binding in Controller');
    assert.ok(r01, 'expected an R-01 finding');
    assert.ok(r01.dynamic, 'expected a dynamic field on the tested finding');
    assert.equal(r01.dynamic.outcome, 'inconclusive');
    assert.notEqual(r01.dynamic.outcome, 'not-exploitable');
});

// (f) dynamic-scanner unit checks against a local stub server
test('(f) dynamic scanner confirms on reflection and is inconclusive on 401', async () => {
    const { verifyVulnerabilities } = require('../dynamic-scanner');

    const server = http.createServer((req, res) => {
        if (req.url === '/secure') {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'unauthorized' }));
            return;
        }
        if (req.url === '/plain') {
            // Returns a fixed body that does NOT reflect the injected fields.
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
            return;
        }
        // Echo the posted body back: the injected fields are reflected.
        let body = '';
        req.on('data', (chunk) => { body += chunk; });
        req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(body || '{}');
        });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    try {
        const findings = [
            { type: 'Direct Entity Binding in Controller', severity: 'HIGH', file: 'a.java', line: 1,
              metadata: { endpoint: '/users', method: 'POST', entity: 'User' } },
            { type: 'Direct Entity Binding in Controller', severity: 'HIGH', file: 'b.java', line: 2,
              metadata: { endpoint: '/secure', method: 'POST', entity: 'User' } },
            { type: 'Direct Entity Binding in Controller', severity: 'HIGH', file: 'c.java', line: 3,
              metadata: { endpoint: '/plain', method: 'POST', entity: 'User' } },
        ];

        // Third endpoint returns 200 with a fixed safe body: no reflection.
        const results = await verifyVulnerabilities(findings, baseUrl);
        assert.equal(results.length, 3);
        const byFile = Object.fromEntries(results.map((r) => [r.file, r.dynamicValidation]));
        assert.equal(byFile['a.java'].outcome, 'confirmed');
        assert.equal(byFile['a.java'].status, 200);
        assert.equal(byFile['b.java'].outcome, 'inconclusive');
        assert.equal(byFile['b.java'].status, 401);
        assert.equal(byFile['c.java'].outcome, 'not-exploitable');
    } finally {
        await new Promise((resolve) => server.close(resolve));
    }
});

test('(f) dynamic scanner marks a failed request inconclusive', async () => {
    const { verifyVulnerabilities } = require('../dynamic-scanner');
    // Port 1 on localhost refuses connections immediately.
    const results = await verifyVulnerabilities(
        [{ type: 'Direct Entity Binding in Controller', severity: 'HIGH', file: 'a.java', line: 1,
           metadata: { endpoint: '/users', method: 'POST', entity: 'User' } }],
        'http://127.0.0.1:1');
    assert.equal(results.length, 1);
    assert.equal(results[0].dynamicValidation.outcome, 'inconclusive');
});
