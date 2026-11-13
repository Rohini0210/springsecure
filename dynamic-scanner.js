const axios = require('axios');
const chalk = require('chalk');

/**
 * Dynamic Scanner Module
 * Verifies static findings by sending requests to a running application instance.
 *
 * Confirmation is response-reflection based ONLY: a fixed injection payload is
 * sent and the response body is checked for the reflected injected values.
 * This module does NOT parse OpenAPI specifications, does NOT perform a
 * follow-up GET oracle, and does NOT compute a divergence measure.
 *
 * Outcomes recorded in `dynamicValidation.outcome`:
 *   - 'confirmed'       — the response reflected injected sensitive fields.
 *   - 'not-exploitable' — the request completed and the response did not
 *                         reflect the injected fields.
 *   - 'inconclusive'    — the request could not be completed (connection
 *                         error / timeout), the server returned 401, or the
 *                         candidate has no endpoint metadata. Inconclusive
 *                         is NEVER recorded as not-exploitable: it means the
 *                         check could not be run, not that the endpoint is safe.
 */

// Fixed injection dictionary (unchanged from the original implementation).
const SENSITIVE_PAYLOAD = {
    isAdmin: true,
    role: 'ADMIN',
    balance: 1000000,
    id: 99999
};

function reflectsInjection(responseBody) {
    return responseBody.includes('"isAdmin":true') ||
        responseBody.includes('"role":"ADMIN"') ||
        (responseBody.includes('1000000') && responseBody.includes('balance'));
}

async function verifyVulnerabilities(vulnerabilities, baseUrl) {
    console.log(chalk.blue(`\n⚡ Starting Dynamic Analysis against ${baseUrl}...`));

    // Only R-01 (Direct Entity Binding in Controller) findings are candidates
    // for dynamic verification.
    const candidates = vulnerabilities.filter(v =>
        v.type === 'Direct Entity Binding in Controller'
    );

    if (candidates.length === 0) {
        console.log(chalk.yellow('⚠ No verifiable endpoints found in static analysis results.'));
        console.log(chalk.gray('(Dynamic analysis requires successfully detected Controller endpoints)'));
        return [];
    }

    console.log(chalk.gray(`Found ${candidates.length} candidate(s) for verification.`));

    const results = [];

    for (const issue of candidates) {
        const endpoint = issue.metadata && issue.metadata.endpoint;
        const method = (issue.metadata && issue.metadata.method) || 'POST';
        const entity = (issue.metadata && issue.metadata.entity) || null;

        // No endpoint metadata: the endpoint cannot be tested. Record
        // 'inconclusive' — never 'not-exploitable'.
        if (!endpoint) {
            console.log(chalk.yellow(`  ⚠ No endpoint metadata for ${issue.file}:${issue.line} — skipping (inconclusive).`));
            results.push({
                ...issue,
                dynamicValidation: {
                    outcome: 'inconclusive',
                    testedUrl: null,
                    status: null,
                    confirmed: false,
                    evidence: 'No endpoint metadata recorded for this finding, so the endpoint could not be tested. Inconclusive: not evidence that the endpoint is safe.'
                }
            });
            continue;
        }

        const fullUrl = `${baseUrl}${endpoint}`;

        console.log(chalk.gray(`\nTesting ${method} ${fullUrl} (Entity: ${entity})...`));

        try {
            const response = await axios({
                method: method,
                url: fullUrl,
                data: SENSITIVE_PAYLOAD,
                timeout: 10000,
                validateStatus: () => true // Don't throw on error status
            });

            const responseBody = JSON.stringify(response.data);

            // 401 (or any authentication failure): verification could not be
            // completed. Inconclusive, not a cleared finding.
            if (response.status === 401) {
                console.log(chalk.yellow(`  ⚠ Server returned 401 — verification inconclusive.`));
                results.push({
                    ...issue,
                    dynamicValidation: {
                        outcome: 'inconclusive',
                        testedUrl: fullUrl,
                        status: response.status,
                        confirmed: false,
                        evidence: 'Server returned HTTP 401; the request was rejected before the injected payload could be evaluated.'
                    }
                });
                continue;
            }

            const confirmed = reflectsInjection(responseBody);

            results.push({
                ...issue,
                dynamicValidation: {
                    outcome: confirmed ? 'confirmed' : 'not-exploitable',
                    testedUrl: fullUrl,
                    status: response.status,
                    confirmed: confirmed,
                    evidence: confirmed
                        ? 'Response reflected injected sensitive fields (Mass Assignment successful).'
                        : 'No immediate evidence of mass assignment in response.'
                }
            });

            if (confirmed) {
                console.log(chalk.red(`  ✗ VULNERABILITY CONFIRMED: Allowed setting sensitive fields!`));
            } else {
                console.log(chalk.green(`  ✓ Could not verify mass assignment (Server returned allowed fields or error).`));
            }

        } catch (error) {
            // Connection error / timeout: the request never completed.
            console.log(chalk.yellow(`  ⚠ Connection failed or timeout: ${error.message}`));
            results.push({
                ...issue,
                dynamicValidation: {
                    outcome: 'inconclusive',
                    testedUrl: fullUrl,
                    status: null,
                    confirmed: false,
                    error: error.message,
                    evidence: `Request did not complete (${error.message}); verification inconclusive.`
                }
            });
        }
    }

    return results;
}

module.exports = {
    verifyVulnerabilities,
    SENSITIVE_PAYLOAD
};
