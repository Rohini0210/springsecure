# CI integration — exit codes and the CI workflow

## Exit-code behaviour (`cli.js`)

The gating flags are static severity counts only. There is no CRITICAL
severity in the code, and no dynamic-verification gating: the exit code is
decided by the static findings alone.

| Flag | Behaviour |
|---|---|
| `--fail-on-high` | Exit code 1 if any HIGH severity finding; otherwise 0. |
| `--fail-on-medium` | Exit code 1 if any MEDIUM or HIGH severity finding; otherwise 0. |
| (neither flag) | Exit code 0 even when findings exist; the report is still written. |

The relevant code (`cli.js`):

```js
if (options.failOnHigh && highCount > 0) {
    console.error(chalk.red(`\n✗ Found ${highCount} high severity issue(s). Exiting with error.\n`));
    process.exit(1);
}

if (options.failOnMedium && (highCount > 0 || mediumCount > 0)) {
    console.error(chalk.red(`\n✗ Found ${highCount + mediumCount} medium+ severity issue(s). Exiting with error.\n`));
    process.exit(1);
}
```

The paper (§6.3) states the severity order LOW < MEDIUM < HIGH < CRITICAL
and that a HIGH gate includes CRITICAL. That is the specified behaviour;
the implemented gate above is static-severity-driven, and gating on the
dynamic result G(e) is next-step work, not implemented.

## CI workflow (paper §6.3)

```yaml
name: SpringSecure MAV Scan run: |
node cli.js ./src \
--format json \
--output springsecure.json \
--fail-on-high
name: Upload report
uses: actions/upload-artifact@v3 with:
name: springsecure-report path: springsecure.json
```

## Integration tests

`tests/cli.test.js` covers the exit codes: test (b) (`--fail-on-high`
exits 1 with a HIGH finding and 0 without) and test (c)
(`--fail-on-medium` exits 1 with MEDIUM+ and 0 on clean). Run them with
`node --test "tests/*.test.js"` (8 tests, all passing at v1.0.1).

## Isolated runs

For a disposable scan environment, see `docker-compose.yml` and
`scripts/scan-isolated.sh` in the repository root.
