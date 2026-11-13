# results/

Placeholder — no scan reports are included in this release, and none has
been fabricated.

This directory holds the JSON reports produced by the tool behind the
paper's tables:

- `scan-<project>.json` — the `node cli.js <project> -f json -o ...` output
  for each evaluated project (CVA, SCA, SRA, JWT-INV, spring-petclinic,
  piggymetrics), produced on the machine the paper reports.
- The summary counts in the paper's Tables 6 and 7 are derived from these
  files; a report whose numbers do not match the paper indicates the scan
  was run with a different tool version or on different code.

Generate a report with, for example:

```bash
node cli.js <project> -f json -o results/scan-<project>.json
node cli.js <project> --url http://localhost:8080 -f json -o results/scan-<project>-dynamic.json
```

Note: the `results/scan.json` file written by `scripts/scan-isolated.sh`
lands here as well; it is the output of a disposable-environment run and
is not, by itself, a paper result.
