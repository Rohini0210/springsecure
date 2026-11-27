# results/

This directory holds JSON scan reports produced by the tool behind the
paper's tables, plus the notes that say exactly how each file was produced.
Read `RESULTS_README.md` before using these files.

## What is here

| File | Contents |
|---|---|
| `jwt-inv.json` | Scan of JWT-INV — 16 findings (see note below). |
| `spring-petclinic.json` | Scan of spring-petclinic — 2 findings. |
| `piggymetrics.json` | Scan of piggymetrics — 5 findings. |
| `RESULTS_README.md` | Provenance: what was run, where, and what matches the paper. |
| `MEASUREMENT_REPORT.md` | Full run detail (environment, commands, per-run counts). |

Generate a report with, for example:

```bash
node cli.js <project> -f json -o results/scan-<project>.json
node cli.js <project> --url http://localhost:8080 -f json -o results/scan-<project>-dynamic.json
```

Note: the `results/scan.json` file written by `scripts/scan-isolated.sh`
lands here as well; it is the output of a disposable-environment run and
is not, by itself, a paper result.
