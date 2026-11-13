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

Finding counts match the paper's reference measurements exactly
(16 / 2 / 5). The JSONs contain no timing fields.

## Important caveats

- These three reports are **container re-runs** (Linux container, Node.js
  v24), not the i7/Ubuntu outputs behind Table 6 of the paper. Absolute
  times and memory from the container runs are not in these files and must
  not be quoted as the paper's Table 6 values.
- They were produced with the patched tool **before** release v1.0.1 removed
  the undocumented 8th rule, so `jwt-inv.json` has 16 findings including the
  8th-rule LOW that v1.0.1 removes (15 findings). See `RESULTS_README.md`.

## What is still missing

- `scan-CVA.json`, `scan-SCA.json`, `scan-SRA.json` — the benchmark scan
  reports. They need the benchmark applications in `benchmarks/` (not in
  this repository) and a run on the machine the paper reports.
- The naming convention for reports added later is `scan-<project>.json`
  (see the `node cli.js <project> -f json -o ...` output). The three files
  above keep their original names because `RESULTS_README.md` refers to
  them by those names.

Generate a report with, for example:

```bash
node cli.js <project> -f json -o results/scan-<project>.json
node cli.js <project> --url http://localhost:8080 -f json -o results/scan-<project>-dynamic.json
```

Note: the `results/scan.json` file written by `scripts/scan-isolated.sh`
lands here as well; it is the output of a disposable-environment run and
is not, by itself, a paper result.
