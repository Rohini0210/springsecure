# Scan results — what these files are

These are real scan outputs of the SpringSecure tool. They are **not**
the i7-machine outputs behind Table 6 of the paper, and they do not claim
to be. Read this note before using them.

## Provenance

- Tool: SpringSecure release **v1.0.2** (R-06 implemented; 11 tests passing).
- Run on: 19 November 2026, Linux container, Node.js v24.22.1, 1.5 vCPU.
  The i7/Ubuntu reference environment (Node.js v22.22.2) is different.
- Command per file (from `SpringSecure_Measured_Data.md` §4):
  `node cli.js <project> -f json -o <project>.json`
- One representative run per project is included here (run 1 of 3 warm runs;
  the other runs gave identical findings). The full run set and the timing
  methodology are in `MEASUREMENT_REPORT.md` in this package.

## What matches the paper, and what does not

Counts match the reference measurements (`SpringSecure_Measured_Data.md`
§3) except for the v1.0.2 changes below (four R-06 findings added on
JWT-INV, three on piggymetrics, and the undocumented 8th rule already
removed in v1.0.1):

| Project | Findings in this JSON | R-01 candidates | Reference (i7) |
|---|---|---|---|
| JWT-INV | 19 | 2 | 16 / 2 |
| spring-petclinic | 2 | 0 | 2 / 0 |
| piggymetrics | 8 | 4 | 5 / 4 |

Absolute scan times and peak memory do **not** match Table 6. On this
container the scans ran about 2× slower and used about 1.4× more memory
than on the i7 workstation. Table 6 cites the i7 reference numbers
(JWT-INV 0.5 s / 130 MB; spring-petclinic 0.8 s / 202 MB; piggymetrics
0.7 s / 137 MB). The relative pattern is the same on both machines.

Note: these JSON files contain **no timing or memory fields** — the tool
records only the timestamp, the summary counts and the findings. The
times and memory figures in Table 6 were measured by the harness around
the tool (mean of 3 warm runs; peak RSS from 2 further runs), not read
out of these files.

## What changed in v1.0.2

`jwt-inv.json` now lists 19 findings: the 15 reported by v1.0.1 plus the
four R-06 instances (OrderService:19, ProductService:18, SupplierService:19,
WarehouseService:19), all matched against the reference set in the paper's
Table 5. `piggymetrics.json` now lists 8 findings (was 5): three R-06
instances (UserServiceImpl:33, RecipientServiceImpl:43, :71).
`spring-petclinic.json` is unchanged at 2 findings.

The previous files (JWT-INV 16 findings, including the undocumented 8th
rule — Lombok `@AllArgsConstructor` on `User.java:27` — which v1.0.1
removed) are superseded by this re-run. The paper's accuracy analysis
(§5.4, Table 5) counts 19 reported findings for JWT-INV: 18 true
positives, 1 false positive, 3 false negatives (precision 0.95,
recall 0.86, F1 0.90).

## File paths inside the JSONs

The `file` fields contain absolute paths from the measurement machine
(`/home/hatch/workspace/...`). They are provenance, not paths that will
exist on another machine. The file names, line numbers, rule names and
severities are the meaningful content.

## What is still missing

- The i7-machine JSONs (`jwt.json`, `petclinic.json`, `piggymetrics.json`
  in the §4 commands) do not exist anywhere — they were never saved or
  uploaded. To get JSONs whose timings match Table 6 exactly, re-run the
  three §4 commands on the i7/Ubuntu machine.
- The CVA / SCA / SRA benchmarks, their OpenAPI specifications and their
  scan results are not in this package. They are not in the public
  repository either. Those go in `benchmarks/` and `results/` separately
  when the team can provide them.

## How to add this to the repository

Copy the three `.json` files and this README into the repository's
`results/` folder (replacing the placeholder README there is fine — keep
this file as the record of where the numbers came from).
