# SpringSecure — independent measurement verification

Manuscript SOFTX-D-26-00466R2. This report re-runs, from scratch, the measurements
in `SpringSecure_Measured_Data.md` (the "Measured_Data" file below) and checks the
code claims in the R2 revision plan. Nothing here is estimated; every number comes
from a run listed below, on this machine. Do not paste these absolute timings into
the manuscript as if they came from the i7/Ubuntu machine — see §4.

## Environment

- Date of runs: 2026-11-13 (UTC; 2026-11-12 evening EST)
- OS: Linux htch-runtime 7.0.0-44-generic x86_64 (shared VM, 1.5 vCPU)
- Node: v24.22.1, npm 10.9.4 (Measured_Data used Node v22.22.2 — different version, different machine)
- Work dir: `hidden_files/measurements/` (tool clone, target clones, `reports/`)

## 1. Tool setup (verified)

```bash
git clone https://github.com/Harshith1201/FY-Team-08-Detection-of-Mass-assignment-Vulnerabilities-in-REST-APIs tool
cd tool && git checkout 7a5170cdbf5648cfb38daf8d3b6defc5de3bf7be   # HEAD confirmed: 7a5170c "Add MIT License to the project", 2026-04-29
npm install
git apply /home/hatch/workspace/user/files/springsecure_parser_fixes.patch   # applied cleanly, 43 insertions, 1 deletion
```

Patch confirmed present in `analyzer.js`:
- `stripJavaComments()` defined at line 17, called at line 52 in `detectVulnerabilities()`.
- Cascade rule (now line 283; was line 241 before the 42-line insertion):
  `@OneToMany || @ManyToMany || @ManyToOne || @OneToOne` + `cascade` + `CascadeType.ALL`.

Targets cloned:
- `Sanjeevi-CS/spring-security-jwt-main` → commit `0e6d98e876197b84710e9986431bcf24b8633e03` (2023-07-20) — matches Measured_Data exactly.
- `spring-projects/spring-petclinic` (depth 1) → `500158f732419217507c7656904b8e6aa1bcc0d6` (2026-09-29).
- `sqshq/piggymetrics` (depth 1) → `6bb2cf9ddbca980b664d3edbb6ff775d75369278` (2021-11-15).

## 2. Performance — measured (primary batch, sequential)

Command per run (3 timed runs warm, then 2 further runs for peak RSS):

```bash
node cli.js <target> -f json -o reports/<tag>-run<N>.json
```

Peak RSS measured with a fresh Python wrapper per run
(`resource.getrusage(RUSAGE_CHILDREN).ru_maxrss` after `subprocess.run`;
`/usr/bin/time` is not installed on this machine). Timing is wall-clock for the
whole `node cli.js` process, including Node startup (~0.1 s, measured separately).

| Project | Java files | Files scanned (tool: "Found N file(s)") | LOC (java, `wc -l`) | Modules (pom.xml count) | Mean scan time (3 runs) | Peak RSS (max of 2) | Findings | R-01 candidates |
|---|---|---|---|---|---|---|---|---|
| JWT-INV | 32 | 32 | 1,352 | 1 | **1,006 ms** (1,025 / 994 / 1,000) | **175 MB** | 16 | 2 |
| spring-petclinic | 50 | 53 | 4,297 | 1 | **1,707 ms** (1,553 / 1,658 / 1,911) | **287 MB** | 2 | 0 |
| piggymetrics | 97 | 128 | 4,472 | 10 | **1,449 ms** (1,459 / 1,552 / 1,336) | **189 MB** | 5 | 4 |

Raw reports: `reports/jwt-inv2-run{1,2,3}.json`, `reports/jwt-inv2-rss{1,2}.json`,
`reports/petclinic2-*`, `reports/piggymetrics2-*` (the `-run1/2/3` and `-rss1/2` files
without the `2` are an earlier batch — see note below).

### Comparison with Measured_Data §3

| Project | Measured_Data time / RSS | This run time / RSS | Ratio |
|---|---|---|---|
| JWT-INV | 521 ms / 130 MB | 1,006 ms / 175 MB | 1.93× / 1.35× |
| spring-petclinic | 842 ms / 202 MB | 1,707 ms / 287 MB | 2.03× / 1.42× |
| piggymetrics | 675 ms / 137 MB | 1,449 ms / 189 MB | 2.15× / 1.38× |

- **Counts reproduce exactly**: Java files 32/50/97, files scanned 32/53/128,
  LOC 1,352/4,297/4,472, modules 1/1/10, findings 16/2/5, R-01 candidates 2/0/4.
- **Absolute times and RSS do NOT reproduce**: times are consistently ~2× slower
  and RSS ~1.4× higher here. The factor is systematic across all three projects,
  consistent with a slower/different machine and Node 24 vs 22 — not with a code
  difference (the counts and finding sets are identical).
- **The relative pattern DOES reproduce**: piggymetrics (128 files) scans faster
  than petclinic (53 files); all three complete in ~1–1.7 s; peak-RSS ordering is
  the same (petclinic > piggymetrics > JWT-INV), supporting Measured_Data's point
  that RSS here reflects runtime/GC behaviour rather than project size.
- Note on the discarded first batch: I first ran petclinic and piggymetrics
  concurrently in parallel shells; those runs took 3,915 ms / 267 MB and
  3,675 ms / 184 MB. They are kept in `reports/` (`petclinic-run*`,
  `piggymetrics-run*`, no `2`) but are **not** used above — parallel execution on
  this shared 1.5-CPU VM contaminated them. The sequential re-runs are the
  primary numbers. (JWT-INV's first batch ran alone: 1,272 ms / 179 MB.)

**Consequence for the paper**: the manuscript's Table 6/7 absolute timings must
still be re-measured on the i7/Ubuntu 22.04 machine, exactly as Measured_Data §5
already says. These numbers must not be pasted in as final.

## 3. JWT-INV accuracy — matched by file AND line

Reference set: manuscript Table 6 in the R1-fixed copy
(`Revised_SoftwareX_MAV_R1_Fixed.docx`, Table 6; 21 instances).
Tool output: `reports/jwt-inv2-run1.json` — 16 findings (summary high 5, medium 10,
low 1), of which 1 is the undocumented 8th rule (see below), leaving 15 counted.

Tool findings by rule (file:line — type):
- R-01 Direct Entity Binding: OrderController:36, ProductController:41 (2)
- R-02 Lombok @Data: User.java:27 (1)
- R-03 Sensitive Field Without @JsonIgnore: User.java:33, Supplier.java:20 (2)
- R-04 Missing Input Validation: AuthenticationController:35, :40, :69,
  OrderController:36, ProductController:41, WarehouseController:35 (6)
- R-05 Dangerous Cascade: Order.java:29, Product.java:30, Product.java:43,
  Supplier.java:22 (4)
- R-06: none (0). R-07: none (0).
- 8th rule (excluded from the table, as in Measured_Data):
  `Lombok @AllArgsConstructor on Entity`, User.java:27, LOW (1).

| Rule | Reference | Reported | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|---|
| R-01 Direct entity binding | 4 | 2 | 2 | 0 | 2 | 1.00 | 0.50 |
| R-02 Unsafe Lombok @Data | 1 | 1 | 1 | 0 | 0 | 1.00 | 1.00 |
| R-03 Sensitive field setter | 2 | 2 | 1 | 1 | 1 | 0.50 | 0.50 |
| R-04 Missing @Valid | 6 | 6 | 6 | 0 | 0 | 1.00 | 1.00 |
| R-05 Dangerous CascadeType.ALL | 4 | 4 | 4 | 0 | 0 | 1.00 | 1.00 |
| R-06 Copy-based service update | 4 | 0 | 0 | 0 | 4 | — | 0.00 |
| R-07 Unsafe Jackson config | 0 | 0 | 0 | 0 | 0 | — | — |
| **Overall** | **21** | **15** | **14** | **1** | **7** | **0.93** | **0.67** |

F1 = 2·0.933·0.667 / (0.933+0.667) = **0.78**. TP+FP = 15 = reported (excl. 8th
rule); TP+FN = 21 = reference set.

**This reproduces Measured_Data §2 exactly** — same per-rule TP/FP/FN, same
overall 0.93 / 0.67 / 0.78, same 14 TP / 1 FP / 7 FN / 15 reported.

### Every FP and FN, with file:line and cause

- **R-01 FN — WarehouseController:35.** Live `@RequestBody Warehouse` (line 35).
  `Warehouse` is not in the hard-coded entity list
  (`ast-detectors.js:179`: `['User','Account','Order','Product','Customer',
  'Payment','Transaction']`), so R-01 never fires. Defect 3, unfixed.
- **R-01 FN — AuthenticationController:69.** Live `@RequestBody Supplier`
  (line 69). `Supplier` is not in the hard-coded list. Defect 3, unfixed.
- **R-03 FP — Supplier.java:20** (`private String password`). It is an FP only
  against the Table 6 reference set, which lists just the two User.java
  Lombok-generated setters. See the discrepancy note below.
- **R-03 FN — User.java role field (line 36, `private Role role;`).** No finding.
  Cause: the setter check (`analyzer.js:314-340`, `checkSensitiveFieldSetters`)
  requires an explicit `public void set<Role>` in the source text; Lombok-generated
  setters do not appear in source, so `setRole()` is invisible to it.
- **R-06 FN ×4 — OrderService:19, ProductService:18, SupplierService:19,
  WarehouseService:19.** Each is a service method that persists a bound entity
  directly, e.g. OrderService: `savesProduct(Order p) { return repo.save(p); }`.
  Cause: **R-06 is not implemented at all** — there is no mention of R-06,
  copy-based update, `copyProperties` or `BeanUtils` anywhere in the tool code
  (checked `analyzer.js`, `ast-detectors.js`, `ast-analyzer.js`, `cli.js`,
  `scanner.js`, `repo-scanner.js`).

### Two discrepancies in Measured_Data's *explanations* (counts are unaffected)

1. **R-03 FP cause is wrong as stated.** Measured_Data §2 says Supplier.java:20
   is an FP because "Supplier is an @Entity with no @Data and no public setter".
   That is incorrect: `Supplier.java:64` contains a live, explicit
   `public void setPassword(String password)`. So under §4.3's own stated
   definition (a public setter for a sensitive-named field), Supplier:20 would
   qualify — the reference set, not the tool, is what excludes it. Either the
   reference set is incomplete (it missed Supplier's explicit setter) or the
   paper's R-03 definition is narrower than written. The FP count (1) is still
   correct against the Table 6 reference set as published.
2. **R-02 line.** The reference set gives no line for R-02 ("User.java (@Data,
   @Builder, @NoArgsConstructor, @AllArgsConstructor, @Entity)"). The tool
   reports User.java:**27** — the class-declaration line; the `@Data` annotation
   itself is on line **21**. I counted it a TP on a file+entity basis (it is the
   only @Data-on-@Entity in the project). A reviewer matching strictly by the
   annotation line would see 27 vs 21.

### Defect 1 fix confirmed in output, not just in code

The three commented-out `@RequestBody` lines — AuthenticationController:53,
ProductController:28, SupplierController:27 — produce **no** findings in the
patched run. Before the patch they produced 2 spurious R-01 and 3 spurious R-04
findings (per Measured_Data §1). R-04 now reports exactly the six live
`@RequestBody` parameters (Auth:35, :40, :69; Order:36; Product:41;
Warehouse:35), TP 6 / FP 0 / FN 0.

## 4. Code checks (patched repo at 7a5170c + patch; read, not guessed)

| Question | Answer (with location) |
|---|---|
| `config/sensitivity.json` exists? | **No.** No `config/` directory and no file named `sensitivity*` anywhere in the repo. |
| `--sensitivity-config` flag exists? | **No.** Zero matches in the whole repo (code, CLI, docs). CLI flags are `-o, -f, -v, --json, --text, --fail-on-high, --fail-on-medium` only. |
| Divergence / Δ(e) computation? | **No.** Zero matches for `divergence`, `delta`, `Δ` in any code file. No θ, σ, ε, W_max, G(e) or graded-score computation anywhere in code. |
| Sensitivity list in `analyzer.js`? | **Two different hard-coded lists, neither matching the manuscript.** (a) Line 173, for `Sensitive Field Without @JsonIgnore` (fires on a `private <type> <field>` declaration whose preceding line lacks `@JsonIgnore`): `['password','token','secret','apiKey','privateKey','salt']`. (b) Line 318, for `Public Setter on Sensitive Field` (requires an explicit `public void set<Field>` in source): `['role','permission','isAdmin','isActive','balance','credit','creditLimit']`. The manuscript's claimed list (`role, isAdmin, admin, permission, privilege, balance, creditLimit, verified, banned`) matches neither: `admin`, `privilege`, `verified`, `banned` are in no code list; `password/token/secret/apiKey/privateKey/salt` and `isActive/credit` are in code but not in the manuscript list. |
| `cli.js` `--fail-on-high` / `--fail-on-medium`? | **Static severity count only** (cli.js:123-134): `highCount` / `mediumCount` over all static findings; exit 1 if the threshold is met. No reference to G(e), dynamic confirmation, or CRITICAL. There is no CRITICAL severity anywhere in the code (only a "Critical Issues" label in `web/index.html`). This confirms the R3-5 diagnosis in the revision plan. |
| `package.json` `"test"`? | `"test": "echo \"Error: no test specified\" && exit 1"` — no tests exist. Version is `1.0.0`. |
| `Updated_24_Jan/`? | **Yes** — a second copy of the tool (analyzer.js, ast-analyzer.js, ast-detectors.js, cli.js, formatter.js, repo-scanner.js, scanner.js, package.json, docs) **plus `dynamic-scanner.js`, which does not exist at the repo root**. Its `analyzer.js` differs from the patched root copy and contains **neither** patch fix (no `stripJavaComments`, no `@ManyToOne`). |
| Dynamic verification in the root code? | **None found.** Zero occurrences of "dynamic" in any root `.js` file (excluding `web/` and `Updated_24_Jan/`). The CLI at the root scans statically only; the dynamic engine lives only in `Updated_24_Jan/dynamic-scanner.js`. |
| README entry point? | `node cli.js` (README.md Usage, line 28; also `node cli.js path/to/spring-project`, `--fail-on-high`, etc.). |
| 8th rule source? | `ast-detectors.js:63-68` — `Lombok @AllArgsConstructor on Entity` (LOW), fired on User.java:27. Not in the manuscript's Table 3. |

## 5. What could NOT be measured

- **CVA / SCA / SRA benchmarks and their OpenAPI specs**: not in the public
  repo. The repo's `examples/` holds only `VulnerableController.java`,
  `VulnerableUser.java` and `application.yml`. The benchmark names appear only
  in prose in the repo docs. Their scan times, peak memory and the Table 7
  CVA/SCA/SRA rows therefore cannot be reproduced or verified from any source
  available here. (This is the same gap Measured_Data §5 lists.)
- **Per-project peak memory for CVA/SCA/SRA**: no source provides it.
- **Dynamic verification cost (2.3 s/endpoint)**: not measured — there is no live
  deployment to run against, and the root CLI has no dynamic code path (see §4).
- **SpotBugs/FindSecBugs baseline**: not run (needs a JDK toolchain and a
  decision on scope; not attempted).
- **Spring Boot / Jackson versions of CVA, SCA, SRA**: not available (codebases
  not in the repo).
- **Re-runs on the i7/Ubuntu 22.04 machine**: this machine is not that machine;
  the absolute timings above must not be substituted for it.
