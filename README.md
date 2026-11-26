# SpringSecure CLI — v1.0.2

A command-line tool for detecting mass assignment vulnerabilities in Spring Boot applications.

## Features

-  **AST-Based Analysis** - Uses java-parser for accurate Abstract Syntax Tree parsing
-  **7-Rule Library (R-01–R-07)** - Detects mass assignment vulnerabilities with CWE classifications, matching Table 3 of the accompanying paper
-  **Dynamic Verification** - Optionally tests R-01 findings against a running instance (`--url`); response-reflection based only (see below)
-  **Multiple Output Formats** - Console, JSON, and text reports
-  **GitHub Repository Scanning** - Scan any public GitHub repository automatically
-  **Fast Scanning** - Recursively scan entire projects
-  **CI/CD Ready** - Exit codes for build pipeline integration
-  **Detailed Recommendations** - Actionable fix instructions for each vulnerability
-  **Smart Fallback** - Automatic fallback to regex-based detection if AST parsing fails

## Installation

```bash
npm install
```

## Usage

### Basic Scan

Scan current directory:
```bash
node cli.js
```

Scan a specific file:
```bash
node cli.js path/to/UserController.java
```

Scan a specific directory:
```bash
node cli.js path/to/spring-project
```

**Scan a GitHub repository:**
```bash
node cli.js https://github.com/username/spring-boot-project
```

### Dynamic Verification

Test R-01 (direct entity binding) findings against a running instance of the
application:

```bash
node cli.js path/to/spring-project --url http://localhost:8080 -f json -o report.json
```

Each tested finding gains a `dynamic` field in the JSON report:

```json
{ "outcome": "confirmed | not-exploitable | inconclusive", "status": 200, "evidence": "..." }
```

- `confirmed` — the response reflected the injected sensitive fields.
- `not-exploitable` — the request completed and the response did not reflect them.
- `inconclusive` — the request could not be completed (connection error /
  timeout), the server returned HTTP 401, or the finding has no endpoint
  metadata. Inconclusive is never recorded as not-exploitable: it means the
  check could not be run, not that the endpoint is safe.

Confirmation is response-reflection based only, using a fixed injection
payload (`{ isAdmin: true, role: "ADMIN", balance: 1000000, id: 99999 }`).
The scanner does not parse OpenAPI specifications, does not perform a
follow-up GET oracle, and does not compute a divergence measure (see
Limitations).

For a repeatable, isolated run, see `scripts/scan-isolated.sh`, which
starts a disposable stack (`docker-compose.yml`), scans it, then destroys
the stack and its volumes.

### Output Formats

**Console output (default):**
```bash
node cli.js src/
```

**JSON output:**
```bash
node cli.js src/ --json -o report.json
```

**Text output:**
```bash
node cli.js src/ --text -o report.txt
```

### Options

```
Usage: springsecure [options] [path]

Arguments:
  path                    File or directory to scan (default: ".")

Options:
  -V, --version          output the version number
  -o, --output <file>    Output file path for report
  -f, --format <type>    Output format: console, json, text (default: "console")
  -v, --verbose          Show detailed recommendations
  --json                 Output as JSON (shorthand for -f json)
  --text                 Output as text (shorthand for -f text)
  --fail-on-high         Exit with error code if high severity issues found
  --fail-on-medium       Exit with error code if medium+ severity issues found
  --url <url>            Base URL of a running instance to dynamically verify R-01 findings
  -h, --help             display help for command
```

### CI/CD Integration

Use `--fail-on-high` or `--fail-on-medium` to fail builds when vulnerabilities are detected:

```bash
# Fail build on high severity issues
node cli.js src/ --fail-on-high

# Fail build on medium or high severity issues
node cli.js src/ --fail-on-medium --json -o security-report.json
```

Note: gating is based on static severity counts only (HIGH / MEDIUM). There
is no CRITICAL severity in this version, and dynamic confirmation does not
change the exit code.

### Tests

```bash
npm test
```

Runs the integration tests in `tests/` (Node's built-in test runner, no
extra dependencies): static scan of a vulnerable and a clean fixture,
`--fail-on-high` / `--fail-on-medium` exit codes, the commented-out
`@RequestBody` regression case, and dynamic-verification outcomes.

## Detected Vulnerabilities — the 7-rule library

These seven rules (R-01–R-07) are the rule library described in Table 3 of
the paper. R-06 is implemented in v1.0.2 (see below).

### HIGH Severity

1. **R-01 Direct Entity Binding in Controller** (CWE-915)
   - Controllers binding `@RequestBody` directly to entity classes
   - Missing DTO layer protection

2. **R-02 Lombok @Data on Entity** (CWE-915)
   - Entity classes using `@Data` annotation
   - Generates public setters for all fields including sensitive ones

3. **R-03 Sensitive Field Without @JsonIgnore / Public Setter on Sensitive Field** (CWE-200 / CWE-915)
   - Sensitive fields exposed in API responses (missing `@JsonIgnore`)
   - Public setters on sensitive fields such as role, isAdmin, balance

### MEDIUM Severity

4. **R-04 Missing Input Validation** (CWE-20)
   - `@RequestBody` without `@Valid` annotation
   - No validation on incoming data

5. **R-05 Dangerous JPA Cascade Configuration** (CWE-915)
   - Using `CascadeType.ALL` on relationships (`@OneToMany`, `@ManyToMany`,
     `@ManyToOne`, `@OneToOne`)
   - Can lead to unintended data modifications

6. **R-06 Unfiltered service-layer persistence** (CWE-915) — implemented in
   v1.0.2: a `@Service` method that passes a parameter directly to a repository
   `save`, `saveAndFlush` or `persist` call is reported at the save line
   (unless the parameter carries `@Valid`). The rule does not trace the entity
   back to a `@RequestBody`, so a service-layer finding is never linked to an
   endpoint or dynamically confirmed (see Limitations)

7. **R-07 Unsafe Jackson Configuration** (CWE-915)
   - `fail-on-unknown-properties: false` in configuration
   - Allows arbitrary property binding

### Sensitivity lists (as implemented)

There is no `config/sensitivity.json` and no `--sensitivity-config` flag.
Sensitivity is two hard-coded lists in `analyzer.js`:

- **`@JsonIgnore` check** — a `private` field whose name is one of
  `password`, `token`, `secret`, `apiKey`, `privateKey`, `salt` and whose
  preceding line lacks `@JsonIgnore`. (The AST variant of this check
  additionally matches `hash`.)
- **Setter check** — an explicit `public void set<Field>` in source for a
  field named one of `role`, `permission`, `isAdmin`, `isActive`, `balance`,
  `credit`, `creditLimit`. Lombok-generated setters do not appear in source
  and are therefore invisible to this check.

### Auxiliary checks (not part of the 7-rule library)

The scanner also reports a small number of configuration checks that are
not rules R-01–R-07: Lombok `@Setter` on an entity, unsafe orphan removal,
and permissive MVC configuration. They are reported with their own type
names and are not counted in the paper's per-rule evaluation.

## Examples

### Example 1: Scan with verbose output

```bash
node cli.js ./src --verbose
```

### Example 2: Generate JSON report for CI/CD

```bash
node cli.js ./src --json -o security-report.json --fail-on-high
```

### Example 3: Scan single file

```bash
node cli.js ./src/main/java/com/example/UserController.java -v
```

### Example 4: Scan with dynamic verification

```bash
node cli.js ./src --url http://localhost:8080 --json -o security-report.json
```

## Sample Output

```
═══════════════════════════════════════════════════════
  SpringSecure - Mass Assignment Vulnerability Scanner
═══════════════════════════════════════════════════════

 Scanning: /path/to/project/src

Found 15 file(s) to analyze...

 src/main/java/com/example/User.java
   Found 2 issue(s): 1 HIGH 1 MEDIUM

   1. HIGH - Lombok @Data Exposure
      Line: 3
      Issue: Entity class uses @Data annotation which generates setters for all fields...
      Fix: Use @Getter and selective @Setter annotations instead.

───────────────────────────────────────────────────────
Summary:
  Total Files Scanned: 15
  Total Issues: 8
  ● High Severity: 3
  ● Medium Severity: 4
  ● Low Severity: 1
───────────────────────────────────────────────────────
```

## Limitations (v1.0.2)

- **R-06 cannot link a service-layer finding to an endpoint.** The rule
  reports a service method that passes its parameter to a save call, but it
  does not trace the entity back to a `@RequestBody`: there is no call graph
  from controller entry points through service and repository layers, so
  R-06 findings are never dynamically confirmed and never reach the CI/CD
  gating condition.
- **Dynamic verification is response-reflection based only.** The dynamic
  scanner does not parse OpenAPI specifications, does not perform a
  follow-up GET oracle, and does not compute the divergence measure. A
  confirmed outcome means the injected values were reflected in the HTTP
  response; it is not, by itself, proof of a committed database change.
  Conversely, a non-reflected response does not prove the database was
  untouched. Outcomes that could not be evaluated (connection error,
  timeout, HTTP 401, or missing endpoint metadata) are recorded as
  `inconclusive`, not as cleared findings.
- **R-01 only matches a hard-coded entity list** (`User`, `Account`,
  `Order`, `Product`, `Customer`, `Payment`, `Transaction`). Entities
  outside that list are missed.
- **Comment stripping is lexical.** The parser strips `//` and `/* */`
  comments before matching; annotations inside comments no longer produce
  findings.
- **Benchmarks and results are not bundled.** `benchmarks/` and `results/`
  contain only README files explaining what belongs there; the benchmark
  applications (CVA, SCA, SRA) and their scan reports are not part of this
  release.
- **Docker was not available on the machine that prepared this release**,
  so `docker compose up` for the disposable-environment example was not
  executed there; `docker-compose.yml` was validated for YAML syntax only
  and `scripts/scan-isolated.sh` exits with a clear error when Docker is
  absent.

## License

MIT
