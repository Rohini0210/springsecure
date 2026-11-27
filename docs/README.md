# Documentation — material cut from the paper

The journal paper (SoftwareX, 10 pages) is short by design. This folder
preserves the material that was cut from it for length during the Round 2
revision, so it is not lost. Everything here is copied verbatim from the
pre-cut manuscript or from the tool
source in this repository — nothing is reconstructed from memory.

## Contents

| File | What it holds |
|---|---|
| `example-output.md` | Console transcripts: a CLI scan, a confirmed endpoint, a cleared endpoint, and the static output for `User.java` (paper Figs. 4–5 and the §5.3 walkthrough listings). |
| `web-interface.md` | The web interface screenshot (paper Fig. 6) and what the web version is. |
| `architecture.md` | The AST data structure (paper Table 2), the DynamicFuzz pseudocode, and the sensitivity lists as implemented. |
| `parser-coverage.md` | Parser construct coverage (paper Table 2) and the regression fixtures in `tests/fixtures/`. |
| `listings.md` | The four code listings moved out of the paper for the word limit: the sensitivity lists and injection dictionary (§4.4), the insecure/secure binding example (§4.5), and the CI workflow fragment (§6.3). |
| `ci-integration.md` | CLI exit-code behaviour, the CI/CD workflow, and the integration tests that cover it. |

## A note on status

The transcripts in `example-output.md` show the behaviour *as described in
the paper* (schema-aware payloads, spec-based candidates). The implemented
dynamic scanner (`dynamic-scanner.js`) is simpler: it sends one fixed
injection payload and confirms only by response reflection, and static
findings carry no endpoint metadata, so `--url` records real R-01 candidates
as inconclusive. The paper (§4.4, §5.4, §6.1) says this openly. Do not read
the transcripts as output of the current CLI.
