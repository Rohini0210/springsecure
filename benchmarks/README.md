# benchmarks/

Placeholder — no benchmark code is included in this release, and none has
been fabricated.

This directory is where the benchmark applications behind the paper's
evaluation belong, so that the reported experiments are reproducible:

- `CVA/`, `SCA/`, `SRA/` — source code of the three benchmark Spring Boot
  applications, each with its `openapi.yaml` (or equivalent API
  specification) describing the endpoints that were dynamically verified.
- `expected-findings/` — the ground-truth finding list for each benchmark
  (file, line, rule), against which precision / recall are computed.

These applications were not available in the public repository at release
time (see the paper's reproducibility discussion). Do not add benchmark code
here unless it is the actual code that was measured; placeholder or
invented applications would misrepresent the evaluation.
