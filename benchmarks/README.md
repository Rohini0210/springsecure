# benchmarks/

This directory is for the benchmark applications behind the paper's
evaluation, so that the reported experiments are reproducible:

- `CVA/`, `SCA/`, `SRA/` — source code of the three benchmark Spring Boot
  applications, each with its `openapi.yaml` (or equivalent API
  specification) describing the endpoints that were dynamically verified.
- `expected-findings/` — the ground-truth finding list for each benchmark
  (file, line, rule), against which precision / recall are computed.

Only add benchmark code here if it is the actual code that was measured;
placeholder or invented applications would misrepresent the evaluation.
