# Parser coverage

The compact version of this table is Table 2 in the paper (§4.2). This file
keeps the full detail and points at the regression fixtures that pin the
behaviour.

## Construct coverage (paper Table 2)

| Construct | Behaviour | Effect | Reported |
|---|---|---|---|
| Commented-out code containing annotations | Comments stripped before matching from v1.0.1 | Over-approximation before v1.0.1 | No |
| CascadeType.ALL on @ManyToOne / @OneToOne | Matched from v1.0.1 | Under-approximation before v1.0.1 | No |
| Entity type resolution in R-01 | Parameter type matched against a fixed set of entity names rather than resolved to an @Entity class | Under-approximation | No |
| Annotations spanning multiple lines | Only the first line examined | Under-approximation | No |
| Generic type parameters | Erased when resolving a parameter type | Under-approximation | No |
| Setters inherited from a superclass | Not resolved across the hierarchy | Under-approximation | No |
| Java records | Accessor and constructor forms not modelled | Under-approximation | No |

All seven constructs fail silently today (no warning is emitted when a
construct is not modelled). That is stated in the paper.

## Regression fixtures

`tests/fixtures/` holds the fixtures the integration tests run against:

| Fixture | Purpose |
|---|---|
| `tests/fixtures/vulnerable/UserController.java` | R-01 direct entity binding; the static scan must report it. |
| `tests/fixtures/clean/UserController.java` | DTO-based binding; the static scan must report nothing. |
| `tests/fixtures/commented/HealthController.java` | Commented-out `@RequestBody`; the parser must produce no finding (comment stripping, v1.0.1). |

The fixture behaviour is pinned by `tests/cli.test.js`: test (a) (R-01 found
on the vulnerable fixture, nothing on the clean fixture) and test (d)
(commented-out `@RequestBody` produces no finding). Run them with
`node --test "tests/*.test.js"`.
