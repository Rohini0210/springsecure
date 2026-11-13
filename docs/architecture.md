# Architecture — AST data structure, dynamic algorithm, sensitivity lists

## AST data structure (paper Table 2)

The data structure produced by the AST Generator. Cut from the paper for
length; the paper's §4.2 names the five node types in one sentence instead.

| Node | Fields captured |
|---|---|
| Class | name, class-level annotations, superclass name |
| Field | name, declared type, access modifier, field-level annotations |
| Method | name, signature, parameters with their annotations |
| Setter | target field, visibility |
| Relation | relationship annotation, cascade setting |

## Dynamic verification — pseudocode as specified (DynamicFuzz)

Cut from the paper (§4.4), where three sentences now describe the same
algorithm. This is the algorithm *as specified in the paper*.

```
DynamicFuzz(R, Spec):
Input: R- static candidate set (R-01 findings matched to the OpenAPI specification;Spec - OpenAPI/Swagger specification)
Output: V- confirmed vulnerable endpoints

V <- {} (empty set)
for each (e, score) in R do
Schema(e)<- ExtractRequestSchema(Spec, e) F_base<- GenerateBaselinePayload(Schema(e)) F_inject<- InjectSensitiveFields(F_base, Phi)
Phi = {role, isAdmin, verified, ...} resp_base<- SEND(e, F_base)
resp_inject <- SEND(e, F_inject)

Delta(e) <-ComputeStateDivergence(resp_base, resp_inject)   // diagnostic only
if status(resp_inject) is 2xx and ReflectsInjectedFields(resp_inject) then
    V <- V union {(e, score, Delta(e))}
end if
end for
return V
```

Status note: the implemented dynamic scanner (`dynamic-scanner.js`) is a
fixed-dictionary reflection fuzzer. It does not parse OpenAPI specifications,
does not generate schema-aware payloads, and does not compute Delta(e). It
sends one fixed payload and confirms only by response reflection (see
below). The paper §4.4 and §5.4 state this.

## Sensitivity lists as implemented

There is no `config/sensitivity.json` and no `--sensitivity-config` flag.
The sensitivity lists are hard-coded in `analyzer.js`. Do not cite a config
file; the lists below are the real ones.

**Credential fields** — missing-`@JsonIgnore` check
(`checkEntityExposure`, `analyzer.js:173`):

```js
const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'privateKey', 'salt'];
```

**Privilege / financial fields** — public-setter check
(`checkSensitiveFieldSetters`, `analyzer.js:318`):

```js
const sensitiveFields = ['role', 'permission', 'isAdmin', 'isActive', 'balance', 'credit', 'creditLimit'];
```

Neither list matches the single list quoted in early drafts of the paper.
The setter check matches on the literal setter name (`set` + field) and is
blind to Lombok-generated setters.

## Injection dictionary

The dictionary described in the paper's §4.4 (illustrative):

```js
const injectionFields = { isAdmin: true, admin: true,
role: "ADMIN", roles: ["ADMIN"], permissions: "ADMIN", privileges: "ADMIN", balance: 999999, creditLimit: 999999,
isVendor: true, accountId: 99999, id: 99999
};
```

The payload actually sent by the implemented dynamic scanner
(`dynamic-scanner.js`, fixed, not configurable):

```js
{ isAdmin: true, role: 'ADMIN', balance: 1000000, id: 99999 }
```

Confirmation is response reflection only: the response body must contain
`"isAdmin":true`, `"role":"ADMIN"`, or `1000000` together with `balance`.
