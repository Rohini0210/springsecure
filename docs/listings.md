# Code listings moved out of the paper

The four code listings below were in the journal paper and were moved here
during the Round 2 revision to bring the paper within the journal's
4,000-word limit. They are reproduced verbatim from the manuscript
(`Revised_SoftwareX_MAV_R3_Final.docx`, before the word-count cut). The paper
points to this file instead of printing them.

## Sensitivity lists and injection dictionary (paper §4.4, Step 2)

```js
// analyser.js — sensitivity lists
const credentialFields = ['password', 'token', 'secret', 'apiKey', 'privateKey', 'salt'];
const sensitiveSetters = ['role', 'permission', 'isAdmin', 'isActive', 'balance', 'credit', 'creditLimit'];
// dynamic-scanner.js — injection dictionary
const injectionFields = { isAdmin: true, role: 'ADMIN', balance: 1000000, id: 99999 };
```

## Insecure and secure binding (paper §4.5, secure-by-default reference pattern)

```java
// Insecure: R-01, HIGH
@PostMapping("/users/register")
public ResponseEntity<?> register(@RequestBody User user) {
  return ResponseEntity.ok(userService.save(user));
}
// Secure: DTO-based binding
@PostMapping("/users/register")
public ResponseEntity<?> register(@Valid @RequestBody UserRegistrationDTO dto) {
  User user = new User();
  user.setUsername(dto.getUsername());
  user.setEmail(dto.getEmail());
  user.setRole(Role.USER); // set by app, not client
  return ResponseEntity.ok(userService.save(user));
}
```

## CI/CD workflow (paper §6.3)

Fragment as printed in the paper. The complete workflow is in
`ci-integration.md` in this folder.

```yaml
name: SpringSecure MAV Scan
run: |
  node cli.js ./src \
    --format json \
    --output springsecure.json \
    --fail-on-high
name: Upload report
uses: actions/upload-artifact@v3
with:
  name: springsecure-report
  path: springsecure.json
```
