/**
 * Enhanced vulnerability detection logic with AST-based analysis and regex fallback
 */

const {
    checkLombokAnnotationsAST,
    checkEntityExposureAST,
    checkControllerBindingsAST
} = require('./ast-detectors');


/**
 * Replace Java comment content with spaces, preserving line numbering and
 * string literals. Prevents annotation patterns inside commented-out code
 * from being matched as live declarations.
 */
function stripJavaComments(code) {
    let out = '';
    let i = 0;
    const n = code.length;
    let state = 'code'; // code | line | block | str | chr
    while (i < n) {
        const c = code[i], d = code[i + 1];
        if (state === 'code') {
            if (c === '/' && d === '/') { state = 'line'; out += '  '; i += 2; continue; }
            if (c === '/' && d === '*') { state = 'block'; out += '  '; i += 2; continue; }
            if (c === '"') { state = 'str'; out += c; i++; continue; }
            if (c === "'") { state = 'chr'; out += c; i++; continue; }
            out += c; i++; continue;
        }
        if (state === 'line') {
            if (c === '\n') { state = 'code'; out += c; i++; continue; }
            out += ' '; i++; continue;
        }
        if (state === 'block') {
            if (c === '*' && d === '/') { state = 'code'; out += '  '; i += 2; continue; }
            out += (c === '\n') ? c : ' '; i++; continue;
        }
        if (state === 'str' || state === 'chr') {
            out += c;
            if (c === '\\') { if (i + 1 < n) { out += code[i + 1]; i += 2; continue; } }
            if ((state === 'str' && c === '"') || (state === 'chr' && c === "'")) {
                if (out.length > 1) state = 'code';
            }
            i++; continue;
        }
    }
    return out;
}

function detectVulnerabilities(code, filename = '') {
    code = stripJavaComments(code);
    const vulnerabilities = [];
    const ext = filename.toLowerCase();

    if (ext.endsWith('.java')) {
        vulnerabilities.push(...analyzeJavaFile(code, filename));
    } else if (ext.endsWith('.yml') || ext.endsWith('.yaml')) {
        vulnerabilities.push(...analyzeYamlFile(code, filename));
    }

    return vulnerabilities;
}

/**
 * Analyze Java files with comprehensive checks
 * Uses AST-based analysis with regex fallback
 */
function analyzeJavaFile(code, filename) {
    const vulnerabilities = [];

    // Try AST-based detection first
    const astLombokResults = checkLombokAnnotationsAST(code, filename);
    const astEntityResults = checkEntityExposureAST(code, filename);
    const astControllerResults = checkControllerBindingsAST(code, filename);

    // If AST parsing succeeded (returned results), use AST results
    // Otherwise fall back to regex-based detection
    if (astLombokResults.length > 0 || astEntityResults.length > 0 || astControllerResults.length > 0) {
        // AST-based detection succeeded
        vulnerabilities.push(...astLombokResults);
        vulnerabilities.push(...astEntityResults);
        vulnerabilities.push(...astControllerResults);
    } else {
        // Fall back to regex-based detection
        vulnerabilities.push(...checkLombokAnnotations(code, filename));
        vulnerabilities.push(...checkEntityExposure(code, filename));
        vulnerabilities.push(...checkControllerBindings(code, filename));
        vulnerabilities.push(...checkValidationAnnotations(code, filename));
    }

    // Always run these checks (not yet implemented in AST)
    vulnerabilities.push(...checkJpaRelationships(code, filename));
    vulnerabilities.push(...checkSensitiveFieldSetters(code, filename));
    vulnerabilities.push(...checkServiceLayerPersistence(code, filename));

    return vulnerabilities;
}

/**
 * Check for Lombok annotation issues
 */
function checkLombokAnnotations(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');

    let hasEntity = false;
    let hasData = false;
    let hasSetter = false;
    let hasAllArgsConstructor = false;
    let hasNoArgsConstructor = false;

    lines.forEach((line, idx) => {
        if (line.includes('@Entity') || line.includes('@Document')) {
            hasEntity = true;
        }
        if (line.includes('@Data')) {
            hasData = true;
            if (hasEntity) {
                vulnerabilities.push({
                    type: 'Lombok @Data on Entity',
                    severity: 'HIGH',
                    description: 'Entity class uses @Data annotation which generates public setters for all fields, including sensitive ones like roles, permissions, and internal state.',
                    line: idx + 1,
                    recommendation: 'Replace @Data with @Getter and use @Setter only on safe fields. Consider using DTOs for API boundaries.',
                    file: filename,
                    cwe: 'CWE-915'
                });
            }
        }
        if (line.includes('@Setter') && hasEntity) {
            hasSetter = true;
            vulnerabilities.push({
                type: 'Lombok @Setter on Entity',
                severity: 'MEDIUM',
                description: 'Entity class uses @Setter which may expose fields to mass assignment attacks.',
                line: idx + 1,
                recommendation: 'Use @Setter only on specific safe fields, or use DTOs for data transfer.',
                file: filename,
                cwe: 'CWE-915'
            });
        }
        if (line.includes('@AllArgsConstructor') && hasEntity) {
            hasAllArgsConstructor = true;
        }
        if (line.includes('@NoArgsConstructor') && hasEntity) {
            hasNoArgsConstructor = true;
        }
    });

    // Check for dangerous combinations
    if (hasEntity && hasAllArgsConstructor && hasNoArgsConstructor) {
        vulnerabilities.push({
            type: 'Dangerous Lombok Constructor Combination',
            severity: 'MEDIUM',
            description: 'Entity has both @AllArgsConstructor and @NoArgsConstructor which can be exploited with reflection.',
            line: findLineNumber(code, '@AllArgsConstructor'),
            recommendation: 'Use @RequiredArgsConstructor with @NonNull on required fields only.',
            file: filename,
            cwe: 'CWE-915'
        });
    }

    return vulnerabilities;
}

/**
 * Check for entity exposure patterns
 */
function checkEntityExposure(code, filename) {
    const vulnerabilities = [];

    // Check for @JsonIgnore missing on sensitive fields
    const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'privateKey', 'salt'];
    const lines = code.split('\n');

    let inEntity = false;
    lines.forEach((line, idx) => {
        if (line.includes('@Entity') || line.includes('@Document')) {
            inEntity = true;
        }

        if (inEntity) {
            sensitiveFields.forEach(field => {
                const fieldPattern = new RegExp(`private\\s+\\w+\\s+${field}`, 'i');
                if (fieldPattern.test(line) && !lines[idx - 1]?.includes('@JsonIgnore')) {
                    vulnerabilities.push({
                        type: 'Sensitive Field Without @JsonIgnore',
                        severity: 'HIGH',
                        description: `Sensitive field '${field}' is not marked with @JsonIgnore and may be exposed in API responses.`,
                        line: idx + 1,
                        recommendation: `Add @JsonIgnore annotation above the ${field} field to prevent serialization.`,
                        file: filename,
                        cwe: 'CWE-200'
                    });
                }
            });
        }
    });

    return vulnerabilities;
}

/**
 * Check for direct entity exposure in controllers
 */
function checkControllerBindings(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');

    let isController = false;
    lines.forEach((line) => {
        if (line.includes('@RestController') || line.includes('@Controller')) {
            isController = true;
        }
    });

    if (!isController) return vulnerabilities;

    // Check for @RequestBody with entity classes
    lines.forEach((line, idx) => {
        if (line.includes('@RequestBody')) {
            const entityPattern = /@RequestBody\s+(\w+)\s+/;
            const match = line.match(entityPattern);

            if (match) {
                const paramType = match[1];

                // Common entity class names or if code contains entity definition
                if (paramType.match(/^(User|Account|Order|Product|Customer|Employee|Payment|Transaction)$/i) ||
                    (code.includes(`class ${paramType}`) && code.includes('@Entity'))) {

                    vulnerabilities.push({
                        type: 'Direct Entity Binding in Controller',
                        severity: 'HIGH',
                        description: `Controller method binds @RequestBody directly to entity class '${paramType}' without DTO layer. This allows clients to modify any field.`,
                        line: idx + 1,
                        recommendation: `Create a ${paramType}DTO class with only modifiable fields. Map DTO to entity in service layer.`,
                        file: filename,
                        cwe: 'CWE-915'
                    });
                }
            }
        }
    });

    return vulnerabilities;
}

/**
 * Check for validation annotations
 */
function checkValidationAnnotations(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');

    lines.forEach((line, idx) => {
        if (line.includes('@RequestBody') && !line.includes('@Valid') && !line.includes('@Validated')) {
            vulnerabilities.push({
                type: 'Missing Input Validation',
                severity: 'MEDIUM',
                description: 'Request body parameter lacks validation annotations.',
                line: idx + 1,
                recommendation: 'Add @Valid or @Validated annotation and use Bean Validation constraints.',
                file: filename,
                cwe: 'CWE-20'
            });
        }
    });

    return vulnerabilities;
}

/**
 * Check for JPA relationship issues
 */
function checkJpaRelationships(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');

    lines.forEach((line, idx) => {
        // Check for cascade = CascadeType.ALL on relationships
        if ((line.includes('@OneToMany') || line.includes('@ManyToMany') ||
             line.includes('@ManyToOne') || line.includes('@OneToOne')) &&
            line.includes('cascade') && line.includes('CascadeType.ALL')) {
            vulnerabilities.push({
                type: 'Dangerous JPA Cascade Configuration',
                severity: 'MEDIUM',
                description: 'Relationship uses CascadeType.ALL which can lead to unintended data modifications through mass assignment.',
                line: idx + 1,
                recommendation: 'Use specific cascade types (PERSIST, MERGE) instead of ALL. Handle deletions explicitly.',
                file: filename,
                cwe: 'CWE-915'
            });
        }

        // Check for orphanRemoval without proper safeguards
        if (line.includes('orphanRemoval = true') && !code.includes('@PreRemove')) {
            vulnerabilities.push({
                type: 'Unsafe Orphan Removal',
                severity: 'LOW',
                description: 'orphanRemoval=true without lifecycle callbacks may lead to unintended deletions.',
                line: idx + 1,
                recommendation: 'Add @PreRemove lifecycle callback to validate deletions.',
                file: filename,
                cwe: 'CWE-915'
            });
        }
    });

    return vulnerabilities;
}

/**
 * Check for unfiltered service-layer persistence (R-06).
 *
 * Rule: in a @Service class, a method that takes an object as a parameter and
 * passes that parameter straight to a repository save/persist call persists
 * whatever the caller supplied, with no validation or field filtering in
 * between. That is the service-layer mass-assignment path.
 *
 * What counts as "unfiltered": the save argument is the parameter itself. A
 * method that checks one field (a null check, hashing the password, setting one
 * server-controlled field) and then saves the parameter is still unfiltered —
 * every other field the caller supplied is persisted as-is. Only the patterns
 * that do NOT pass the parameter to the save are safe: building the entity
 * locally from a DTO, or copying an allowlist of fields onto an entity loaded
 * from the database and saving that. Those are excluded by construction, because
 * the save argument is a local variable, not the parameter.
 * A @Valid annotation on the parameter suppresses the finding, matching how the
 * codebase treats @Valid as validated input elsewhere (R-04).
 * One finding per method, reported at the save line (this matches the reference
 * set, which records one R-06 instance per service method, at the save call).
 * saveAll() is deliberately not covered: it takes a collection, and deciding
 * whether a collection was filtered needs data-flow this line scanner cannot do.
 * Multi-line method signatures are not matched either.
 */
function checkServiceLayerPersistence(code, filename) {
    const vulnerabilities = [];
    const lines = code.split('\n');
    const SAVE_CALL = /\.\s*(save|saveAndFlush|persist)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/;

    // Brace depth before each line, so methods can be matched to their bodies.
    // (Comments were already stripped by stripJavaComments.)
    let depth = 0;
    const depthAtLine = lines.map((line) => {
        const d = depth;
        for (const ch of line) {
            if (ch === '{') depth++;
            else if (ch === '}') depth--;
        }
        return d;
    });

    // Find the @Service class: the annotation line, then the class declaration.
    // Record the line range and depth of its body.
    let classLine = -1;
    let classEnd = -1;
    let serviceDepth = -1;
    let sawService = false;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/@Service\b/.test(line)) sawService = true;
        if (sawService && /\bclass\s+\w+/.test(line)) {
            classLine = i;
            serviceDepth = depthAtLine[i] + (line.match(/\{/g) || []).length;
            if (!line.includes('{')) serviceDepth = depthAtLine[i] + 1;
            for (let j = i + 1; j < lines.length; j++) {
                if (depthAtLine[j] < serviceDepth) { classEnd = j; break; }
            }
            if (classEnd < 0) classEnd = lines.length;
            break;
        }
    }
    if (classLine < 0) return vulnerabilities;

    // Walk method signatures inside the service class.
    const SIG = /^\s*(public|protected|private)\s+(?:static\s+)?[\w<>\[\],.? ]+?\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s.]+)?\s*\{?\s*$/;
    for (let i = classLine + 1; i < classEnd; i++) {
        const line = lines[i];
        if (depthAtLine[i] !== serviceDepth) continue;
        const sig = line.match(SIG);
        if (!sig) continue;
        const paramsRaw = sig[3].trim();
        if (!paramsRaw) continue;
        const paramNames = paramsRaw.split(',').map((p) => {
            const tokens = p.trim().split(/\s+/);
            return tokens[tokens.length - 1];
        }).filter((n) => /^[A-Za-z_$][\w$]*$/.test(n));
        if (paramNames.length === 0) continue;
        if (/@Valid\b/.test(line)) continue;

        // Find the method body: from the signature line until the braces balance.
        let bodyDepth = 0;
        let opened = false;
        let bodyEnd = -1;
        for (let j = i; j < lines.length; j++) {
            for (const ch of lines[j]) {
                if (ch === '{') { bodyDepth++; opened = true; }
                else if (ch === '}') bodyDepth--;
            }
            if (opened && bodyDepth === 0) { bodyEnd = j; break; }
        }
        if (bodyEnd < 0) continue;

        // Find a save/persist call in the body whose argument is a parameter.
        // No "used elsewhere" guard: checking one field (a null check, hashing
        // the password) does not filter the rest of the fields, so it does not
        // exempt the method. The safe patterns (DTO mapping, allowlist copy)
        // are excluded by construction — their save argument is a local, not
        // the parameter.
        for (let k = i; k <= bodyEnd; k++) {
            const m = lines[k].match(SAVE_CALL);
            if (!m) continue;
            const arg = m[2];
            if (!paramNames.includes(arg)) continue;
            vulnerabilities.push({
                type: 'Unfiltered Service-Layer Persistence',
                severity: 'MEDIUM',
                description: `Service method passes parameter '${arg}' directly to a repository save/persist call without validation or field filtering, so any field the caller supplied is persisted as-is.`,
                line: k + 1,
                recommendation: 'Validate or filter the entity\'s fields before persisting it, or map from a DTO that exposes only safe fields.',
                file: filename,
                cwe: 'CWE-915'
            });
            break; // one finding per method
        }
    }

    return vulnerabilities;
}

/**
 * Check for setters on sensitive fields
 */
function checkSensitiveFieldSetters(code, filename) {
    const vulnerabilities = [];
    const sensitiveFields = ['role', 'permission', 'isAdmin', 'isActive', 'balance', 'credit', 'creditLimit'];
    const lines = code.split('\n');

    sensitiveFields.forEach(field => {
        const setterPattern = new RegExp(`public\\s+void\\s+set${field}`, 'i');
        lines.forEach((line, idx) => {
            if (setterPattern.test(line)) {
                vulnerabilities.push({
                    type: 'Public Setter on Sensitive Field',
                    severity: 'HIGH',
                    description: `Public setter found for sensitive field '${field}' which can be exploited via mass assignment.`,
                    line: idx + 1,
                    recommendation: `Remove public setter for ${field} or make it private/protected. Update field through business logic methods only.`,
                    file: filename,
                    cwe: 'CWE-915'
                });
            }
        });
    });

    return vulnerabilities;
}

/**
 * Analyze YAML configuration files
 */
function analyzeYamlFile(code, filename) {
    const vulnerabilities = [];

    // Check for unsafe Jackson config
    if (code.includes('fail-on-unknown-properties: false')) {
        vulnerabilities.push({
            type: 'Unsafe Jackson Deserialization',
            severity: 'MEDIUM',
            description: 'Jackson configured to accept unknown properties, enabling mass assignment attacks.',
            line: findLineNumber(code, 'fail-on-unknown-properties'),
            recommendation: 'Set fail-on-unknown-properties to true or remove this configuration.',
            file: filename,
            cwe: 'CWE-915'
        });
    }

    if (code.includes('fail-on-ignored-properties: false')) {
        vulnerabilities.push({
            type: 'Unsafe Jackson Configuration',
            severity: 'MEDIUM',
            description: 'Jackson configured to ignore @JsonIgnore annotations.',
            line: findLineNumber(code, 'fail-on-ignored-properties'),
            recommendation: 'Set fail-on-ignored-properties to true.',
            file: filename,
            cwe: 'CWE-915'
        });
    }

    // Check for permissive MVC configuration
    if (code.includes('throw-exception-if-no-handler-found: false')) {
        vulnerabilities.push({
            type: 'Permissive MVC Configuration',
            severity: 'LOW',
            description: 'MVC configured to silently ignore missing handlers.',
            line: findLineNumber(code, 'throw-exception-if-no-handler-found'),
            recommendation: 'Enable exception throwing for missing handlers.',
            file: filename,
            cwe: 'CWE-755'
        });
    }

    return vulnerabilities;
}

function findLineNumber(code, searchTerm) {
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(searchTerm)) {
            return i + 1;
        }
    }
    return 1;
}

function getSeverityStats(vulnerabilities) {
    return {
        high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: vulnerabilities.filter(v => v.severity === 'LOW').length,
        total: vulnerabilities.length
    };
}

module.exports = {
    detectVulnerabilities,
    getSeverityStats
};

