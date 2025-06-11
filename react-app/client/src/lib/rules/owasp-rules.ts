
import type { OwaspRule } from "@shared/schema";

// Comprehensive Security Framework Rules - OWASP, NIST, CIS, SANS, ISO 27001, PCI DSS, and more
export const OWASP_RULES: OwaspRule[] = [
  // A01: Broken Access Control - Enhanced Rules
  {
    id: 'direct-object-reference',
    name: 'Insecure Direct Object Reference',
    description: 'Detects direct object references without authorization checks',
    category: 'A01:2021 - Broken Access Control',
    severity: 'critical',
    pattern: /(?:\/users?\/\d+|\/files?\/[\w\-]+|\/documents?\/\d+)(?!\s*(?:\.authorize|\.check|\.verify|auth|permission))/gi,
    recommendation: 'Implement proper authorization checks before accessing resources.',
    enabled: true
  },
  {
    id: 'missing-access-control',
    name: 'Missing Access Control Middleware',
    description: 'Detects endpoints without authentication middleware',
    category: 'A01:2021 - Broken Access Control',
    severity: 'high',
    pattern: /(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"][^'"]*['"],\s*(?!.*(?:auth|authenticate|isLoggedIn|requireLogin|checkPermission|verifyToken))/gi,
    recommendation: 'Add authentication middleware to protect sensitive endpoints.',
    enabled: true
  },
  {
    id: 'privilege-escalation-risk',
    name: 'Potential Privilege Escalation',
    description: 'Detects role assignment without proper validation',
    category: 'A01:2021 - Broken Access Control',
    severity: 'critical',
    pattern: /(?:user\.role|userRole|\.setRole)\s*=\s*(?:request\.|req\.|params\.|body\.)/gi,
    recommendation: 'Validate role assignments and implement proper authorization checks.',
    enabled: true
  },
  {
    id: 'cors-wildcard',
    name: 'Overly Permissive CORS',
    description: 'Detects wildcard CORS configuration that allows any origin',
    category: 'A01:2021 - Broken Access Control',
    severity: 'medium',
    pattern: /Access-Control-Allow-Origin['"]?\s*:\s*['"]?\*/gi,
    recommendation: 'Configure CORS with specific allowed origins instead of wildcards.',
    enabled: true
  },

  // A02: Cryptographic Failures - Enhanced Rules
  {
    id: 'hardcoded-secrets-comprehensive',
    name: 'Comprehensive Hardcoded Secrets Detection',
    description: 'Detects various forms of hardcoded secrets and credentials',
    category: 'A02:2021 - Cryptographic Failures',
    severity: 'critical',
    pattern: /(?:(?:api_?key|apikey|secret_?key|secretkey|access_?token|accesstoken|private_?key|privatekey|client_?secret|clientsecret|auth_?token|authtoken|bearer_?token|bearertoken|refresh_?token|refreshtoken|session_?secret|sessionsecret|jwt_?secret|jwtsecret|encryption_?key|encryptionkey|db_?password|dbpassword|database_?password|databasepassword|admin_?password|adminpassword|root_?password|rootpassword|master_?key|masterkey|service_?account|serviceaccount)\s*[:=]\s*['"][^'"]{8,}['"])/gi,
    recommendation: 'Move all secrets to environment variables or secure configuration systems.',
    enabled: true
  },
  {
    id: 'weak-encryption-algorithms',
    name: 'Weak Encryption Algorithms',
    description: 'Detects use of deprecated or weak encryption algorithms',
    category: 'A02:2021 - Cryptographic Failures',
    severity: 'high',
    pattern: /(?:DES|3DES|RC4|MD4|MD5|SHA1)(?:\(|\.getInstance|algorithm)/gi,
    recommendation: 'Use strong encryption algorithms like AES-256, SHA-256, or SHA-3.',
    enabled: true
  },
  {
    id: 'weak-ssl-tls',
    name: 'Weak SSL/TLS Configuration',
    description: 'Detects weak SSL/TLS configurations and protocols',
    category: 'A02:2021 - Cryptographic Failures',
    severity: 'high',
    pattern: /(?:SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|ssl_verify\s*=\s*False|verify\s*=\s*False|CERT_NONE)/gi,
    recommendation: 'Use TLS 1.2 or higher with proper certificate validation.',
    enabled: true
  },
  {
    id: 'insecure-random-comprehensive',
    name: 'Comprehensive Insecure Random Detection',
    description: 'Detects various forms of insecure random number generation',
    category: 'A02:2021 - Cryptographic Failures',
    severity: 'medium',
    pattern: /(?:Math\.random|new\s+Random\(\)|random\.(?:randint|choice|uniform|random)|rand\(\)|srand\(\)|time\(\)\s*%)/gi,
    recommendation: 'Use cryptographically secure random generators (crypto.getRandomValues, SecureRandom, secrets module).',
    enabled: true
  },

  // A03: Injection - Enhanced Rules
  {
    id: 'sql-injection-comprehensive',
    name: 'Comprehensive SQL Injection Detection',
    description: 'Advanced SQL injection detection with context awareness',
    category: 'A03:2021 - Injection',
    severity: 'critical',
    pattern: /(?:(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\s+.*(?:\+|concat|format|f['"].*\{.*\}['"]|\$\{.*\}|\%s|\%d).*(?:FROM|INTO|SET|WHERE|VALUES|TABLE|DATABASE))/gi,
    recommendation: 'Use parameterized queries, prepared statements, or ORM with proper escaping.',
    enabled: true
  },
  {
    id: 'nosql-injection',
    name: 'NoSQL Injection Detection',
    description: 'Detects NoSQL injection vulnerabilities in MongoDB and similar databases',
    category: 'A03:2021 - Injection',
    severity: 'critical',
    pattern: /(?:db\.collection\.find|find\(\s*\{[^}]*\$(?:where|regex|gt|lt|ne|in|nin|exists|size|all|elemMatch)\s*:|eval\s*\(\s*\{)/gi,
    recommendation: 'Validate and sanitize all user inputs before using in NoSQL queries.',
    enabled: true
  },
  {
    id: 'command-injection-comprehensive',
    name: 'Comprehensive Command Injection',
    description: 'Enhanced command injection detection across multiple languages',
    category: 'A03:2021 - Injection',
    severity: 'critical',
    pattern: /(?:(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|subprocess\.(?:call|run|Popen|check_output)|exec|eval|system|shell_exec|passthru|proc_open|popen)\s*\([^)]*(?:\+|concat|format|f['"].*\{.*\}['"]|\$\{.*\}|\%s))/gi,
    recommendation: 'Avoid executing system commands with user input. Use safe alternatives and input validation.',
    enabled: true
  },
  {
    id: 'xss-comprehensive',
    name: 'Comprehensive XSS Detection',
    description: 'Advanced cross-site scripting detection with context awareness',
    category: 'A03:2021 - Injection',
    severity: 'high',
    pattern: /(?:innerHTML\s*=|document\.write\s*\(|\.html\s*\(|dangerouslySetInnerHTML|v-html|ng-bind-html)(?!\s*(?:DOMPurify|sanitize|escape|encode))[^;]*(?:\+|concat|template|interpolat|\$\{|\{\{)/gi,
    recommendation: 'Use proper output encoding, Content Security Policy, and sanitization libraries.',
    enabled: true
  },
  {
    id: 'ldap-injection-enhanced',
    name: 'Enhanced LDAP Injection Detection',
    description: 'Detects LDAP injection with various input patterns',
    category: 'A03:2021 - Injection',
    severity: 'high',
    pattern: /(?:LdapContext|InitialDirContext|search|searchSubtree).*(?:\+|concat|format|f['"].*\{.*\}['"]|\$\{.*\}).*(?:\(|\)|&|\||=|\*|<|>)/gi,
    recommendation: 'Use LDAP escaping functions and validate all user inputs in LDAP queries.',
    enabled: true
  },
  {
    id: 'xml-injection',
    name: 'XML/XXE Injection Detection',
    description: 'Detects XML External Entity and XML injection vulnerabilities',
    category: 'A03:2021 - Injection',
    severity: 'high',
    pattern: /(?:DocumentBuilderFactory|SAXParserFactory|XMLReader|XMLInputFactory)(?!.*setFeature.*XMLConstants\.FEATURE_SECURE_PROCESSING)/gi,
    recommendation: 'Disable XML external entity processing and use secure XML parsing configurations.',
    enabled: true
  },

  // A04: Insecure Design - Enhanced Rules
  {
    id: 'missing-rate-limiting',
    name: 'Missing Rate Limiting',
    description: 'Detects endpoints without rate limiting that could be abused',
    category: 'A04:2021 - Insecure Design',
    severity: 'medium',
    pattern: /(?:app|router)\.post\s*\(\s*['"][^'"]*(?:login|register|forgot|reset|contact|search|upload)['"](?!.*(?:rateLimit|rateLimiter|throttle|limit))/gi,
    recommendation: 'Implement rate limiting for sensitive endpoints to prevent abuse.',
    enabled: true
  },
  {
    id: 'insufficient-input-validation',
    name: 'Insufficient Input Validation',
    description: 'Detects direct use of user input without comprehensive validation',
    category: 'A04:2021 - Insecure Design',
    severity: 'medium',
    pattern: /(?:req\.(?:body|query|params)|request\.(?:form|args|json|data))\.[a-zA-Z_]+(?!\s*(?:validate|sanitize|clean|check|filter|escape|strip|trim|length|match|test|startsWith|endsWith|includes))/gi,
    recommendation: 'Implement comprehensive input validation, sanitization, and type checking.',
    enabled: true
  },
  {
    id: 'business-logic-bypass',
    name: 'Business Logic Bypass Risk',
    description: 'Detects potential business logic bypass vulnerabilities',
    category: 'A04:2021 - Insecure Design',
    severity: 'high',
    pattern: /(?:price|amount|balance|quantity|discount|total)\s*=\s*(?:req\.|request\.|params\.|body\.)/gi,
    recommendation: 'Validate business logic constraints server-side and implement proper checks.',
    enabled: true
  },

  // A05: Security Misconfiguration - Enhanced Rules
  {
    id: 'debug-mode-production',
    name: 'Debug Mode in Production',
    description: 'Detects debug mode enabled in production environments',
    category: 'A05:2021 - Security Misconfiguration',
    severity: 'high',
    pattern: /(?:DEBUG\s*=\s*True|debug\s*=\s*true|development|app\.set\s*\(\s*['"]env['"],\s*['"]development['"])/gi,
    recommendation: 'Disable debug mode in production environments and use proper logging.',
    enabled: true
  },
  {
    id: 'default-credentials',
    name: 'Default Credentials Usage',
    description: 'Detects usage of default or common credentials',
    category: 'A05:2021 - Security Misconfiguration',
    severity: 'critical',
    pattern: /(?:admin|administrator|root|sa|postgres|mysql|oracle|password|123456|qwerty|letmein|welcome|default)/gi,
    recommendation: 'Change all default credentials and use strong, unique passwords.',
    enabled: true
  },
  {
    id: 'insecure-headers',
    name: 'Missing Security Headers',
    description: 'Detects missing or insecure HTTP security headers',
    category: 'A05:2021 - Security Misconfiguration',
    severity: 'medium',
    pattern: /(?:X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Strict-Transport-Security|Content-Security-Policy)(?!.*(?:DENY|nosniff|1; mode=block|max-age|default-src))/gi,
    recommendation: 'Implement proper security headers to protect against common attacks.',
    enabled: true
  },

  // A06: Vulnerable Components - Enhanced Rules
  {
    id: 'outdated-dependencies',
    name: 'Potentially Outdated Dependencies',
    description: 'Detects imports of commonly vulnerable libraries',
    category: 'A06:2021 - Vulnerable and Outdated Components',
    severity: 'medium',
    pattern: /(?:import|require|from)\s+(?:['"](?:lodash|moment|jquery|bootstrap|angular|react)['"]\s*(?:;|$)|jquery|moment\.js|bootstrap\.js)/gi,
    recommendation: 'Regularly update dependencies and scan for known vulnerabilities.',
    enabled: true
  },
  {
    id: 'unsafe-dependencies',
    name: 'Known Unsafe Dependencies',
    description: 'Detects usage of libraries with known security issues',
    category: 'A06:2021 - Vulnerable and Outdated Components',
    severity: 'high',
    pattern: /(?:eval|vm\.runInThisContext|vm\.runInNewContext|Function\s*\(|setTimeout\s*\(\s*['"]|setInterval\s*\(\s*['"])/gi,
    recommendation: 'Avoid using eval and similar dynamic code execution functions.',
    enabled: true
  },

  // A07: Identification and Authentication Failures - Enhanced Rules
  {
    id: 'weak-session-management',
    name: 'Weak Session Management',
    description: 'Detects weak session configuration and management',
    category: 'A07:2021 - Identification and Authentication Failures',
    severity: 'high',
    pattern: /(?:session\s*\(\s*\{[^}]*(?:secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*false)|express-session.*secret\s*:\s*['"][^'"]{1,8}['"])/gi,
    recommendation: 'Configure secure session settings with proper flags and strong secrets.',
    enabled: true
  },
  {
    id: 'insufficient-password-policy',
    name: 'Insufficient Password Policy',
    description: 'Detects weak password validation and storage',
    category: 'A07:2021 - Identification and Authentication Failures',
    severity: 'high',
    pattern: /(?:password\.length\s*[<>=]+\s*[1-7]|password\s*===?\s*['"][^'"]{1,7}['"]|md5\s*\(\s*password|sha1\s*\(\s*password)/gi,
    recommendation: 'Implement strong password policies and use secure hashing algorithms like bcrypt.',
    enabled: true
  },
  {
    id: 'jwt-vulnerabilities',
    name: 'JWT Security Issues',
    description: 'Detects common JWT implementation vulnerabilities',
    category: 'A07:2021 - Identification and Authentication Failures',
    severity: 'high',
    pattern: /(?:jwt\.sign\s*\([^,]*,\s*null|jwt\.verify\s*\([^,]*,\s*null|algorithm\s*:\s*['"]none['"])/gi,
    recommendation: 'Use strong secrets for JWT signing and avoid the "none" algorithm.',
    enabled: true
  },

  // A08: Software and Data Integrity Failures - Enhanced Rules
  {
    id: 'insecure-deserialization-comprehensive',
    name: 'Comprehensive Insecure Deserialization',
    description: 'Enhanced detection of unsafe deserialization across multiple languages',
    category: 'A08:2021 - Software and Data Integrity Failures',
    severity: 'critical',
    pattern: /(?:pickle\.loads?|ObjectInputStream\.readObject|unserialize|yaml\.load|eval\s*\(|JSON\.parse.*localStorage|JSON\.parse.*sessionStorage)/gi,
    recommendation: 'Validate serialized data, use safe deserialization methods, and implement integrity checks.',
    enabled: true
  },
  {
    id: 'unsafe-file-operations',
    name: 'Unsafe File Operations',
    description: 'Detects unsafe file upload and processing operations',
    category: 'A08:2021 - Software and Data Integrity Failures',
    severity: 'high',
    pattern: /(?:multer|formidable|busboy)(?!.*(?:fileFilter|limits|whitelist|allowedTypes))|(?:fs\.writeFile|writeFileSync).*(?:\+|concat|interpolat)/gi,
    recommendation: 'Implement file type validation, size limits, and secure file storage practices.',
    enabled: true
  },

  // A09: Security Logging and Monitoring Failures - Enhanced Rules
  {
    id: 'sensitive-data-logging-comprehensive',
    name: 'Comprehensive Sensitive Data Logging',
    description: 'Enhanced detection of sensitive information in logs',
    category: 'A09:2021 - Security Logging and Monitoring Failures',
    severity: 'high',
    pattern: /(?:console\.log|print|logger|log\.info|System\.out\.println).*(?:password|credit|card|ssn|social|token|key|secret|pin|account|auth|session)/gi,
    recommendation: 'Implement structured logging with data classification and avoid logging sensitive information.',
    enabled: true
  },
  {
    id: 'missing-security-logging',
    name: 'Missing Security Event Logging',
    description: 'Detects security-critical operations without proper logging',
    category: 'A09:2021 - Security Logging and Monitoring Failures',
    severity: 'medium',
    pattern: /(?:login|logout|register|delete|admin|password.*change)(?!.*(?:log|audit|track|monitor|record))/gi,
    recommendation: 'Implement comprehensive security event logging for audit trails.',
    enabled: true
  },

  // A10: Server-Side Request Forgery - Enhanced Rules
  {
    id: 'ssrf-comprehensive',
    name: 'Comprehensive SSRF Detection',
    description: 'Enhanced detection of Server-Side Request Forgery vulnerabilities',
    category: 'A10:2021 - Server-Side Request Forgery (SSRF)',
    severity: 'critical',
    pattern: /(?:requests\.get|urllib\.request|fetch|axios|http\.request|curl|wget).*(?:\+|concat|format|f['"].*\{.*\}['"]|\$\{.*\}|interpolat).*(?:http|ftp|file|gopher|dict|ldap)/gi,
    recommendation: 'Validate and whitelist allowed URLs, use URL parsing libraries, and restrict network access.',
    enabled: true
  },

  // Additional Security Categories
  {
    id: 'buffer-overflow-risk',
    name: 'Buffer Overflow Risk',
    description: 'Detects potential buffer overflow vulnerabilities in C/C++ style operations',
    category: 'BUFF - Buffer Overflow Protection',
    severity: 'high',
    pattern: /(?:strcpy|strcat|sprintf|gets|scanf|memcpy)(?!\s*(?:_s|_safe|secure))/gi,
    recommendation: 'Use safe string functions and bounds checking to prevent buffer overflows.',
    enabled: true
  },
  {
    id: 'race-condition-risk',
    name: 'Race Condition Risk',
    description: 'Detects potential race condition vulnerabilities',
    category: 'RACE - Race Condition Detection',
    severity: 'medium',
    pattern: /(?:temp|tmp).*(?:createTempFile|mktemp|tempfile)(?!.*atomic|lock|synchronized)/gi,
    recommendation: 'Use atomic operations, proper locking mechanisms, and secure temporary file creation.',
    enabled: true
  },
  {
    id: 'information-disclosure-comprehensive',
    name: 'Comprehensive Information Disclosure',
    description: 'Enhanced detection of information disclosure vulnerabilities',
    category: 'INFO - Information Disclosure',
    severity: 'medium',
    pattern: /(?:stack\s*trace|error\s*message|exception\s*detail|debug\s*info|server\s*version|php\s*version|database\s*version)(?!.*(?:suppress|hide|mask|sanitize))/gi,
    recommendation: 'Implement proper error handling and avoid exposing sensitive system information.',
    enabled: true
  },
  {
    id: 'dos-resource-exhaustion',
    name: 'DoS Resource Exhaustion',
    description: 'Detects potential denial of service through resource exhaustion',
    category: 'DOS - Denial of Service',
    severity: 'medium',
    pattern: /(?:while\s*\(\s*true\)|for\s*\(\s*;\s*;\s*\)|recursion|infinite\s*loop)(?!.*(?:break|return|limit|timeout))/gi,
    recommendation: 'Implement proper loop controls, timeouts, and resource limits.',
    enabled: true
  },
  {
    id: 'crypto-timing-attack',
    name: 'Cryptographic Timing Attack',
    description: 'Detects potential timing attack vulnerabilities in cryptographic operations',
    category: 'A02:2021 - Cryptographic Failures',
    severity: 'medium',
    pattern: /(?:string\s*comparison|password\s*check|token\s*verify)(?!.*(?:constant\s*time|secure\s*compare|timing\s*safe))/gi,
    recommendation: 'Use constant-time comparison functions for cryptographic operations.',
    enabled: true
  },

  // NIST Cybersecurity Framework - Identify (ID)
  {
    id: 'nist-asset-inventory',
    name: 'Missing Asset Inventory Documentation',
    description: 'Detects lack of proper asset documentation and inventory tracking',
    category: 'NIST ID.AM - Asset Management',
    severity: 'medium',
    pattern: /(?:config|configuration|environment|env)(?!.*(?:inventory|documented|tracked|cataloged|registered))/gi,
    recommendation: 'Maintain comprehensive asset inventory and documentation.',
    enabled: true
  },
  {
    id: 'nist-data-classification',
    name: 'Unclassified Sensitive Data',
    description: 'Detects sensitive data without proper classification',
    category: 'NIST ID.GV - Governance',
    severity: 'high',
    pattern: /(?:personal|private|confidential|sensitive|pii|phi|credit|ssn|passport)(?!.*(?:classified|protected|encrypted|secured))/gi,
    recommendation: 'Implement data classification and protection controls.',
    enabled: true
  },

  // NIST Cybersecurity Framework - Protect (PR)
  {
    id: 'nist-access-control',
    name: 'Insufficient Access Control Implementation',
    description: 'Detects inadequate access control mechanisms per NIST guidelines',
    category: 'NIST PR.AC - Identity Management',
    severity: 'high',
    pattern: /(?:admin|administrator|root|superuser)(?!.*(?:multi.*factor|mfa|2fa|two.*factor|rbac|role.*based))/gi,
    recommendation: 'Implement multi-factor authentication and role-based access control.',
    enabled: true
  },
  {
    id: 'nist-data-security',
    name: 'Data at Rest Protection',
    description: 'Detects unprotected data storage per NIST standards',
    category: 'NIST PR.DS - Data Security',
    severity: 'critical',
    pattern: /(?:database|db|storage|file).*(?:password|secret|key|token)(?!.*(?:encrypt|hash|protect|secure))/gi,
    recommendation: 'Encrypt sensitive data at rest using NIST-approved algorithms.',
    enabled: true
  },
  {
    id: 'nist-maintenance',
    name: 'Inadequate Maintenance Procedures',
    description: 'Detects systems without proper maintenance procedures',
    category: 'NIST PR.MA - Maintenance',
    severity: 'medium',
    pattern: /(?:update|patch|maintenance|upgrade)(?!.*(?:schedule|automated|managed|controlled))/gi,
    recommendation: 'Implement automated patch management and maintenance procedures.',
    enabled: true
  },

  // NIST Cybersecurity Framework - Detect (DE)
  {
    id: 'nist-anomaly-detection',
    name: 'Missing Anomaly Detection',
    description: 'Detects lack of anomaly and event detection mechanisms',
    category: 'NIST DE.AE - Anomalies and Events',
    severity: 'medium',
    pattern: /(?:login|access|transaction|request)(?!.*(?:monitor|detect|alert|threshold|baseline))/gi,
    recommendation: 'Implement anomaly detection and event monitoring systems.',
    enabled: true
  },
  {
    id: 'nist-continuous-monitoring',
    name: 'Insufficient Security Monitoring',
    description: 'Detects inadequate continuous security monitoring',
    category: 'NIST DE.CM - Security Continuous Monitoring',
    severity: 'high',
    pattern: /(?:security|audit|compliance)(?!.*(?:continuous|real.*time|monitor|track|log))/gi,
    recommendation: 'Implement continuous security monitoring and logging.',
    enabled: true
  },

  // CIS Controls (Center for Internet Security)
  {
    id: 'cis-inventory-control',
    name: 'CIS Control 1: Hardware Asset Inventory',
    description: 'Detects unauthorized or unmanaged hardware assets',
    category: 'CIS Control 1 - Inventory and Control',
    severity: 'medium',
    pattern: /(?:device|hardware|server|endpoint)(?!.*(?:authorized|approved|managed|inventoried))/gi,
    recommendation: 'Maintain authorized hardware inventory and remove unauthorized devices.',
    enabled: true
  },
  {
    id: 'cis-software-inventory',
    name: 'CIS Control 2: Software Asset Inventory',
    description: 'Detects unauthorized software or missing software inventory',
    category: 'CIS Control 2 - Software Inventory',
    severity: 'medium',
    pattern: /(?:install|download|package|library|dependency)(?!.*(?:authorized|approved|whitelisted|verified))/gi,
    recommendation: 'Maintain authorized software inventory and remove unauthorized software.',
    enabled: true
  },
  {
    id: 'cis-secure-config',
    name: 'CIS Control 5: Secure Configuration',
    description: 'Detects insecure default configurations',
    category: 'CIS Control 5 - Secure Configuration',
    severity: 'high',
    pattern: /(?:default|config|configuration).*(?:admin|password|secret|key)(?!.*(?:changed|modified|secure|hardened))/gi,
    recommendation: 'Implement and maintain secure configuration standards.',
    enabled: true
  },
  {
    id: 'cis-controlled-access',
    name: 'CIS Control 6: Access Control Management',
    description: 'Detects inadequate access control management',
    category: 'CIS Control 6 - Access Control',
    severity: 'critical',
    pattern: /(?:user|account|privilege).*(?:create|add|grant)(?!.*(?:approved|authorized|reviewed|justified))/gi,
    recommendation: 'Implement formal access control management processes.',
    enabled: true
  },
  {
    id: 'cis-email-web-protection',
    name: 'CIS Control 7: Email and Web Browser Protection',
    description: 'Detects unprotected email and web communications',
    category: 'CIS Control 7 - Email and Web Protection',
    severity: 'high',
    pattern: /(?:email|mail|smtp|http|web|browser)(?!.*(?:encrypted|secured|filtered|protected))/gi,
    recommendation: 'Implement email and web browser security controls.',
    enabled: true
  },

  // SANS Top 25 Most Dangerous Software Errors
  {
    id: 'sans-cwe-79-xss',
    name: 'SANS/CWE-79: Cross-site Scripting (XSS)',
    description: 'Comprehensive XSS detection based on SANS Top 25',
    category: 'SANS Top 25 - CWE-79',
    severity: 'critical',
    pattern: /(?:innerHTML|outerHTML|document\.write|\.html\(\)|v-html|dangerouslySetInnerHTML).*(?:\+|concat|\$\{|\{\{|template)/gi,
    recommendation: 'Use proper output encoding and Content Security Policy.',
    enabled: true
  },
  {
    id: 'sans-cwe-89-sqli',
    name: 'SANS/CWE-89: SQL Injection',
    description: 'SQL injection detection based on SANS Top 25 guidelines',
    category: 'SANS Top 25 - CWE-89',
    severity: 'critical',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*(?:\+|concat|format|\$\{|\%s).*(?:FROM|INTO|SET|WHERE|VALUES)/gi,
    recommendation: 'Use parameterized queries and input validation.',
    enabled: true
  },
  {
    id: 'sans-cwe-20-input-validation',
    name: 'SANS/CWE-20: Improper Input Validation',
    description: 'Detects improper input validation per SANS guidelines',
    category: 'SANS Top 25 - CWE-20',
    severity: 'high',
    pattern: /(?:req\.|request\.|input\.|form\.)(?:body|query|params)(?!.*(?:validate|sanitize|check|verify|clean|escape))/gi,
    recommendation: 'Implement comprehensive input validation and sanitization.',
    enabled: true
  },
  {
    id: 'sans-cwe-78-os-injection',
    name: 'SANS/CWE-78: OS Command Injection',
    description: 'OS command injection detection per SANS Top 25',
    category: 'SANS Top 25 - CWE-78',
    severity: 'critical',
    pattern: /(?:exec|system|shell|spawn|child_process).*(?:\+|concat|\$\{|template|interpolat)/gi,
    recommendation: 'Avoid executing system commands with user input.',
    enabled: true
  },

  // ISO 27001 Security Controls
  {
    id: 'iso27001-access-policy',
    name: 'ISO 27001: Access Control Policy',
    description: 'Detects missing access control policy implementation',
    category: 'ISO 27001 - A.9 Access Control',
    severity: 'high',
    pattern: /(?:access|login|auth)(?!.*(?:policy|procedure|control|governed|managed))/gi,
    recommendation: 'Implement formal access control policies and procedures.',
    enabled: true
  },
  {
    id: 'iso27001-crypto-management',
    name: 'ISO 27001: Cryptography Management',
    description: 'Detects inadequate cryptographic key management',
    category: 'ISO 27001 - A.10 Cryptography',
    severity: 'critical',
    pattern: /(?:key|secret|certificate|crypto)(?!.*(?:management|rotation|escrow|lifecycle))/gi,
    recommendation: 'Implement proper cryptographic key management lifecycle.',
    enabled: true
  },
  {
    id: 'iso27001-physical-security',
    name: 'ISO 27001: Physical Security',
    description: 'Detects inadequate physical security considerations',
    category: 'ISO 27001 - A.11 Physical Security',
    severity: 'medium',
    pattern: /(?:server|datacenter|facility|equipment)(?!.*(?:secured|protected|controlled|monitored))/gi,
    recommendation: 'Implement physical security controls for critical assets.',
    enabled: true
  },
  {
    id: 'iso27001-incident-management',
    name: 'ISO 27001: Incident Management',
    description: 'Detects missing incident response procedures',
    category: 'ISO 27001 - A.16 Incident Management',
    severity: 'high',
    pattern: /(?:error|exception|failure|incident)(?!.*(?:reported|logged|handled|managed|escalated))/gi,
    recommendation: 'Implement formal incident management procedures.',
    enabled: true
  },

  // PCI DSS (Payment Card Industry Data Security Standard)
  {
    id: 'pci-dss-cardholder-data',
    name: 'PCI DSS: Cardholder Data Protection',
    description: 'Detects unprotected cardholder data',
    category: 'PCI DSS - Requirement 3',
    severity: 'critical',
    pattern: /(?:card|credit|debit|pan|cvv|cvc|expir|track)(?!.*(?:encrypt|hash|mask|tokenize|protect))/gi,
    recommendation: 'Encrypt and protect all cardholder data per PCI DSS requirements.',
    enabled: true
  },
  {
    id: 'pci-dss-transmission-security',
    name: 'PCI DSS: Secure Transmission',
    description: 'Detects insecure transmission of cardholder data',
    category: 'PCI DSS - Requirement 4',
    severity: 'critical',
    pattern: /(?:transmit|send|transfer).*(?:card|payment|credit)(?!.*(?:encrypt|tls|ssl|secure))/gi,
    recommendation: 'Encrypt cardholder data during transmission using strong cryptography.',
    enabled: true
  },
  {
    id: 'pci-dss-access-control',
    name: 'PCI DSS: Access Control',
    description: 'Detects inadequate access controls for cardholder data',
    category: 'PCI DSS - Requirement 7',
    severity: 'high',
    pattern: /(?:cardholder|payment|card.*data).*(?:access|read|view)(?!.*(?:need.*to.*know|role.*based|authorized))/gi,
    recommendation: 'Restrict access to cardholder data on need-to-know basis.',
    enabled: true
  },

  // GDPR (General Data Protection Regulation)
  {
    id: 'gdpr-personal-data',
    name: 'GDPR: Personal Data Processing',
    description: 'Detects processing of personal data without proper controls',
    category: 'GDPR - Article 6 Lawfulness',
    severity: 'critical',
    pattern: /(?:personal|private|pii|name|email|phone|address|id|identifier)(?!.*(?:consent|legitimate|legal.*basis|anonymized))/gi,
    recommendation: 'Ensure lawful basis for processing personal data and obtain consent.',
    enabled: true
  },
  {
    id: 'gdpr-data-subject-rights',
    name: 'GDPR: Data Subject Rights',
    description: 'Detects missing implementation of data subject rights',
    category: 'GDPR - Articles 15-22 Rights',
    severity: 'high',
    pattern: /(?:delete|remove|update|modify).*(?:user|customer|personal)(?!.*(?:right|request|procedure|process))/gi,
    recommendation: 'Implement procedures for data subject rights (access, rectification, erasure).',
    enabled: true
  },
  {
    id: 'gdpr-breach-notification',
    name: 'GDPR: Breach Notification',
    description: 'Detects missing breach detection and notification procedures',
    category: 'GDPR - Article 33 Breach Notification',
    severity: 'high',
    pattern: /(?:breach|leak|incident|compromise)(?!.*(?:notification|report|authority|72.*hours))/gi,
    recommendation: 'Implement breach detection and 72-hour notification procedures.',
    enabled: true
  },

  // HIPAA (Health Insurance Portability and Accountability Act)
  {
    id: 'hipaa-phi-protection',
    name: 'HIPAA: Protected Health Information',
    description: 'Detects unprotected health information',
    category: 'HIPAA - PHI Protection',
    severity: 'critical',
    pattern: /(?:health|medical|patient|phi|diagnosis|treatment|prescription)(?!.*(?:encrypt|hipaa|protected|secure|authorized))/gi,
    recommendation: 'Implement HIPAA-compliant protection for health information.',
    enabled: true
  },
  {
    id: 'hipaa-minimum-necessary',
    name: 'HIPAA: Minimum Necessary Standard',
    description: 'Detects potential violations of minimum necessary standard',
    category: 'HIPAA - Minimum Necessary',
    severity: 'high',
    pattern: /(?:select|query|fetch).*(?:patient|health|medical)(?!.*(?:where|limit|filter|necessary|authorized))/gi,
    recommendation: 'Apply minimum necessary standard when accessing health information.',
    enabled: true
  },

  // SOX (Sarbanes-Oxley Act)
  {
    id: 'sox-financial-controls',
    name: 'SOX: Financial Reporting Controls',
    description: 'Detects inadequate controls over financial data',
    category: 'SOX - Section 404 Controls',
    severity: 'high',
    pattern: /(?:financial|revenue|expense|accounting|audit)(?!.*(?:control|approval|segregation|review))/gi,
    recommendation: 'Implement proper internal controls over financial reporting.',
    enabled: true
  },
  {
    id: 'sox-audit-trail',
    name: 'SOX: Audit Trail Requirements',
    description: 'Detects missing audit trails for financial transactions',
    category: 'SOX - Audit Requirements',
    severity: 'high',
    pattern: /(?:transaction|payment|transfer|journal)(?!.*(?:log|audit|trail|track|record))/gi,
    recommendation: 'Maintain comprehensive audit trails for all financial transactions.',
    enabled: true
  },

  // FISMA (Federal Information Security Management Act)
  {
    id: 'fisma-risk-assessment',
    name: 'FISMA: Risk Assessment',
    description: 'Detects missing risk assessment procedures',
    category: 'FISMA - Risk Management',
    severity: 'medium',
    pattern: /(?:risk|threat|vulnerability)(?!.*(?:assess|evaluate|analyze|manage|mitigate))/gi,
    recommendation: 'Implement comprehensive risk assessment and management procedures.',
    enabled: true
  },
  {
    id: 'fisma-continuous-monitoring',
    name: 'FISMA: Continuous Monitoring',
    description: 'Detects inadequate continuous monitoring implementation',
    category: 'FISMA - Continuous Monitoring',
    severity: 'high',
    pattern: /(?:system|network|security)(?!.*(?:monitor|continuous|real.*time|ongoing))/gi,
    recommendation: 'Implement continuous monitoring of information systems.',
    enabled: true
  },

  // COBIT (Control Objectives for Information and Related Technologies)
  {
    id: 'cobit-governance',
    name: 'COBIT: IT Governance',
    description: 'Detects inadequate IT governance structures',
    category: 'COBIT - Governance and Management',
    severity: 'medium',
    pattern: /(?:governance|management|oversight)(?!.*(?:framework|process|structure|defined))/gi,
    recommendation: 'Implement formal IT governance framework and processes.',
    enabled: true
  },
  {
    id: 'cobit-value-delivery',
    name: 'COBIT: Value Delivery',
    description: 'Detects lack of value delivery measurement',
    category: 'COBIT - Value Delivery',
    severity: 'medium',
    pattern: /(?:project|investment|resource)(?!.*(?:value|benefit|roi|measurement|metrics))/gi,
    recommendation: 'Implement value delivery measurement and tracking mechanisms.',
    enabled: true
  },

  // Cloud Security Framework (CSA)
  {
    id: 'csa-identity-federation',
    name: 'CSA: Identity and Access Management',
    description: 'Detects inadequate cloud identity management',
    category: 'CSA - Identity and Access Management',
    severity: 'high',
    pattern: /(?:cloud|saas|iaas|paas).*(?:login|access|auth)(?!.*(?:federation|sso|multi.*factor|centralized))/gi,
    recommendation: 'Implement federated identity management for cloud services.',
    enabled: true
  },
  {
    id: 'csa-data-protection',
    name: 'CSA: Cloud Data Protection',
    description: 'Detects inadequate data protection in cloud environments',
    category: 'CSA - Data Security',
    severity: 'critical',
    pattern: /(?:cloud|storage|bucket|container).*(?:data|file|document)(?!.*(?:encrypt|protect|classify|dlp))/gi,
    recommendation: 'Implement comprehensive data protection for cloud-stored data.',
    enabled: true
  },

  // DevSecOps Security Framework
  {
    id: 'devsecops-secure-pipeline',
    name: 'DevSecOps: Secure CI/CD Pipeline',
    description: 'Detects insecure CI/CD pipeline configurations',
    category: 'DevSecOps - Secure Pipeline',
    severity: 'high',
    pattern: /(?:pipeline|ci|cd|build|deploy)(?!.*(?:security|scan|test|validate|approve))/gi,
    recommendation: 'Integrate security testing and validation into CI/CD pipelines.',
    enabled: true
  },
  {
    id: 'devsecops-infrastructure-as-code',
    name: 'DevSecOps: Infrastructure as Code Security',
    description: 'Detects insecure infrastructure as code practices',
    category: 'DevSecOps - Infrastructure Security',
    severity: 'high',
    pattern: /(?:terraform|ansible|cloudformation|kubernetes)(?!.*(?:security|policy|compliance|validation))/gi,
    recommendation: 'Implement security policies and validation for infrastructure as code.',
    enabled: true
  },

  // Zero Trust Security Framework
  {
    id: 'zero-trust-verification',
    name: 'Zero Trust: Verify Everything',
    description: 'Detects missing verification in zero trust implementation',
    category: 'Zero Trust - Never Trust, Always Verify',
    severity: 'high',
    pattern: /(?:access|request|connection)(?!.*(?:verify|authenticate|authorize|validate|check))/gi,
    recommendation: 'Implement continuous verification for all access requests.',
    enabled: true
  },
  {
    id: 'zero-trust-least-privilege',
    name: 'Zero Trust: Least Privilege Access',
    description: 'Detects violations of least privilege principle',
    category: 'Zero Trust - Least Privilege',
    severity: 'critical',
    pattern: /(?:admin|administrator|root|full.*access|wildcard)(?!.*(?:least|minimal|necessary|justified|time.*limited))/gi,
    recommendation: 'Apply least privilege access principles with just-in-time access.',
    enabled: true
  },

  // STRIDE Threat Modeling Framework (Microsoft)
  {
    id: 'stride-spoofing-detection',
    name: 'STRIDE: Spoofing Threats',
    description: 'Detects potential identity spoofing vulnerabilities',
    category: 'STRIDE - Spoofing',
    severity: 'high',
    pattern: /(?:authenticate|login|verify).*(?:username|user|id)(?!.*(?:strong|multi.*factor|certificate|biometric|secure))/gi,
    recommendation: 'Implement strong authentication mechanisms to prevent identity spoofing.',
    enabled: true
  },
  {
    id: 'stride-tampering-detection',
    name: 'STRIDE: Tampering Threats',
    description: 'Detects data tampering vulnerabilities',
    category: 'STRIDE - Tampering',
    severity: 'critical',
    pattern: /(?:data|message|request|response)(?!.*(?:integrity|hash|checksum|signature|hmac|digital.*signature))/gi,
    recommendation: 'Implement data integrity checks and digital signatures.',
    enabled: true
  },
  {
    id: 'stride-repudiation-detection',
    name: 'STRIDE: Repudiation Threats',
    description: 'Detects lack of non-repudiation mechanisms',
    category: 'STRIDE - Repudiation',
    severity: 'medium',
    pattern: /(?:transaction|action|operation|change)(?!.*(?:audit|log|trail|signature|timestamp|witness))/gi,
    recommendation: 'Implement comprehensive audit logging and digital signatures.',
    enabled: true
  },
  {
    id: 'stride-information-disclosure',
    name: 'STRIDE: Information Disclosure',
    description: 'Detects information disclosure vulnerabilities',
    category: 'STRIDE - Information Disclosure',
    severity: 'high',
    pattern: /(?:error|exception|debug|trace|stack).*(?:message|info|detail)(?!.*(?:sanitize|clean|filter|generic))/gi,
    recommendation: 'Sanitize error messages and avoid exposing sensitive information.',
    enabled: true
  },
  {
    id: 'stride-denial-of-service',
    name: 'STRIDE: Denial of Service',
    description: 'Detects DoS vulnerability patterns',
    category: 'STRIDE - Denial of Service',
    severity: 'medium',
    pattern: /(?:resource|memory|cpu|bandwidth|connection)(?!.*(?:limit|throttle|quota|pool|timeout))/gi,
    recommendation: 'Implement resource limits and rate limiting to prevent DoS attacks.',
    enabled: true
  },
  {
    id: 'stride-elevation-of-privilege',
    name: 'STRIDE: Elevation of Privilege',
    description: 'Detects privilege escalation vulnerabilities',
    category: 'STRIDE - Elevation of Privilege',
    severity: 'critical',
    pattern: /(?:privilege|permission|role|access).*(?:escalate|elevate|grant|assign)(?!.*(?:validate|authorize|approve|control))/gi,
    recommendation: 'Implement proper authorization controls for privilege changes.',
    enabled: true
  },

  // PASTA (Process for Attack Simulation and Threat Analysis)
  {
    id: 'pasta-attack-surface',
    name: 'PASTA: Attack Surface Analysis',
    description: 'Detects exposed attack surface elements',
    category: 'PASTA - Attack Surface',
    severity: 'medium',
    pattern: /(?:endpoint|api|service|interface)(?!.*(?:protected|secured|authenticated|authorized))/gi,
    recommendation: 'Minimize and secure all exposed attack surfaces.',
    enabled: true
  },
  {
    id: 'pasta-threat-enumeration',
    name: 'PASTA: Threat Enumeration',
    description: 'Detects common threat patterns in code',
    category: 'PASTA - Threat Enumeration',
    severity: 'high',
    pattern: /(?:external|untrusted|user).*(?:input|data|content)(?!.*(?:validate|sanitize|filter|escape))/gi,
    recommendation: 'Validate and sanitize all external inputs.',
    enabled: true
  },

  // DREAD Risk Assessment Model
  {
    id: 'dread-damage-potential',
    name: 'DREAD: High Damage Potential',
    description: 'Detects code patterns with high damage potential',
    category: 'DREAD - Damage Assessment',
    severity: 'critical',
    pattern: /(?:delete|drop|truncate|remove|destroy).*(?:database|table|file|data|system)(?!.*(?:backup|confirm|validate|authorize))/gi,
    recommendation: 'Implement proper authorization and backup mechanisms for destructive operations.',
    enabled: true
  },
  {
    id: 'dread-reproducibility',
    name: 'DREAD: High Reproducibility Risk',
    description: 'Detects easily reproducible vulnerabilities',
    category: 'DREAD - Reproducibility',
    severity: 'high',
    pattern: /(?:default|static|hardcoded|fixed).*(?:password|key|secret|token)(?!.*(?:change|rotate|generate|random))/gi,
    recommendation: 'Use dynamic, rotatable credentials instead of static ones.',
    enabled: true
  },
  {
    id: 'dread-exploitability',
    name: 'DREAD: High Exploitability',
    description: 'Detects easily exploitable vulnerabilities',
    category: 'DREAD - Exploitability',
    severity: 'critical',
    pattern: /(?:eval|exec|system|shell).*(?:\+|concat|interpolat|\$\{|\%s)(?!.*(?:escape|sanitize|validate|whitelist))/gi,
    recommendation: 'Avoid dynamic code execution or implement strict input validation.',
    enabled: true
  },
  {
    id: 'dread-affected-users',
    name: 'DREAD: Wide User Impact',
    description: 'Detects vulnerabilities affecting many users',
    category: 'DREAD - Affected Users',
    severity: 'high',
    pattern: /(?:global|shared|common|public).*(?:variable|resource|data|session)(?!.*(?:isolate|separate|scope|protect))/gi,
    recommendation: 'Implement proper data isolation and user separation.',
    enabled: true
  },
  {
    id: 'dread-discoverability',
    name: 'DREAD: High Discoverability',
    description: 'Detects easily discoverable vulnerabilities',
    category: 'DREAD - Discoverability',
    severity: 'medium',
    pattern: /(?:admin|test|debug|dev|staging).*(?:panel|interface|endpoint|page)(?!.*(?:hidden|protected|secure|internal))/gi,
    recommendation: 'Secure or remove discoverable administrative interfaces.',
    enabled: true
  },

  // OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation)
  {
    id: 'octave-critical-asset',
    name: 'OCTAVE: Critical Asset Protection',
    description: 'Detects inadequate protection of critical assets',
    category: 'OCTAVE - Asset Protection',
    severity: 'critical',
    pattern: /(?:critical|important|sensitive|confidential).*(?:data|asset|resource|information)(?!.*(?:encrypt|protect|secure|backup))/gi,
    recommendation: 'Implement comprehensive protection for critical assets.',
    enabled: true
  },
  {
    id: 'octave-operational-risk',
    name: 'OCTAVE: Operational Risk Assessment',
    description: 'Detects operational security risks',
    category: 'OCTAVE - Operational Risk',
    severity: 'high',
    pattern: /(?:operation|process|workflow|procedure)(?!.*(?:secure|controlled|monitored|audited))/gi,
    recommendation: 'Implement security controls for operational processes.',
    enabled: true
  },

  // FAIR (Factor Analysis of Information Risk)
  {
    id: 'fair-threat-capability',
    name: 'FAIR: Threat Capability Assessment',
    description: 'Detects high threat capability scenarios',
    category: 'FAIR - Threat Analysis',
    severity: 'high',
    pattern: /(?:advanced|sophisticated|targeted|persistent).*(?:threat|attack|exploit)(?!.*(?:detect|prevent|mitigate|respond))/gi,
    recommendation: 'Implement advanced threat detection and response capabilities.',
    enabled: true
  },
  {
    id: 'fair-vulnerability-assessment',
    name: 'FAIR: Vulnerability Assessment',
    description: 'Detects high-impact vulnerabilities per FAIR model',
    category: 'FAIR - Vulnerability Analysis',
    severity: 'critical',
    pattern: /(?:vulnerability|weakness|flaw|gap).*(?:critical|severe|high.*impact|exploitable)(?!.*(?:patch|fix|mitigate|address))/gi,
    recommendation: 'Prioritize and address high-impact vulnerabilities immediately.',
    enabled: true
  },

  // OWASP Mobile Application Security
  {
    id: 'owasp-mobile-platform',
    name: 'OWASP Mobile: Platform Usage',
    description: 'Detects insecure mobile platform usage',
    category: 'OWASP Mobile - M1 Platform Usage',
    severity: 'high',
    pattern: /(?:mobile|android|ios|cordova|phonegap).*(?:permission|capability|feature)(?!.*(?:minimal|necessary|justified|documented))/gi,
    recommendation: 'Request only necessary mobile permissions and capabilities.',
    enabled: true
  },
  {
    id: 'owasp-mobile-data-storage',
    name: 'OWASP Mobile: Insecure Data Storage',
    description: 'Detects insecure mobile data storage',
    category: 'OWASP Mobile - M2 Data Storage',
    severity: 'critical',
    pattern: /(?:localStorage|sessionStorage|sqlite|preferences|keychain).*(?:password|token|secret|key)(?!.*(?:encrypt|secure|protect))/gi,
    recommendation: 'Encrypt sensitive data stored on mobile devices.',
    enabled: true
  },
  {
    id: 'owasp-mobile-communication',
    name: 'OWASP Mobile: Insecure Communication',
    description: 'Detects insecure mobile communications',
    category: 'OWASP Mobile - M4 Communication',
    severity: 'high',
    pattern: /(?:http|ws|ftp)(?!s).*(?:mobile|app|client)(?!.*(?:tls|ssl|secure|encrypt))/gi,
    recommendation: 'Use secure communication protocols (HTTPS, WSS) for mobile apps.',
    enabled: true
  },
  {
    id: 'owasp-mobile-authentication',
    name: 'OWASP Mobile: Insufficient Authentication',
    description: 'Detects weak mobile authentication',
    category: 'OWASP Mobile - M4 Authentication',
    severity: 'critical',
    pattern: /(?:mobile|app).*(?:login|auth|authenticate)(?!.*(?:biometric|multi.*factor|strong|secure))/gi,
    recommendation: 'Implement strong authentication for mobile applications.',
    enabled: true
  },
  {
    id: 'owasp-mobile-cryptography',
    name: 'OWASP Mobile: Insufficient Cryptography',
    description: 'Detects weak mobile cryptography',
    category: 'OWASP Mobile - M5 Cryptography',
    severity: 'high',
    pattern: /(?:mobile|app).*(?:encrypt|crypto|cipher).*(?:weak|deprecated|md5|sha1|des)(?!.*(?:upgrade|replace|strengthen))/gi,
    recommendation: 'Use strong cryptographic algorithms for mobile applications.',
    enabled: true
  },

  // OWASP API Security Top 10
  {
    id: 'owasp-api-broken-object-auth',
    name: 'OWASP API: Broken Object Level Authorization',
    description: 'Detects broken object-level authorization in APIs',
    category: 'OWASP API - API1 Object Authorization',
    severity: 'critical',
    pattern: /(?:api|endpoint).*\/(?:users?|objects?|resources?)\/\d+(?!.*(?:authorize|check.*owner|verify.*access))/gi,
    recommendation: 'Implement proper object-level authorization checks in APIs.',
    enabled: true
  },
  {
    id: 'owasp-api-broken-user-auth',
    name: 'OWASP API: Broken User Authentication',
    description: 'Detects broken user authentication in APIs',
    category: 'OWASP API - API2 User Authentication',
    severity: 'critical',
    pattern: /(?:api|endpoint).*(?:login|auth|token)(?!.*(?:rate.*limit|account.*lockout|strong.*password|multi.*factor))/gi,
    recommendation: 'Implement comprehensive authentication mechanisms for APIs.',
    enabled: true
  },
  {
    id: 'owasp-api-excessive-data',
    name: 'OWASP API: Excessive Data Exposure',
    description: 'Detects excessive data exposure in API responses',
    category: 'OWASP API - API3 Data Exposure',
    severity: 'high',
    pattern: /(?:api|response|json).*(?:select.*\*|all.*fields|complete.*object)(?!.*(?:filter|limit|select.*specific|minimal))/gi,
    recommendation: 'Return only necessary data fields in API responses.',
    enabled: true
  },
  {
    id: 'owasp-api-lack-rate-limiting',
    name: 'OWASP API: Lack of Resources Rate Limiting',
    description: 'Detects missing rate limiting on API resources',
    category: 'OWASP API - API4 Rate Limiting',
    severity: 'high',
    pattern: /(?:api|endpoint|route).*(?:post|put|delete|patch)(?!.*(?:rate.*limit|throttle|quota|limit))/gi,
    recommendation: 'Implement rate limiting on API endpoints to prevent abuse.',
    enabled: true
  },
  {
    id: 'owasp-api-broken-function-auth',
    name: 'OWASP API: Broken Function Level Authorization',
    description: 'Detects broken function-level authorization',
    category: 'OWASP API - API5 Function Authorization',
    severity: 'critical',
    pattern: /(?:api|endpoint).*(?:admin|delete|modify|privileged)(?!.*(?:role.*check|permission.*verify|admin.*only))/gi,
    recommendation: 'Implement proper function-level authorization checks.',
    enabled: true
  },
  {
    id: 'owasp-api-mass-assignment',
    name: 'OWASP API: Mass Assignment',
    description: 'Detects mass assignment vulnerabilities in APIs',
    category: 'OWASP API - API6 Mass Assignment',
    severity: 'high',
    pattern: /(?:api|endpoint).*(?:req\.body|request\.json|body\.*)(?!.*(?:whitelist|allowed.*fields|validate.*fields))/gi,
    recommendation: 'Validate and whitelist allowed fields in API requests.',
    enabled: true
  },
  {
    id: 'owasp-api-security-misconfiguration',
    name: 'OWASP API: Security Misconfiguration',
    description: 'Detects API security misconfigurations',
    category: 'OWASP API - API7 Security Misconfiguration',
    severity: 'medium',
    pattern: /(?:api|cors|headers).*(?:allow.*origin.*\*|expose.*headers|allow.*credentials)(?!.*(?:specific.*domain|whitelist|secure))/gi,
    recommendation: 'Configure API security settings properly and restrictively.',
    enabled: true
  },
  {
    id: 'owasp-api-injection',
    name: 'OWASP API: Injection',
    description: 'Detects injection vulnerabilities in APIs',
    category: 'OWASP API - API8 Injection',
    severity: 'critical',
    pattern: /(?:api|query|filter|search).*(?:\+|concat|interpolat|\$\{|\%s)(?!.*(?:parameterize|escape|sanitize|validate))/gi,
    recommendation: 'Use parameterized queries and proper input validation in APIs.',
    enabled: true
  },
  {
    id: 'owasp-api-improper-assets',
    name: 'OWASP API: Improper Assets Management',
    description: 'Detects improper API assets management',
    category: 'OWASP API - API9 Assets Management',
    severity: 'medium',
    pattern: /(?:api).*(?:v1|v2|beta|test|dev|deprecated)(?!.*(?:retired|documented|secured|monitored))/gi,
    recommendation: 'Properly manage and secure all API versions and environments.',
    enabled: true
  },
  {
    id: 'owasp-api-insufficient-logging',
    name: 'OWASP API: Insufficient Logging & Monitoring',
    description: 'Detects insufficient logging and monitoring in APIs',
    category: 'OWASP API - API10 Logging & Monitoring',
    severity: 'medium',
    pattern: /(?:api|endpoint).*(?:error|failure|attack|breach)(?!.*(?:log|monitor|alert|track))/gi,
    recommendation: 'Implement comprehensive logging and monitoring for APIs.',
    enabled: true
  },

  // NIST Risk Management Framework (RMF)
  {
    id: 'nist-rmf-categorization',
    name: 'NIST RMF: System Categorization',
    description: 'Detects uncategorized systems per NIST RMF',
    category: 'NIST RMF - Categorize',
    severity: 'medium',
    pattern: /(?:system|application|service|component)(?!.*(?:categorize|classify|impact.*level|fips.*199))/gi,
    recommendation: 'Categorize systems according to NIST RMF guidelines.',
    enabled: true
  },
  {
    id: 'nist-rmf-control-selection',
    name: 'NIST RMF: Security Control Selection',
    description: 'Detects missing security control selection',
    category: 'NIST RMF - Select',
    severity: 'high',
    pattern: /(?:security|control|safeguard|countermeasure)(?!.*(?:select|baseline|tailore|customize))/gi,
    recommendation: 'Select appropriate security controls based on system categorization.',
    enabled: true
  },
  {
    id: 'nist-rmf-implementation',
    name: 'NIST RMF: Control Implementation',
    description: 'Detects incomplete control implementation',
    category: 'NIST RMF - Implement',
    severity: 'high',
    pattern: /(?:implement|deploy|configure).*(?:control|security)(?!.*(?:complete|tested|validated|documented))/gi,
    recommendation: 'Fully implement and document all selected security controls.',
    enabled: true
  },
  {
    id: 'nist-rmf-assessment',
    name: 'NIST RMF: Security Assessment',
    description: 'Detects missing security assessments',
    category: 'NIST RMF - Assess',
    severity: 'medium',
    pattern: /(?:assessment|test|evaluation|validation)(?!.*(?:security|control|compliance|effectiveness))/gi,
    recommendation: 'Conduct comprehensive security assessments of implemented controls.',
    enabled: true
  },
  {
    id: 'nist-rmf-authorization',
    name: 'NIST RMF: Authorization',
    description: 'Detects missing system authorization',
    category: 'NIST RMF - Authorize',
    severity: 'critical',
    pattern: /(?:authorize|approval|accredit)(?!.*(?:risk|accept|formal|documented|signed))/gi,
    recommendation: 'Obtain formal authorization to operate based on acceptable risk.',
    enabled: true
  },
  {
    id: 'nist-rmf-monitoring',
    name: 'NIST RMF: Continuous Monitoring',
    description: 'Detects inadequate continuous monitoring',
    category: 'NIST RMF - Monitor',
    severity: 'high',
    pattern: /(?:monitor|surveillance|oversight)(?!.*(?:continuous|ongoing|real.*time|automated))/gi,
    recommendation: 'Implement continuous monitoring of security controls and system state.',
    enabled: true
  },

  // ENISA (European Union Agency for Cybersecurity) Guidelines
  {
    id: 'enisa-incident-response',
    name: 'ENISA: Incident Response',
    description: 'Detects inadequate incident response capabilities',
    category: 'ENISA - Incident Response',
    severity: 'high',
    pattern: /(?:incident|breach|attack|compromise)(?!.*(?:response|plan|team|procedure|escalation))/gi,
    recommendation: 'Implement comprehensive incident response procedures per ENISA guidelines.',
    enabled: true
  },
  {
    id: 'enisa-supply-chain',
    name: 'ENISA: Supply Chain Security',
    description: 'Detects supply chain security risks',
    category: 'ENISA - Supply Chain',
    severity: 'high',
    pattern: /(?:supplier|vendor|third.*party|dependency)(?!.*(?:secure|vetted|assessed|monitored))/gi,
    recommendation: 'Implement supply chain security assessments and monitoring.',
    enabled: true
  },
  {
    id: 'enisa-privacy-engineering',
    name: 'ENISA: Privacy by Design',
    description: 'Detects missing privacy by design principles',
    category: 'ENISA - Privacy Engineering',
    severity: 'high',
    pattern: /(?:personal|private|sensitive).*(?:data|information)(?!.*(?:privacy|anonymous|pseudonym|minimize))/gi,
    recommendation: 'Implement privacy by design principles in data processing.',
    enabled: true
  },

  // Australian Cyber Security Centre (ACSC) Essential 8
  {
    id: 'acsc-application-control',
    name: 'ACSC Essential 8: Application Control',
    description: 'Detects missing application control measures',
    category: 'ACSC Essential 8 - Application Control',
    severity: 'high',
    pattern: /(?:application|software|executable).*(?:install|run|execute)(?!.*(?:whitelist|approved|signed|verified))/gi,
    recommendation: 'Implement application whitelisting and control measures.',
    enabled: true
  },
  {
    id: 'acsc-patch-applications',
    name: 'ACSC Essential 8: Patch Applications',
    description: 'Detects unpatched applications',
    category: 'ACSC Essential 8 - Patch Management',
    severity: 'high',
    pattern: /(?:application|software|library|dependency)(?!.*(?:patch|update|current|latest|vulnerability.*scan))/gi,
    recommendation: 'Maintain current patches for all applications and dependencies.',
    enabled: true
  },
  {
    id: 'acsc-macro-settings',
    name: 'ACSC Essential 8: Configure Microsoft Office Macro Settings',
    description: 'Detects insecure macro configurations',
    category: 'ACSC Essential 8 - Macro Security',
    severity: 'medium',
    pattern: /(?:macro|vba|office|excel|word)(?!.*(?:disable|block|restrict|security))/gi,
    recommendation: 'Configure secure macro settings to prevent malicious code execution.',
    enabled: true
  },
  {
    id: 'acsc-user-application-hardening',
    name: 'ACSC Essential 8: User Application Hardening',
    description: 'Detects inadequate application hardening',
    category: 'ACSC Essential 8 - Application Hardening',
    severity: 'medium',
    pattern: /(?:browser|application|client)(?!.*(?:harden|secure|config|restrict|sandbox))/gi,
    recommendation: 'Implement application hardening measures for user applications.',
    enabled: true
  },
  {
    id: 'acsc-admin-privileges',
    name: 'ACSC Essential 8: Restrict Administrative Privileges',
    description: 'Detects unrestricted administrative privileges',
    category: 'ACSC Essential 8 - Privilege Restriction',
    severity: 'critical',
    pattern: /(?:admin|administrator|root|superuser).*(?:privilege|access|right)(?!.*(?:restrict|limit|just.*in.*time|temporary))/gi,
    recommendation: 'Restrict and control administrative privileges with just-in-time access.',
    enabled: true
  },
  {
    id: 'acsc-patch-os',
    name: 'ACSC Essential 8: Patch Operating Systems',
    description: 'Detects unpatched operating systems',
    category: 'ACSC Essential 8 - OS Patching',
    severity: 'critical',
    pattern: /(?:operating.*system|os|kernel|windows|linux)(?!.*(?:patch|update|current|latest|security.*update))/gi,
    recommendation: 'Maintain current patches for all operating systems.',
    enabled: true
  },
  {
    id: 'acsc-multi-factor-auth',
    name: 'ACSC Essential 8: Multi-factor Authentication',
    description: 'Detects missing multi-factor authentication',
    category: 'ACSC Essential 8 - Multi-factor Authentication',
    severity: 'critical',
    pattern: /(?:authenticate|login|access)(?!.*(?:multi.*factor|mfa|2fa|two.*factor|otp|token))/gi,
    recommendation: 'Implement multi-factor authentication for all user accounts.',
    enabled: true
  },
  {
    id: 'acsc-daily-backups',
    name: 'ACSC Essential 8: Daily Backups',
    description: 'Detects missing backup procedures',
    category: 'ACSC Essential 8 - Backup',
    severity: 'high',
    pattern: /(?:backup|restore|recovery)(?!.*(?:daily|regular|schedule|automated|tested))/gi,
    recommendation: 'Implement daily automated backups with regular restore testing.',
    enabled: true
  },

  // BSI (German Federal Office for Information Security) IT-Grundschutz
  {
    id: 'bsi-information-security-management',
    name: 'BSI: Information Security Management',
    description: 'Detects missing information security management',
    category: 'BSI IT-Grundschutz - Security Management',
    severity: 'medium',
    pattern: /(?:security|information.*security)(?!.*(?:management|policy|governance|strategy))/gi,
    recommendation: 'Implement comprehensive information security management system.',
    enabled: true
  },
  {
    id: 'bsi-organization-security',
    name: 'BSI: Organization of Information Security',
    description: 'Detects inadequate security organization',
    category: 'BSI IT-Grundschutz - Organization',
    severity: 'medium',
    pattern: /(?:security.*officer|ciso|security.*team|security.*role)(?!.*(?:defined|appointed|responsible|accountable))/gi,
    recommendation: 'Define clear security roles and responsibilities in organization.',
    enabled: true
  },
  {
    id: 'bsi-personnel-security',
    name: 'BSI: Personnel Security',
    description: 'Detects inadequate personnel security measures',
    category: 'BSI IT-Grundschutz - Personnel Security',
    severity: 'medium',
    pattern: /(?:employee|staff|personnel|user)(?!.*(?:training|awareness|background.*check|security.*clearance))/gi,
    recommendation: 'Implement personnel security measures including training and background checks.',
    enabled: true
  },
  {
    id: 'bsi-physical-environmental',
    name: 'BSI: Physical and Environmental Security',
    description: 'Detects inadequate physical security measures',
    category: 'BSI IT-Grundschutz - Physical Security',
    severity: 'medium',
    pattern: /(?:physical|facility|datacenter|server.*room)(?!.*(?:secure|protected|access.*control|monitor))/gi,
    recommendation: 'Implement physical and environmental security controls.',
    enabled: true
  },

  // COBIT 2019 Framework (Additional Controls)
  {
    id: 'cobit-align-plan-organize',
    name: 'COBIT: Align, Plan and Organize',
    description: 'Detects missing alignment and planning processes',
    category: 'COBIT 2019 - APO Domain',
    severity: 'medium',
    pattern: /(?:strategy|plan|organize|governance)(?!.*(?:align|business|objective|stakeholder))/gi,
    recommendation: 'Align IT strategy with business objectives and stakeholder needs.',
    enabled: true
  },
  {
    id: 'cobit-build-acquire-implement',
    name: 'COBIT: Build, Acquire and Implement',
    description: 'Detects inadequate build and implementation processes',
    category: 'COBIT 2019 - BAI Domain',
    severity: 'medium',
    pattern: /(?:build|acquire|implement|develop)(?!.*(?:secure|control|test|validate|approve))/gi,
    recommendation: 'Implement secure development and implementation processes.',
    enabled: true
  },
  {
    id: 'cobit-deliver-service-support',
    name: 'COBIT: Deliver, Service and Support',
    description: 'Detects inadequate service delivery and support',
    category: 'COBIT 2019 - DSS Domain',
    severity: 'medium',
    pattern: /(?:deliver|service|support|operation)(?!.*(?:secure|available|reliable|perform))/gi,
    recommendation: 'Ensure secure and reliable service delivery and support.',
    enabled: true
  },
  {
    id: 'cobit-monitor-evaluate-assess',
    name: 'COBIT: Monitor, Evaluate and Assess',
    description: 'Detects inadequate monitoring and evaluation',
    category: 'COBIT 2019 - MEA Domain',
    severity: 'medium',
    pattern: /(?:monitor|evaluate|assess|measure)(?!.*(?:performance|compliance|risk|control))/gi,
    recommendation: 'Implement comprehensive monitoring and evaluation processes.',
    enabled: true
  },

  // Additional Specialized Security Frameworks
  {
    id: 'mitre-attack-initial-access',
    name: 'MITRE ATT&CK: Initial Access',
    description: 'Detects initial access attack vectors',
    category: 'MITRE ATT&CK - Initial Access',
    severity: 'high',
    pattern: /(?:phishing|spearphishing|watering.*hole|drive.*by|exploit.*public)(?!.*(?:detect|prevent|block|filter))/gi,
    recommendation: 'Implement controls to detect and prevent initial access attacks.',
    enabled: true
  },
  {
    id: 'mitre-attack-persistence',
    name: 'MITRE ATT&CK: Persistence',
    description: 'Detects persistence mechanisms',
    category: 'MITRE ATT&CK - Persistence',
    severity: 'high',
    pattern: /(?:registry|scheduled.*task|service|startup|bootkit)(?!.*(?:monitor|detect|prevent|whitelist))/gi,
    recommendation: 'Monitor and control persistence mechanisms to prevent unauthorized access.',
    enabled: true
  },
  {
    id: 'mitre-attack-privilege-escalation',
    name: 'MITRE ATT&CK: Privilege Escalation',
    description: 'Detects privilege escalation techniques',
    category: 'MITRE ATT&CK - Privilege Escalation',
    severity: 'critical',
    pattern: /(?:escalate|elevate|privilege).*(?:exploit|vulnerability|weakness)(?!.*(?:prevent|patch|mitigate|control))/gi,
    recommendation: 'Implement controls to prevent privilege escalation attacks.',
    enabled: true
  },
  {
    id: 'mitre-attack-defense-evasion',
    name: 'MITRE ATT&CK: Defense Evasion',
    description: 'Detects defense evasion techniques',
    category: 'MITRE ATT&CK - Defense Evasion',
    severity: 'high',
    pattern: /(?:obfuscat|encode|pack|steganograph|masquerad)(?!.*(?:detect|decode|analyze|investigate))/gi,
    recommendation: 'Implement advanced detection capabilities for evasion techniques.',
    enabled: true
  },
  {
    id: 'mitre-attack-credential-access',
    name: 'MITRE ATT&CK: Credential Access',
    description: 'Detects credential access techniques',
    category: 'MITRE ATT&CK - Credential Access',
    severity: 'critical',
    pattern: /(?:credential|password|hash|kerberos|ticket).*(?:dump|extract|steal|crack)(?!.*(?:protect|encrypt|secure|detect))/gi,
    recommendation: 'Protect credentials and implement detection for credential theft.',
    enabled: true
  },
  {
    id: 'mitre-attack-discovery',
    name: 'MITRE ATT&CK: Discovery',
    description: 'Detects discovery and reconnaissance techniques',
    category: 'MITRE ATT&CK - Discovery',
    severity: 'medium',
    pattern: /(?:enumerate|discover|reconnaissance|scan|probe)(?!.*(?:detect|monitor|log|alert))/gi,
    recommendation: 'Monitor and detect reconnaissance activities in the environment.',
    enabled: true
  },
  {
    id: 'mitre-attack-lateral-movement',
    name: 'MITRE ATT&CK: Lateral Movement',
    description: 'Detects lateral movement techniques',
    category: 'MITRE ATT&CK - Lateral Movement',
    severity: 'high',
    pattern: /(?:lateral.*movement|pivot|remote.*access|psexec|wmi)(?!.*(?:detect|segment|isolate|monitor))/gi,
    recommendation: 'Implement network segmentation and monitoring for lateral movement.',
    enabled: true
  },
  {
    id: 'mitre-attack-collection',
    name: 'MITRE ATT&CK: Collection',
    description: 'Detects data collection techniques',
    category: 'MITRE ATT&CK - Collection',
    severity: 'high',
    pattern: /(?:collect|gather|harvest).*(?:data|information|file|email|credential)(?!.*(?:monitor|detect|prevent|dlp))/gi,
    recommendation: 'Implement data loss prevention and monitoring for data collection.',
    enabled: true
  },
  {
    id: 'mitre-attack-exfiltration',
    name: 'MITRE ATT&CK: Exfiltration',
    description: 'Detects data exfiltration techniques',
    category: 'MITRE ATT&CK - Exfiltration',
    severity: 'critical',
    pattern: /(?:exfiltrat|steal|transfer|upload).*(?:data|file|information)(?!.*(?:detect|prevent|block|monitor))/gi,
    recommendation: 'Implement data exfiltration detection and prevention controls.',
    enabled: true
  },
  {
    id: 'mitre-attack-impact',
    name: 'MITRE ATT&CK: Impact',
    description: 'Detects impact and destruction techniques',
    category: 'MITRE ATT&CK - Impact',
    severity: 'critical',
    pattern: /(?:destroy|delete|corrupt|encrypt|ransom|wipe).*(?:data|file|system|disk)(?!.*(?:backup|recover|protect|prevent))/gi,
    recommendation: 'Implement backup and recovery procedures to mitigate impact attacks.',
    enabled: true
  }
];

export function getRuleById(ruleId: string): OwaspRule | undefined {
  return OWASP_RULES.find(rule => rule.id === ruleId);
}

export function getRulesByCategory(category: string): OwaspRule[] {
  return OWASP_RULES.filter(rule => rule.category.includes(category));
}

export function getEnabledRules(): OwaspRule[] {
  return OWASP_RULES.filter(rule => rule.enabled);
}

export function getRulesBySeverity(severity: string): OwaspRule[] {
  return OWASP_RULES.filter(rule => rule.severity === severity);
}

export function getCategorySummary() {
  const categories = new Map<string, { name: string; count: number }>();
  
  OWASP_RULES.forEach(rule => {
    const categoryKey = rule.category.split(' - ')[0];
    const categoryName = rule.category.split(' - ')[1] || rule.category;
    
    if (categories.has(categoryKey)) {
      categories.get(categoryKey)!.count++;
    } else {
      categories.set(categoryKey, { name: categoryName, count: 1 });
    }
  });
  
  return Array.from(categories.entries()).map(([key, value]) => ({
    category: key,
    name: value.name,
    count: value.count
  }));
}
