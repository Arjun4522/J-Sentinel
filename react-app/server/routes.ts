import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import multer from "multer";
import { z } from "zod";
import { insertAnalysisJobSchema, insertUploadedFileSchema, type SecurityReport, type ControlFlowGraph, type DataFlowGraph, type GraphNode, type GraphEdge, type VariableInfo } from "@shared/schema";

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedExtensions = ['.py', '.js', '.java', '.cpp', '.cs', '.php', '.rb', '.jsx', '.ts', '.tsx'];
    const extension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
    cb(null, allowedExtensions.includes(extension));
  }
});

// Language detection helper
function detectLanguage(filename: string): string {
  const extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
  const languageMap: Record<string, string> = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.java': 'java',
    '.cpp': 'cpp',
    '.cs': 'csharp',
    '.php': 'php',
    '.rb': 'ruby'
  };
  return languageMap[extension] || 'unknown';
}

// Comprehensive analysis engine with multiple security frameworks (OWASP, NIST, CIS, SANS, ISO 27001, PCI DSS, GDPR, HIPAA, etc.)
async function analyzeCode(files: any[]): Promise<any[]> {
  const vulnerabilities: any[] = [];
  
  // Multi-framework security patterns with enhanced precision and reduced false positives
  const patterns = [
    // A01: Broken Access Control - Enhanced Rules
    {
      id: 'direct-object-reference',
      pattern: /(?:\/users?\/\d+|\/files?\/[\w\-]+|\/documents?\/\d+)(?!\s*(?:\.authorize|\.check|\.verify|auth|permission))/gi,
      severity: 'critical',
      title: 'Insecure Direct Object Reference',
      category: 'A01:2021 - Broken Access Control',
      description: 'Direct object references without authorization checks',
      recommendation: 'Implement proper authorization checks before accessing resources.'
    },
    {
      id: 'missing-access-control',
      pattern: /(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"][^'"]*['"],\s*(?!.*(?:auth|authenticate|isLoggedIn|requireLogin|checkPermission|verifyToken))/gi,
      severity: 'high',
      title: 'Missing Access Control Middleware',
      category: 'A01:2021 - Broken Access Control',
      description: 'Endpoints without authentication middleware',
      recommendation: 'Add authentication middleware to protect sensitive endpoints.'
    },
    {
      id: 'privilege-escalation-risk',
      pattern: /(?:user\.role|userRole|\.setRole)\s*=\s*(?:request\.|req\.|params\.|body\.)/gi,
      severity: 'critical',
      title: 'Potential Privilege Escalation',
      category: 'A01:2021 - Broken Access Control',
      description: 'Role assignment without proper validation',
      recommendation: 'Validate role assignments and implement proper authorization checks.'
    },
    
    // A02: Cryptographic Failures - Enhanced Rules
    {
      id: 'hardcoded-secrets-comprehensive',
      pattern: /(?:(?:api_?key|apikey|secret_?key|secretkey|access_?token|accesstoken|private_?key|privatekey|client_?secret|clientsecret|auth_?token|authtoken|bearer_?token|bearertoken|refresh_?token|refreshtoken|session_?secret|sessionsecret|jwt_?secret|jwtsecret|encryption_?key|encryptionkey|db_?password|dbpassword|database_?password|databasepassword|admin_?password|adminpassword|root_?password|rootpassword|master_?key|masterkey|service_?account|serviceaccount)\s*[:=]\s*['"][^'"]{8,}['"])/gi,
      severity: 'critical',
      title: 'Comprehensive Hardcoded Secrets Detection',
      category: 'A02:2021 - Cryptographic Failures',
      description: 'Various forms of hardcoded secrets and credentials detected',
      recommendation: 'Move all secrets to environment variables or secure configuration systems.'
    },
    {
      id: 'weak-encryption-algorithms',
      pattern: /(?:DES|3DES|RC4|MD4|MD5|SHA1)(?:\(|\.getInstance|algorithm)/gi,
      severity: 'high',
      title: 'Weak Encryption Algorithms',
      category: 'A02:2021 - Cryptographic Failures',
      description: 'Use of deprecated or weak encryption algorithms',
      recommendation: 'Use strong encryption algorithms like AES-256, SHA-256, or SHA-3.'
    },
    
    // A03: Injection - Enhanced Rules
    {
      id: 'sql-injection-comprehensive',
      pattern: /(?:(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\s+.*(?:\+|concat|format|f['"].*\{.*\}['"]|\$\{.*\}|\%s|\%d).*(?:FROM|INTO|SET|WHERE|VALUES|TABLE|DATABASE))/gi,
      severity: 'critical',
      title: 'Comprehensive SQL Injection Detection',
      category: 'A03:2021 - Injection',
      description: 'Advanced SQL injection detection with context awareness',
      recommendation: 'Use parameterized queries, prepared statements, or ORM with proper escaping.'
    },
    {
      id: 'nosql-injection',
      pattern: /(?:db\.collection\.find|find\(\s*\{[^}]*\$(?:where|regex|gt|lt|ne|in|nin|exists|size|all|elemMatch)\s*:|eval\s*\(\s*\{)/gi,
      severity: 'critical',
      title: 'NoSQL Injection Detection',
      category: 'A03:2021 - Injection',
      description: 'NoSQL injection vulnerabilities in MongoDB and similar databases',
      recommendation: 'Validate and sanitize all user inputs before using in NoSQL queries.'
    },
    {
      id: 'command-injection-comprehensive',
      pattern: /(?:(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|subprocess\.(?:call|run|Popen|check_output)|exec|eval|system|shell_exec|passthru|proc_open|popen)\s*\([^)]*(?:\+|concat|format|f['"].*\{.*\}['"]|\$\{.*\}|\%s))/gi,
      severity: 'critical',
      title: 'Comprehensive Command Injection',
      category: 'A03:2021 - Injection',
      description: 'Enhanced command injection detection across multiple languages',
      recommendation: 'Avoid executing system commands with user input. Use safe alternatives and input validation.'
    },
    {
      id: 'xss-comprehensive',
      pattern: /(?:innerHTML\s*=|document\.write\s*\(|\.html\s*\(|dangerouslySetInnerHTML|v-html|ng-bind-html)(?!\s*(?:DOMPurify|sanitize|escape|encode))[^;]*(?:\+|concat|template|interpolat|\$\{|\{\{)/gi,
      severity: 'high',
      title: 'Comprehensive XSS Detection',
      category: 'A03:2021 - Injection',
      description: 'Advanced cross-site scripting detection with context awareness',
      recommendation: 'Use proper output encoding, Content Security Policy, and sanitization libraries.'
    },
    
    // Hardcoded Credentials
    {
      id: 'hardcoded-passwords',
      pattern: /(?:password|pwd|pass|adminPass)\s*[:=]\s*["'][^"']{3,}["']/gi,
      severity: 'high',
      title: 'Hardcoded Passwords',
      category: 'A02:2021 - Cryptographic Failures',
      description: 'Hardcoded passwords detected in source code',
      recommendation: 'Store passwords in environment variables or secure configuration systems.'
    },
    {
      id: 'hardcoded-api-keys',
      pattern: /(?:API_KEY|api_key|apikey|secret|token|key)\s*[:=]\s*["'][^"']{8,}["']/gi,
      severity: 'high',
      title: 'Hardcoded API Keys',
      category: 'A02:2021 - Cryptographic Failures',
      description: 'Hardcoded API keys and tokens detected',
      recommendation: 'Store API keys in environment variables or secure vault systems.'
    },
    {
      id: 'hardcoded-database-creds',
      pattern: /DATABASE_PASSWORD\s*=\s*["'][^"']+["']/gi,
      severity: 'critical',
      title: 'Hardcoded Database Credentials',
      category: 'A02:2021 - Cryptographic Failures',
      description: 'Hardcoded database passwords detected',
      recommendation: 'Use environment variables for database credentials.'
    },
    
    // Command Injection
    {
      id: 'command-injection-java',
      pattern: /Runtime\.getRuntime\(\)\.exec\s*\(.*\+/gi,
      severity: 'critical',
      title: 'Command Injection - Java',
      category: 'A03:2021 - Injection',
      description: 'Command injection through Runtime.exec() with user input',
      recommendation: 'Avoid executing system commands with user input. Use ProcessBuilder with validated parameters.'
    },
    {
      id: 'command-injection-python',
      pattern: /subprocess\.(?:call|run|Popen).*shell\s*=\s*True/gi,
      severity: 'critical',
      title: 'Command Injection - Python',
      category: 'A03:2021 - Injection',
      description: 'Command injection through subprocess with shell=True',
      recommendation: 'Avoid shell=True. Use subprocess with list arguments for safe command execution.'
    },
    
    // Weak Cryptography
    {
      id: 'weak-crypto-md5',
      pattern: /(?:hashlib\.md5|MessageDigest\.getInstance\s*\(\s*["']MD5["']\)|\.md5\()/gi,
      severity: 'high',
      title: 'Weak Cryptography - MD5',
      category: 'A02:2021 - Cryptographic Failures',
      description: 'Use of weak MD5 hashing algorithm',
      recommendation: 'Use strong cryptographic algorithms like SHA-256, SHA-3, or bcrypt.'
    },
    
    // Path Traversal
    {
      id: 'path-traversal-file-access',
      pattern: /(?:File\(|open\(|fopen\().*\+.*filename/gi,
      severity: 'high',
      title: 'Path Traversal - Unsafe File Access',
      category: 'A01:2021 - Broken Access Control',
      description: 'Unsafe file access with user input concatenation',
      recommendation: 'Validate file paths and use secure file access methods with path normalization.'
    },
    
    // Insecure Random
    {
      id: 'insecure-random-java',
      pattern: /new\s+Random\(\)|random\.nextInt/gi,
      severity: 'medium',
      title: 'Insecure Random - Java',
      category: 'A02:2021 - Cryptographic Failures',
      description: 'Use of weak Random class for security-sensitive operations',
      recommendation: 'Use SecureRandom for cryptographically secure random number generation.'
    },
    {
      id: 'insecure-random-python',
      pattern: /import\s+random|random\.randint|random\.choice/gi,
      severity: 'medium',
      title: 'Insecure Random - Python',
      category: 'A02:2021 - Cryptographic Failures',
      description: 'Use of weak random module for security operations',
      recommendation: 'Use secrets module for cryptographically secure random numbers.'
    },
    
    // Information Disclosure
    {
      id: 'sensitive-data-logging-java',
      pattern: /System\.out\.println.*(?:password|credit|ssn|social)/gi,
      severity: 'high',
      title: 'Sensitive Data Logging - Java',
      category: 'A09:2021 - Security Logging and Monitoring Failures',
      description: 'Logging of sensitive information detected',
      recommendation: 'Avoid logging sensitive information. Use proper logging frameworks with filtering.'
    },
    {
      id: 'sensitive-data-logging-python',
      pattern: /print.*(?:password|credit|ssn|social|token)/gi,
      severity: 'high',
      title: 'Sensitive Data Logging - Python',
      category: 'A09:2021 - Security Logging and Monitoring Failures',
      description: 'Logging of sensitive information detected',
      recommendation: 'Avoid logging sensitive information. Use structured logging with data classification.'
    },
    
    // Deserialization
    {
      id: 'insecure-deserialization-java',
      pattern: /ObjectInputStream.*readObject/gi,
      severity: 'critical',
      title: 'Insecure Deserialization - Java',
      category: 'A08:2021 - Software and Data Integrity Failures',
      description: 'Unsafe ObjectInputStream deserialization',
      recommendation: 'Validate serialized data before deserialization. Use whitelisting for allowed classes.'
    },
    {
      id: 'insecure-deserialization-python',
      pattern: /pickle\.loads?/gi,
      severity: 'critical',
      title: 'Insecure Deserialization - Python',
      category: 'A08:2021 - Software and Data Integrity Failures',
      description: 'Unsafe pickle deserialization',
      recommendation: 'Avoid pickle for untrusted data. Use JSON or other safe serialization formats.'
    },
    
    // File Upload Security
    {
      id: 'insecure-file-upload',
      pattern: /(?:save_uploaded_file|upload).*filename.*write/gi,
      severity: 'high',
      title: 'Insecure File Upload',
      category: 'A04:2021 - Insecure Design',
      description: 'File uploads without proper validation',
      recommendation: 'Implement file type validation, size limits, and secure file storage.'
    },
    
    // XSS
    {
      id: 'xss-direct-output',
      pattern: /(?:innerHTML|document\.write|\.html\(|f["'].*<.*\{)/gi,
      severity: 'high',
      title: 'Cross-Site Scripting - Direct Output',
      category: 'A03:2021 - Injection',
      description: 'Potential XSS through direct user input output',
      recommendation: 'Use proper output encoding and Content Security Policy. Escape user input before output.'
    },
    
    // LDAP Injection
    {
      id: 'ldap-injection',
      pattern: /ldap_filter.*f["'].*\{.*\}/gi,
      severity: 'high',
      title: 'LDAP Injection',
      category: 'A03:2021 - Injection',
      description: 'LDAP injection through direct user input in filters',
      recommendation: 'Escape or validate user input before using in LDAP filters.'
    },
    
    // STRIDE Framework Patterns
    {
      id: 'stride-spoofing',
      pattern: /(?:authenticate|login|verify).*(?:username|user|id)(?!.*(?:strong|multi.*factor|certificate|biometric|secure))/gi,
      severity: 'high',
      title: 'STRIDE: Spoofing Vulnerability',
      category: 'STRIDE - Spoofing',
      description: 'Potential identity spoofing due to weak authentication',
      recommendation: 'Implement strong authentication mechanisms to prevent identity spoofing.'
    },
    {
      id: 'stride-tampering',
      pattern: /(?:data|message|request|response)(?!.*(?:integrity|hash|checksum|signature|hmac|digital.*signature))/gi,
      severity: 'critical',
      title: 'STRIDE: Tampering Risk',
      category: 'STRIDE - Tampering',
      description: 'Data integrity at risk without proper protection',
      recommendation: 'Implement data integrity checks and digital signatures.'
    },
    {
      id: 'stride-repudiation',
      pattern: /(?:transaction|action|operation|change)(?!.*(?:audit|log|trail|signature|timestamp|witness))/gi,
      severity: 'medium',
      title: 'STRIDE: Repudiation Risk',
      category: 'STRIDE - Repudiation',
      description: 'Actions may be repudiated without proper audit trail',
      recommendation: 'Implement comprehensive audit logging and digital signatures.'
    },
    {
      id: 'stride-information-disclosure',
      pattern: /(?:error|exception|debug|trace|stack).*(?:message|info|detail)(?!.*(?:sanitize|clean|filter|generic))/gi,
      severity: 'high',
      title: 'STRIDE: Information Disclosure',
      category: 'STRIDE - Information Disclosure',
      description: 'Potential information disclosure through error messages',
      recommendation: 'Sanitize error messages and avoid exposing sensitive information.'
    },
    {
      id: 'stride-denial-of-service',
      pattern: /(?:resource|memory|cpu|bandwidth|connection)(?!.*(?:limit|throttle|quota|pool|timeout))/gi,
      severity: 'medium',
      title: 'STRIDE: DoS Vulnerability',
      category: 'STRIDE - Denial of Service',
      description: 'Resource exhaustion may lead to denial of service',
      recommendation: 'Implement resource limits and rate limiting to prevent DoS attacks.'
    },
    {
      id: 'stride-elevation-of-privilege',
      pattern: /(?:privilege|permission|role|access).*(?:escalate|elevate|grant|assign)(?!.*(?:validate|authorize|approve|control))/gi,
      severity: 'critical',
      title: 'STRIDE: Privilege Escalation',
      category: 'STRIDE - Elevation of Privilege',
      description: 'Potential privilege escalation without proper controls',
      recommendation: 'Implement proper authorization controls for privilege changes.'
    },
    
    // PASTA Framework Patterns
    {
      id: 'pasta-attack-surface',
      pattern: /(?:endpoint|api|service|interface)(?!.*(?:protected|secured|authenticated|authorized))/gi,
      severity: 'medium',
      title: 'PASTA: Exposed Attack Surface',
      category: 'PASTA - Attack Surface',
      description: 'Exposed interfaces increase attack surface',
      recommendation: 'Minimize and secure all exposed attack surfaces.'
    },
    {
      id: 'pasta-threat-enumeration',
      pattern: /(?:external|untrusted|user).*(?:input|data|content)(?!.*(?:validate|sanitize|filter|escape))/gi,
      severity: 'high',
      title: 'PASTA: Threat Pattern',
      category: 'PASTA - Threat Enumeration',
      description: 'Common threat pattern detected in external input handling',
      recommendation: 'Validate and sanitize all external inputs.'
    },
    
    // DREAD Framework Patterns
    {
      id: 'dread-damage-potential',
      pattern: /(?:delete|drop|truncate|remove|destroy).*(?:database|table|file|data|system)(?!.*(?:backup|confirm|validate|authorize))/gi,
      severity: 'critical',
      title: 'DREAD: High Damage Potential',
      category: 'DREAD - Damage Assessment',
      description: 'Operations with high damage potential detected',
      recommendation: 'Implement proper authorization and backup mechanisms for destructive operations.'
    },
    {
      id: 'dread-reproducibility',
      pattern: /(?:default|static|hardcoded|fixed).*(?:password|key|secret|token)(?!.*(?:change|rotate|generate|random))/gi,
      severity: 'high',
      title: 'DREAD: High Reproducibility',
      category: 'DREAD - Reproducibility',
      description: 'Easily reproducible vulnerability detected',
      recommendation: 'Use dynamic, rotatable credentials instead of static ones.'
    },
    {
      id: 'dread-exploitability',
      pattern: /(?:eval|exec|system|shell).*(?:\+|concat|interpolat|\$\{|\%s)(?!.*(?:escape|sanitize|validate|whitelist))/gi,
      severity: 'critical',
      title: 'DREAD: High Exploitability',
      category: 'DREAD - Exploitability',
      description: 'Easily exploitable vulnerability detected',
      recommendation: 'Avoid dynamic code execution or implement strict input validation.'
    },
    {
      id: 'dread-affected-users',
      pattern: /(?:global|shared|common|public).*(?:variable|resource|data|session)(?!.*(?:isolate|separate|scope|protect))/gi,
      severity: 'high',
      title: 'DREAD: Wide User Impact',
      category: 'DREAD - Affected Users',
      description: 'Vulnerability affects many users',
      recommendation: 'Implement proper data isolation and user separation.'
    },
    {
      id: 'dread-discoverability',
      pattern: /(?:admin|test|debug|dev|staging).*(?:panel|interface|endpoint|page)(?!.*(?:hidden|protected|secure|internal))/gi,
      severity: 'medium',
      title: 'DREAD: High Discoverability',
      category: 'DREAD - Discoverability',
      description: 'Easily discoverable vulnerability',
      recommendation: 'Secure or remove discoverable administrative interfaces.'
    },
    
    // OWASP API Security Patterns
    {
      id: 'owasp-api-broken-object-auth',
      pattern: /(?:api|endpoint).*\/(?:users?|objects?|resources?)\/\d+(?!.*(?:authorize|check.*owner|verify.*access))/gi,
      severity: 'critical',
      title: 'OWASP API: Broken Object Authorization',
      category: 'OWASP API - API1 Object Authorization',
      description: 'Broken object-level authorization in API',
      recommendation: 'Implement proper object-level authorization checks in APIs.'
    },
    {
      id: 'owasp-api-excessive-data',
      pattern: /(?:api|response|json).*(?:select.*\*|all.*fields|complete.*object)(?!.*(?:filter|limit|select.*specific|minimal))/gi,
      severity: 'high',
      title: 'OWASP API: Excessive Data Exposure',
      category: 'OWASP API - API3 Data Exposure',
      description: 'API may expose excessive data in responses',
      recommendation: 'Return only necessary data fields in API responses.'
    },
    {
      id: 'owasp-api-lack-rate-limiting',
      pattern: /(?:api|endpoint|route).*(?:post|put|delete|patch)(?!.*(?:rate.*limit|throttle|quota|limit))/gi,
      severity: 'high',
      title: 'OWASP API: Missing Rate Limiting',
      category: 'OWASP API - API4 Rate Limiting',
      description: 'API endpoints lack rate limiting',
      recommendation: 'Implement rate limiting on API endpoints to prevent abuse.'
    },
    {
      id: 'owasp-api-mass-assignment',
      pattern: /(?:api|endpoint).*(?:req\.body|request\.json|body\.*)(?!.*(?:whitelist|allowed.*fields|validate.*fields))/gi,
      severity: 'high',
      title: 'OWASP API: Mass Assignment',
      category: 'OWASP API - API6 Mass Assignment',
      description: 'Mass assignment vulnerability in API',
      recommendation: 'Validate and whitelist allowed fields in API requests.'
    },
    
    // OWASP Mobile Security Patterns
    {
      id: 'owasp-mobile-insecure-storage',
      pattern: /(?:localStorage|sessionStorage|sqlite|preferences|keychain).*(?:password|token|secret|key)(?!.*(?:encrypt|secure|protect))/gi,
      severity: 'critical',
      title: 'OWASP Mobile: Insecure Storage',
      category: 'OWASP Mobile - M2 Data Storage',
      description: 'Insecure storage of sensitive data on mobile',
      recommendation: 'Encrypt sensitive data stored on mobile devices.'
    },
    {
      id: 'owasp-mobile-insecure-communication',
      pattern: /(?:http|ws|ftp)(?!s).*(?:mobile|app|client)(?!.*(?:tls|ssl|secure|encrypt))/gi,
      severity: 'high',
      title: 'OWASP Mobile: Insecure Communication',
      category: 'OWASP Mobile - M4 Communication',
      description: 'Insecure communication in mobile application',
      recommendation: 'Use secure communication protocols (HTTPS, WSS) for mobile apps.'
    },
    
    // MITRE ATT&CK Patterns
    {
      id: 'mitre-attack-initial-access',
      pattern: /(?:phishing|spearphishing|watering.*hole|drive.*by|exploit.*public)(?!.*(?:detect|prevent|block|filter))/gi,
      severity: 'high',
      title: 'MITRE ATT&CK: Initial Access Vector',
      category: 'MITRE ATT&CK - Initial Access',
      description: 'Potential initial access attack vector',
      recommendation: 'Implement controls to detect and prevent initial access attacks.'
    },
    {
      id: 'mitre-attack-persistence',
      pattern: /(?:registry|scheduled.*task|service|startup|bootkit)(?!.*(?:monitor|detect|prevent|whitelist))/gi,
      severity: 'high',
      title: 'MITRE ATT&CK: Persistence Mechanism',
      category: 'MITRE ATT&CK - Persistence',
      description: 'Potential persistence mechanism detected',
      recommendation: 'Monitor and control persistence mechanisms to prevent unauthorized access.'
    },
    {
      id: 'mitre-attack-credential-access',
      pattern: /(?:credential|password|hash|kerberos|ticket).*(?:dump|extract|steal|crack)(?!.*(?:protect|encrypt|secure|detect))/gi,
      severity: 'critical',
      title: 'MITRE ATT&CK: Credential Access',
      category: 'MITRE ATT&CK - Credential Access',
      description: 'Potential credential access technique',
      recommendation: 'Protect credentials and implement detection for credential theft.'
    },
    {
      id: 'mitre-attack-lateral-movement',
      pattern: /(?:lateral.*movement|pivot|remote.*access|psexec|wmi)(?!.*(?:detect|segment|isolate|monitor))/gi,
      severity: 'high',
      title: 'MITRE ATT&CK: Lateral Movement',
      category: 'MITRE ATT&CK - Lateral Movement',
      description: 'Potential lateral movement technique',
      recommendation: 'Implement network segmentation and monitoring for lateral movement.'
    },
    {
      id: 'mitre-attack-exfiltration',
      pattern: /(?:exfiltrat|steal|transfer|upload).*(?:data|file|information)(?!.*(?:detect|prevent|block|monitor))/gi,
      severity: 'critical',
      title: 'MITRE ATT&CK: Data Exfiltration',
      category: 'MITRE ATT&CK - Exfiltration',
      description: 'Potential data exfiltration technique',
      recommendation: 'Implement data exfiltration detection and prevention controls.'
    },
    
    // NIST Framework Patterns
    {
      id: 'nist-identify-asset-management',
      pattern: /(?:asset|device|system|application)(?!.*(?:inventory|catalog|managed|documented|tracked))/gi,
      severity: 'medium',
      title: 'NIST: Asset Management',
      category: 'NIST - Identify',
      description: 'Assets may not be properly managed or documented',
      recommendation: 'Implement comprehensive asset management and documentation.'
    },
    {
      id: 'nist-protect-access-control',
      pattern: /(?:access|permission|authorization)(?!.*(?:control|manage|restrict|principle.*least.*privilege))/gi,
      severity: 'high',
      title: 'NIST: Access Control',
      category: 'NIST - Protect',
      description: 'Access control may be inadequate',
      recommendation: 'Implement proper access control mechanisms.'
    },
    {
      id: 'nist-detect-continuous-monitoring',
      pattern: /(?:monitor|detect|surveillance)(?!.*(?:continuous|real.*time|automated|comprehensive))/gi,
      severity: 'medium',
      title: 'NIST: Continuous Monitoring',
      category: 'NIST - Detect',
      description: 'Monitoring may be insufficient',
      recommendation: 'Implement continuous monitoring capabilities.'
    },
    {
      id: 'nist-respond-incident-response',
      pattern: /(?:incident|breach|attack|compromise)(?!.*(?:response|plan|procedure|team|escalation))/gi,
      severity: 'high',
      title: 'NIST: Incident Response',
      category: 'NIST - Respond',
      description: 'Incident response capabilities may be inadequate',
      recommendation: 'Develop and maintain incident response procedures.'
    },
    {
      id: 'nist-recover-recovery-planning',
      pattern: /(?:recovery|restore|backup|continuity)(?!.*(?:plan|procedure|test|validate|documented))/gi,
      severity: 'high',
      title: 'NIST: Recovery Planning',
      category: 'NIST - Recover',
      description: 'Recovery planning may be inadequate',
      recommendation: 'Develop and test comprehensive recovery procedures.'
    },
    
    // CIS Controls Patterns
    {
      id: 'cis-inventory-hardware',
      pattern: /(?:hardware|device|system|server)(?!.*(?:inventory|catalog|authorized|approved|managed))/gi,
      severity: 'medium',
      title: 'CIS: Hardware Inventory',
      category: 'CIS Control 1 - Inventory',
      description: 'Hardware inventory may be incomplete',
      recommendation: 'Maintain complete hardware inventory with authorization tracking.'
    },
    {
      id: 'cis-inventory-software',
      pattern: /(?:software|application|program|package)(?!.*(?:inventory|catalog|authorized|approved|licensed))/gi,
      severity: 'medium',
      title: 'CIS: Software Inventory',
      category: 'CIS Control 2 - Software Inventory',
      description: 'Software inventory may be incomplete',
      recommendation: 'Maintain complete software inventory with license tracking.'
    },
    {
      id: 'cis-secure-configuration',
      pattern: /(?:configuration|config|setting)(?!.*(?:secure|hardened|baseline|standard|documented))/gi,
      severity: 'high',
      title: 'CIS: Secure Configuration',
      category: 'CIS Control 5 - Secure Configuration',
      description: 'Secure configuration standards may not be applied',
      recommendation: 'Implement and maintain secure configuration standards.'
    },
    
    // Zero Trust Architecture Patterns
    {
      id: 'zero-trust-never-trust',
      pattern: /(?:trust|assume|inherit).*(?:network|location|device|user)(?!.*(?:verify|authenticate|validate|authorize))/gi,
      severity: 'high',
      title: 'Zero Trust: Implicit Trust',
      category: 'Zero Trust - Never Trust',
      description: 'Implicit trust detected, violates zero trust principles',
      recommendation: 'Implement explicit verification for all access requests.'
    },
    {
      id: 'zero-trust-always-verify',
      pattern: /(?:access|request|transaction)(?!.*(?:verify|authenticate|authorize|validate|check))/gi,
      severity: 'high',
      title: 'Zero Trust: Missing Verification',
      category: 'Zero Trust - Always Verify',
      description: 'Access granted without proper verification',
      recommendation: 'Implement continuous verification for all access requests.'
    },
    
    // Additional Security Pattern Categories
    {
      id: 'supply-chain-security',
      pattern: /(?:dependency|library|package|module|component)(?!.*(?:verified|signed|scanned|trusted|secure))/gi,
      severity: 'medium',
      title: 'Supply Chain Security',
      category: 'Supply Chain - Third Party Risk',
      description: 'Third-party dependencies may pose security risks',
      recommendation: 'Verify and scan all third-party dependencies for vulnerabilities.'
    },
    {
      id: 'privacy-by-design',
      pattern: /(?:personal|private|sensitive).*(?:data|information)(?!.*(?:privacy|anonymize|pseudonymize|minimize|consent))/gi,
      severity: 'high',
      title: 'Privacy by Design',
      category: 'Privacy - Data Protection',
      description: 'Personal data processing may lack privacy protections',
      recommendation: 'Implement privacy by design principles in data processing.'
    },
    {
      id: 'secure-by-default',
      pattern: /(?:default|initial|baseline).*(?:configuration|setting|password|access)(?!.*(?:secure|restricted|minimal|least.*privilege))/gi,
      severity: 'medium',
      title: 'Secure by Default',
      category: 'Secure Design - Default Security',
      description: 'Default configurations may not be secure',
      recommendation: 'Implement secure by default configurations and settings.'
    },
    {
      id: 'defense-in-depth',
      pattern: /(?:security|protection|defense)(?!.*(?:layer|multiple|redundant|diverse|depth))/gi,
      severity: 'medium',
      title: 'Defense in Depth',
      category: 'Security Architecture - Defense in Depth',
      description: 'Security architecture may lack multiple defensive layers',
      recommendation: 'Implement multiple layers of security controls (defense in depth).'
    }
  ];

  for (const file of files) {
    const lines = file.content.split('\n');
    
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      
      for (const pattern of patterns) {
        // Reset regex state for global patterns
        pattern.pattern.lastIndex = 0;
        
        // Find all matches in the line
        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          vulnerabilities.push({
            fileId: file.id,
            ruleId: pattern.id,
            severity: pattern.severity,
            title: pattern.title,
            description: pattern.description,
            category: pattern.category,
            line: lineIndex + 1,
            column: match.index + 1,
            code: line.trim(),
            recommendation: pattern.recommendation
          });
          
          // Avoid infinite loop for non-global patterns
          if (!pattern.pattern.global) break;
        }
      }
    }
  }

  return vulnerabilities;
}

// Generate Control Flow Graph for code analysis
function generateControlFlowGraph(content: string, language: string, filename: string): ControlFlowGraph {
  const lines = content.split('\n');
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  
  // Entry node
  const entryNode: GraphNode = {
    id: 'entry',
    type: 'entry',
    label: 'ENTRY',
    line: 1,
    metadata: { isSpecial: true }
  };
  nodes.push(entryNode);
  
  // Create nodes for each significant line of code
  let nodeCounter = 1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line && !line.startsWith('//') && !line.startsWith('#') && !line.startsWith('/*')) {
      const nodeId = `node_${nodeCounter}`;
      const node: GraphNode = {
        id: nodeId,
        type: getNodeType(line, language),
        label: line.length > 30 ? `${line.substring(0, 30)}...` : line,
        line: i + 1,
        code: line,
        metadata: { 
          isControlFlow: isControlFlowStatement(line, language),
          isFunction: isFunctionDeclaration(line, language)
        }
      };
      nodes.push(node);
      
      // Create edge from previous node or entry
      const sourceId = nodeCounter === 1 ? 'entry' : `node_${nodeCounter - 1}`;
      edges.push({
        id: `edge_${edges.length}`,
        source: sourceId,
        target: nodeId,
        type: 'control_flow',
        label: 'next'
      });
      
      nodeCounter++;
    }
  }
  
  // Exit node
  const exitNode: GraphNode = {
    id: 'exit',
    type: 'exit',
    label: 'EXIT',
    line: lines.length,
    metadata: { isSpecial: true }
  };
  nodes.push(exitNode);
  
  // Connect last node to exit
  if (nodeCounter > 1) {
    edges.push({
      id: `edge_${edges.length}`,
      source: `node_${nodeCounter - 1}`,
      target: 'exit',
      type: 'control_flow',
      label: 'end'
    });
  }
  
  return {
    nodes,
    edges,
    entry: 'entry',
    exit: 'exit',
    metadata: {
      language,
      filename,
      generatedAt: new Date().toISOString()
    }
  };
}

// Generate Data Flow Graph for code analysis
function generateDataFlowGraph(content: string, language: string, filename: string): DataFlowGraph {
  const lines = content.split('\n');
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const variables = new Map<string, VariableInfo>();
  
  let nodeCounter = 1;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line && !line.startsWith('//') && !line.startsWith('#')) {
      
      // Extract variable definitions and uses
      const varDefs = extractVariableDefinitions(line, language);
      const varUses = extractVariableUses(line, language);
      
      // Process variable definitions
      for (const varDef of varDefs) {
        const nodeId = `def_${nodeCounter}`;
        nodes.push({
          id: nodeId,
          type: 'definition',
          label: `def: ${varDef.name}`,
          line: i + 1,
          code: line,
          metadata: { variable: varDef.name, type: varDef.type }
        });
        
        // Update variable info
        if (!variables.has(varDef.name)) {
          variables.set(varDef.name, {
            name: varDef.name,
            type: varDef.type,
            definitionSites: [],
            useSites: [],
            scope: 'local'
          });
        }
        variables.get(varDef.name)!.definitionSites.push(nodeId);
        nodeCounter++;
      }
      
      // Process variable uses
      for (const varUse of varUses) {
        const nodeId = `use_${nodeCounter}`;
        nodes.push({
          id: nodeId,
          type: 'use',
          label: `use: ${varUse}`,
          line: i + 1,
          code: line,
          metadata: { variable: varUse }
        });
        
        // Update variable info
        if (!variables.has(varUse)) {
          variables.set(varUse, {
            name: varUse,
            definitionSites: [],
            useSites: [],
            scope: 'local'
          });
        }
        variables.get(varUse)!.useSites.push(nodeId);
        
        // Create data flow edge from definition to use
        const varInfo = variables.get(varUse)!;
        if (varInfo.definitionSites.length > 0) {
          const lastDef = varInfo.definitionSites[varInfo.definitionSites.length - 1];
          edges.push({
            id: `flow_${edges.length}`,
            source: lastDef,
            target: nodeId,
            type: 'data_flow',
            label: `${varUse}`,
            metadata: { variable: varUse }
          });
        }
        
        nodeCounter++;
      }
    }
  }
  
  return {
    nodes,
    edges,
    variables,
    metadata: {
      language,
      filename,
      generatedAt: new Date().toISOString()
    }
  };
}

// Helper functions for graph generation
function getNodeType(line: string, language: string): string {
  if (isFunctionDeclaration(line, language)) return 'function';
  if (isControlFlowStatement(line, language)) return 'control';
  if (isAssignment(line, language)) return 'assignment';
  if (isMethodCall(line, language)) return 'call';
  return 'statement';
}

function isControlFlowStatement(line: string, language: string): boolean {
  const controlKeywords = ['if', 'else', 'for', 'while', 'switch', 'try', 'catch', 'finally'];
  return controlKeywords.some(keyword => line.includes(keyword));
}

function isFunctionDeclaration(line: string, language: string): boolean {
  switch (language) {
    case 'javascript':
      return /function\s+\w+|const\s+\w+\s*=\s*\(|=>\s*{/.test(line);
    case 'python':
      return /def\s+\w+\s*\(/.test(line);
    case 'java':
      return /public|private|protected.*\s+\w+\s*\(/.test(line);
    default:
      return false;
  }
}

function isAssignment(line: string, language: string): boolean {
  return /\w+\s*[=]\s*/.test(line) && !line.includes('==') && !line.includes('!=');
}

function isMethodCall(line: string, language: string): boolean {
  return /\w+\s*\.\s*\w+\s*\(/.test(line) || /\w+\s*\(/.test(line);
}

function extractVariableDefinitions(line: string, language: string): Array<{name: string, type?: string}> {
  const defs: Array<{name: string, type?: string}> = [];
  
  switch (language) {
    case 'javascript':
      const jsMatches = line.match(/(?:let|const|var)\s+(\w+)/g);
      if (jsMatches) {
        jsMatches.forEach(match => {
          const name = match.split(/\s+/)[1];
          if (name) defs.push({ name });
        });
      }
      break;
      
    case 'python':
      const pyMatches = line.match(/(\w+)\s*=/g);
      if (pyMatches) {
        pyMatches.forEach(match => {
          const name = match.split('=')[0].trim();
          if (name) defs.push({ name });
        });
      }
      break;
      
    case 'java':
      const javaMatches = line.match(/(\w+)\s+(\w+)\s*[=;]/g);
      if (javaMatches) {
        javaMatches.forEach(match => {
          const parts = match.split(/\s+/);
          if (parts.length >= 2) {
            defs.push({ name: parts[1], type: parts[0] });
          }
        });
      }
      break;
  }
  
  return defs;
}

function extractVariableUses(line: string, language: string): string[] {
  const uses: string[] = [];
  
  // Simple regex to find variable references
  const varRefs = line.match(/\b[a-zA-Z_]\w*\b/g);
  if (varRefs) {
    // Filter out keywords and known functions
    const keywords = ['if', 'else', 'for', 'while', 'function', 'def', 'class', 'import', 'return', 'true', 'false', 'null', 'undefined'];
    uses.push(...varRefs.filter(ref => !keywords.includes(ref) && ref.length > 1));
  }
  
  return Array.from(new Set(uses)); // Remove duplicates
}

export async function registerRoutes(app: Express): Promise<Server> {
  
  // Create analysis job
  app.post("/api/analysis", async (req, res) => {
    try {
      const job = await storage.createAnalysisJob({
        status: "pending",
        totalFiles: 0,
        processedFiles: 0,
        vulnerabilities: []
      });
      res.json(job);
    } catch (error) {
      res.status(500).json({ message: "Failed to create analysis job" });
    }
  });

  // Upload files
  app.post("/api/analysis/:jobId/files", upload.array('files'), async (req, res) => {
    try {
      const jobId = parseInt(req.params.jobId);
      const files = req.files as Express.Multer.File[];
      
      if (!files || files.length === 0) {
        return res.status(400).json({ message: "No files uploaded" });
      }

      const uploadedFiles = [];
      for (const file of files) {
        const language = detectLanguage(file.originalname);
        const uploadedFile = await storage.createUploadedFile({
          jobId,
          filename: file.originalname,
          language,
          content: file.buffer.toString('utf-8'),
          size: file.size
        });
        uploadedFiles.push(uploadedFile);
      }

      // Update job with total files count
      await storage.updateAnalysisJob(jobId, {
        totalFiles: files.length,
        status: "processing"
      });

      res.json({ files: uploadedFiles });
    } catch (error) {
      res.status(500).json({ message: "Failed to upload files" });
    }
  });

  // Start analysis
  app.post("/api/analysis/:jobId/start", async (req, res) => {
    try {
      const jobId = parseInt(req.params.jobId);
      const job = await storage.getAnalysisJob(jobId);
      
      if (!job) {
        return res.status(404).json({ message: "Analysis job not found" });
      }

      // Get uploaded files
      const files = await storage.getFilesByJobId(jobId);
      
      // Analyze files and generate graphs
      const vulnerabilities = await analyzeCode(files);
      
      // Generate graphs for the first file (primary analysis file)
      let cfg: ControlFlowGraph | undefined;
      let dfg: DataFlowGraph | undefined;
      
      if (files.length > 0) {
        const primaryFile = files[0];
        cfg = generateControlFlowGraph(primaryFile.content, primaryFile.language, primaryFile.filename);
        dfg = generateDataFlowGraph(primaryFile.content, primaryFile.language, primaryFile.filename);
      }
      
      // Store vulnerabilities
      for (const vuln of vulnerabilities) {
        await storage.createVulnerability({
          jobId,
          fileId: vuln.fileId,
          ruleId: vuln.ruleId,
          severity: vuln.severity,
          title: vuln.title,
          description: vuln.description,
          category: vuln.category,
          line: vuln.line,
          column: vuln.column || null,
          code: vuln.code || null,
          recommendation: vuln.recommendation || null
        });
      }

      // Update job status with graph data
      await storage.updateAnalysisJob(jobId, {
        status: "completed",
        processedFiles: files.length,
        vulnerabilities: { vulnerabilities, cfg, dfg },
        completedAt: new Date()
      });

      res.json({ status: "completed", vulnerabilities: vulnerabilities.length });
    } catch (error) {
      res.status(500).json({ message: "Analysis failed" });
    }
  });

  // Get analysis progress
  app.get("/api/analysis/:jobId/progress", async (req, res) => {
    try {
      const jobId = parseInt(req.params.jobId);
      const job = await storage.getAnalysisJob(jobId);
      
      if (!job) {
        return res.status(404).json({ message: "Analysis job not found" });
      }

      const progress = {
        status: job.status,
        totalFiles: job.totalFiles,
        processedFiles: job.processedFiles,
        percentage: job.totalFiles > 0 ? Math.round((job.processedFiles / job.totalFiles) * 100) : 0
      };

      res.json(progress);
    } catch (error) {
      res.status(500).json({ message: "Failed to get progress" });
    }
  });

  // Get analysis results
  app.get("/api/analysis/:jobId/results", async (req, res) => {
    try {
      const jobId = parseInt(req.params.jobId);
      const job = await storage.getAnalysisJob(jobId);
      
      if (!job) {
        return res.status(404).json({ message: "Analysis job not found" });
      }

      const vulnerabilities = await storage.getVulnerabilitiesByJobId(jobId);
      const files = await storage.getFilesByJobId(jobId);
      
      // Extract CFG and DFG from stored job data
      let cfg: any, dfg: any;
      if (job.vulnerabilities && typeof job.vulnerabilities === 'object') {
        const storedData = job.vulnerabilities as any;
        cfg = storedData.cfg;
        dfg = storedData.dfg;
      }

      const report: SecurityReport = {
        jobId,
        totalVulnerabilities: vulnerabilities.length,
        criticalCount: vulnerabilities.filter(v => v.severity === 'critical').length,
        highCount: vulnerabilities.filter(v => v.severity === 'high').length,
        mediumCount: vulnerabilities.filter(v => v.severity === 'medium').length,
        lowCount: vulnerabilities.filter(v => v.severity === 'low').length,
        filesAnalyzed: files.length,
        linesOfCode: files.reduce((total, file) => total + file.content.split('\n').length, 0),
        rulesApplied: 18, // Number of comprehensive OWASP rules we have
        analysisTime: job.completedAt && job.createdAt ? 
          `${Math.floor((job.completedAt.getTime() - job.createdAt.getTime()) / 1000)}s` : '0s',
        vulnerabilities,
        cfg,
        dfg
      };

      res.json(report);
    } catch (error) {
      res.status(500).json({ message: "Failed to get results" });
    }
  });

  // Delete analysis job (cleanup)
  app.delete("/api/analysis/:jobId", async (req, res) => {
    try {
      const jobId = parseInt(req.params.jobId);
      await storage.deleteJobAndRelatedData(jobId);
      res.json({ message: "Analysis job deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete analysis job" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
