import { OWASP_RULES, type OwaspRule } from "./rules/owasp-rules";
import { JavaScriptParser } from "./parsers/javascript";
import { PythonParser } from "./parsers/python";
import { JavaParser } from "./parsers/java";
import { GraphGenerator } from "./graph-generator";
import type { ControlFlowGraph, DataFlowGraph } from "./graph-generator";
import type { Vulnerability, InsertVulnerability } from "@shared/schema";

export interface AnalysisContext {
  filename: string;
  language: string;
  content: string;
  fileId: number;
  jobId: number;
}

export interface RuleMatch {
  ruleId: string;
  severity: string;
  title: string;
  description: string;
  category: string;
  line: number;
  column?: number;
  code: string;
  recommendation: string;
  confidence: number;
}

export interface AnalysisResult {
  fileId: number;
  vulnerabilities: RuleMatch[];
  cfg?: ControlFlowGraph;
  dfg?: DataFlowGraph;
  metrics: {
    linesOfCode: number;
    complexityScore: number;
    rulesApplied: number;
  };
}

export class RuleEngine {
  private enabledRules: OwaspRule[];
  private patternCache: Map<string, RegExp>;

  constructor(customRules?: OwaspRule[]) {
    this.enabledRules = customRules || OWASP_RULES.filter(rule => rule.enabled);
    this.patternCache = new Map();
    this.precompilePatterns();
  }

  private precompilePatterns(): void {
    this.enabledRules.forEach(rule => {
      if (typeof rule.pattern === 'string') {
        this.patternCache.set(rule.id, new RegExp(rule.pattern, 'gi'));
      } else if (rule.pattern instanceof RegExp) {
        this.patternCache.set(rule.id, rule.pattern);
      }
    });
  }

  public async analyzeFile(context: AnalysisContext): Promise<AnalysisResult> {
    const vulnerabilities: RuleMatch[] = [];
    const lines = context.content.split('\n');
    
    // Generate AST and graphs
    const ast = this.parseCode(context.content, context.language);
    const cfg = GraphGenerator.generateControlFlowGraph(ast, context.language, context.filename);
    const dfg = GraphGenerator.generateDataFlowGraph(ast, context.language, context.filename);

    // Apply pattern-based rules
    const patternMatches = this.applyPatternRules(context, lines);
    vulnerabilities.push(...patternMatches);

    // Apply semantic rules using AST
    const semanticMatches = this.applySemanticRules(context, ast, lines);
    vulnerabilities.push(...semanticMatches);

    // Apply data flow analysis rules
    const dataFlowMatches = this.applyDataFlowRules(context, dfg, lines);
    vulnerabilities.push(...dataFlowMatches);

    // Apply control flow analysis rules
    const controlFlowMatches = this.applyControlFlowRules(context, cfg, lines);
    vulnerabilities.push(...controlFlowMatches);

    // Calculate metrics
    const metrics = this.calculateMetrics(context.content, ast);

    return {
      fileId: context.fileId,
      vulnerabilities,
      cfg,
      dfg,
      metrics
    };
  }

  private parseCode(content: string, language: string): any {
    try {
      switch (language.toLowerCase()) {
        case 'javascript':
        case 'typescript':
          return JavaScriptParser.parse(content);
        case 'python':
          return PythonParser.parse(content);
        case 'java':
          return JavaParser.parse(content);
        default:
          return { type: 'Unknown', body: [] };
      }
    } catch (error) {
      console.warn(`Failed to parse ${language} code:`, error);
      return { type: 'ParseError', body: [] };
    }
  }

  private applyPatternRules(context: AnalysisContext, lines: string[]): RuleMatch[] {
    const matches: RuleMatch[] = [];

    lines.forEach((line, lineIndex) => {
      const trimmedLine = line.trim();
      if (!trimmedLine) return;

      this.enabledRules.forEach(rule => {
        const pattern = this.patternCache.get(rule.id);
        if (!pattern) return;

        // Reset regex state
        pattern.lastIndex = 0;
        const regexMatches = Array.from(trimmedLine.matchAll(pattern));

        regexMatches.forEach(match => {
          if (match.index !== undefined) {
            matches.push({
              ruleId: rule.id,
              severity: rule.severity,
              title: rule.name,
              description: rule.description,
              category: rule.category,
              line: lineIndex + 1,
              column: match.index + 1,
              code: trimmedLine,
              recommendation: rule.recommendation,
              confidence: this.calculateConfidence(rule, match[0], trimmedLine)
            });
          }
        });
      });
    });

    return matches;
  }

  private applySemanticRules(context: AnalysisContext, ast: any, lines: string[]): RuleMatch[] {
    const matches: RuleMatch[] = [];

    if (!ast.body) return matches;

    // Language-specific semantic analysis
    switch (context.language.toLowerCase()) {
      case 'javascript':
      case 'typescript':
        matches.push(...this.analyzeJavaScriptSemantics(context, ast, lines));
        break;
      case 'python':
        matches.push(...this.analyzePythonSemantics(context, ast, lines));
        break;
      case 'java':
        matches.push(...this.analyzeJavaSemantics(context, ast, lines));
        break;
    }

    return matches;
  }

  private analyzeJavaScriptSemantics(context: AnalysisContext, ast: any, lines: string[]): RuleMatch[] {
    const matches: RuleMatch[] = [];

    ast.body.forEach((node: any) => {
      // Check for missing authentication middleware
      if (node.type === 'CallExpression' && node.code) {
        if (node.code.includes('app.') && (node.code.includes('.get(') || node.code.includes('.post('))) {
          if (!this.hasAuthenticationCheck(node.code, ast)) {
            matches.push({
              ruleId: 'missing-auth-check',
              severity: 'high',
              title: 'Missing Authentication Check',
              description: 'Route handler may lack proper authentication verification',
              category: 'A07:2021 - Identification and Authentication Failures',
              line: node.line || 1,
              code: node.code,
              recommendation: 'Add authentication middleware or checks before processing requests',
              confidence: 0.7
            });
          }
        }

        // Check for unsafe DOM manipulation
        if (node.code.includes('innerHTML') || node.code.includes('document.write')) {
          matches.push({
            ruleId: 'xss-reflection',
            severity: 'high',
            title: 'Potential XSS Vulnerability',
            description: 'Unsafe DOM manipulation that could lead to XSS attacks',
            category: 'A03:2021 - Injection',
            line: node.line || 1,
            code: node.code,
            recommendation: 'Use textContent or proper sanitization libraries instead of innerHTML',
            confidence: 0.8
          });
        }
      }

      // Check for insecure cookie settings
      if (node.type === 'CallExpression' && node.code && node.code.includes('cookie')) {
        if (!node.code.includes('secure') || !node.code.includes('httpOnly')) {
          matches.push({
            ruleId: 'insecure-cookie',
            severity: 'medium',
            title: 'Insecure Cookie Configuration',
            description: 'Cookie missing security flags (secure, httpOnly)',
            category: 'A05:2021 - Security Misconfiguration',
            line: node.line || 1,
            code: node.code,
            recommendation: 'Set secure and httpOnly flags for sensitive cookies',
            confidence: 0.9
          });
        }
      }
    });

    return matches;
  }

  private analyzePythonSemantics(context: AnalysisContext, ast: any, lines: string[]): RuleMatch[] {
    const matches: RuleMatch[] = [];

    ast.body.forEach((node: any) => {
      // Check for SQL injection in Python
      if (node.type === 'Expr' && node.code) {
        if (node.code.includes('cursor.execute') && node.code.includes('%s')) {
          matches.push({
            ruleId: 'sql-injection-python',
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: 'Use of string formatting in SQL queries can lead to injection',
            category: 'A03:2021 - Injection',
            line: node.line || 1,
            code: node.code,
            recommendation: 'Use parameterized queries with proper placeholders',
            confidence: 0.9
          });
        }

        // Check for pickle deserialization
        if (node.code.includes('pickle.loads') || node.code.includes('pickle.load')) {
          matches.push({
            ruleId: 'insecure-deserialization-python',
            severity: 'high',
            title: 'Insecure Deserialization',
            description: 'Pickle deserialization can execute arbitrary code',
            category: 'A08:2021 - Software and Data Integrity Failures',
            line: node.line || 1,
            code: node.code,
            recommendation: 'Use safer serialization formats like JSON with validation',
            confidence: 0.95
          });
        }
      }

      // Check for weak random number generation
      if (node.type === 'Import' && node.code && node.code.includes('random')) {
        matches.push({
          ruleId: 'weak-random-python',
          severity: 'medium',
          title: 'Weak Random Number Generator',
          description: 'Standard random module is not cryptographically secure',
          category: 'A02:2021 - Cryptographic Failures',
          line: node.line || 1,
          code: node.code,
          recommendation: 'Use secrets module for cryptographically secure random numbers',
          confidence: 0.6
        });
      }
    });

    return matches;
  }

  private analyzeJavaSemantics(context: AnalysisContext, ast: any, lines: string[]): RuleMatch[] {
    const matches: RuleMatch[] = [];

    ast.classes?.forEach((cls: any) => {
      // Check for serialization issues
      cls.methods?.forEach((method: any) => {
        if (method.name === 'readObject' && !this.hasSecurityChecks(method.code)) {
          matches.push({
            ruleId: 'insecure-serialization-java',
            severity: 'high',
            title: 'Insecure Serialization',
            description: 'Custom readObject method without security validation',
            category: 'A08:2021 - Software and Data Integrity Failures',
            line: method.line || 1,
            code: method.code || '',
            recommendation: 'Add validation and security checks in readObject method',
            confidence: 0.8
          });
        }

        // Check for SQL injection in JDBC
        if (method.code && method.code.includes('Statement') && method.code.includes('executeQuery')) {
          if (!method.code.includes('PreparedStatement')) {
            matches.push({
              ruleId: 'sql-injection-java',
              severity: 'critical',
              title: 'SQL Injection Vulnerability',
              description: 'Use of Statement instead of PreparedStatement',
              category: 'A03:2021 - Injection',
              line: method.line || 1,
              code: method.code,
              recommendation: 'Use PreparedStatement with parameterized queries',
              confidence: 0.9
            });
          }
        }
      });
    });

    return matches;
  }

  private applyDataFlowRules(context: AnalysisContext, dfg: DataFlowGraph, lines: string[]): RuleMatch[] {
    const matches: RuleMatch[] = [];

    // Analyze variable flows for taint analysis
    dfg.variables.forEach((varInfo, varName) => {
      // Check if sensitive data flows to insecure locations
      if (this.isSensitiveVariable(varName)) {
        varInfo.useSites.forEach(useSite => {
          const node = dfg.nodes.find(n => n.id === useSite);
          if (node && this.isInsecureUsage(node.code || '')) {
            matches.push({
              ruleId: 'sensitive-data-exposure',
              severity: 'high',
              title: 'Sensitive Data Exposure',
              description: `Sensitive variable '${varName}' used in potentially insecure context`,
              category: 'A02:2021 - Cryptographic Failures',
              line: node.line || 1,
              code: node.code || '',
              recommendation: 'Ensure sensitive data is properly protected and not logged or exposed',
              confidence: 0.7
            });
          }
        });
      }
    });

    return matches;
  }

  private applyControlFlowRules(context: AnalysisContext, cfg: ControlFlowGraph, lines: string[]): RuleMatch[] {
    const matches: RuleMatch[] = [];

    // Analyze control flow for security patterns
    cfg.nodes.forEach(node => {
      // Check for unreachable code after return/throw
      if (node.code && (node.code.includes('return') || node.code.includes('throw'))) {
        const nodeIndex = cfg.nodes.indexOf(node);
        const nextNode = cfg.nodes[nodeIndex + 1];
        
        if (nextNode && !this.hasIncomingEdges(nextNode.id, cfg.edges)) {
          matches.push({
            ruleId: 'unreachable-code',
            severity: 'low',
            title: 'Unreachable Code',
            description: 'Code after return/throw statement is unreachable',
            category: 'A04:2021 - Insecure Design',
            line: nextNode.line || 1,
            code: nextNode.code || '',
            recommendation: 'Remove unreachable code or fix control flow logic',
            confidence: 0.8
          });
        }
      }
    });

    return matches;
  }

  private calculateConfidence(rule: OwaspRule, match: string, context: string): number {
    let confidence = 0.5; // Base confidence

    // Increase confidence based on rule specificity
    if (rule.severity === 'critical') confidence += 0.2;
    if (rule.severity === 'high') confidence += 0.15;
    
    // Context-based confidence adjustments
    if (context.includes('password') || context.includes('secret')) confidence += 0.2;
    if (context.includes('user') || context.includes('input')) confidence += 0.1;
    if (context.includes('//') || context.includes('#')) confidence -= 0.1; // Comments
    
    return Math.min(0.95, Math.max(0.1, confidence));
  }

  private calculateMetrics(content: string, ast: any): { linesOfCode: number; complexityScore: number; rulesApplied: number } {
    const lines = content.split('\n').filter(line => line.trim() !== '');
    const linesOfCode = lines.length;
    
    // Simple complexity calculation based on control structures
    const complexityIndicators = ['if', 'else', 'for', 'while', 'switch', 'case', 'try', 'catch'];
    let complexityScore = 1; // Base complexity
    
    lines.forEach(line => {
      complexityIndicators.forEach(indicator => {
        if (line.includes(indicator)) complexityScore++;
      });
    });

    return {
      linesOfCode,
      complexityScore,
      rulesApplied: this.enabledRules.length
    };
  }

  private hasAuthenticationCheck(code: string, ast: any): boolean {
    // Simple heuristic to check for authentication patterns
    const authPatterns = ['authenticate', 'auth', 'token', 'login', 'session', 'verify'];
    return authPatterns.some(pattern => code.toLowerCase().includes(pattern));
  }

  private hasSecurityChecks(code: string): boolean {
    const securityPatterns = ['validate', 'check', 'verify', 'security', 'sanitize'];
    return securityPatterns.some(pattern => code.toLowerCase().includes(pattern));
  }

  private isSensitiveVariable(varName: string): boolean {
    const sensitivePatterns = ['password', 'pwd', 'secret', 'key', 'token', 'api', 'credential'];
    return sensitivePatterns.some(pattern => varName.toLowerCase().includes(pattern));
  }

  private isInsecureUsage(code: string): boolean {
    const insecurePatterns = ['console.log', 'print', 'System.out', 'log.info', 'logger.info'];
    return insecurePatterns.some(pattern => code.includes(pattern));
  }

  private hasIncomingEdges(nodeId: string, edges: any[]): boolean {
    return edges.some(edge => edge.target === nodeId);
  }

  public getEnabledRules(): OwaspRule[] {
    return [...this.enabledRules];
  }

  public enableRule(ruleId: string): void {
    const rule = OWASP_RULES.find(r => r.id === ruleId);
    if (rule && !this.enabledRules.find(r => r.id === ruleId)) {
      this.enabledRules.push(rule);
      this.precompilePatterns();
    }
  }

  public disableRule(ruleId: string): void {
    this.enabledRules = this.enabledRules.filter(r => r.id !== ruleId);
    this.patternCache.delete(ruleId);
  }

  public setCustomRules(rules: OwaspRule[]): void {
    this.enabledRules = rules;
    this.patternCache.clear();
    this.precompilePatterns();
  }
}

// Export singleton instance
export const ruleEngine = new RuleEngine();

// Export utility functions
export function createVulnerabilityFromMatch(match: RuleMatch, jobId: number, fileId: number): InsertVulnerability {
  return {
    jobId,
    fileId,
    ruleId: match.ruleId,
    severity: match.severity,
    title: match.title,
    description: match.description,
    category: match.category,
    line: match.line,
    column: match.column,
    code: match.code,
    recommendation: match.recommendation
  };
}

export function prioritizeVulnerabilities(vulnerabilities: RuleMatch[]): RuleMatch[] {
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  
  return vulnerabilities.sort((a, b) => {
    const severityDiff = (severityOrder[b.severity as keyof typeof severityOrder] || 0) - 
                        (severityOrder[a.severity as keyof typeof severityOrder] || 0);
    
    if (severityDiff !== 0) return severityDiff;
    
    // Secondary sort by confidence
    return b.confidence - a.confidence;
  });
}
