import json
import yaml
from pathlib import Path
from typing import List, Dict, Any
import uuid
from datetime import datetime
import sys
import re

class VulnerabilityRule:
    def __init__(self, rule_data: Dict[str, Any]):
        self.rule_id = rule_data.get("rule_id")
        self.name = rule_data.get("name")
        self.category = rule_data.get("category")
        self.owasp_category = rule_data.get("owasp_category")
        self.severity = rule_data.get("severity")
        self.description = rule_data.get("description")
        pattern = rule_data.get("pattern", {})
        self.source_types = pattern.get("source_types", [])
        self.source_names = pattern.get("source_names", [])
        self.sink_types = pattern.get("sink_types", [])
        self.sink_names = pattern.get("sink_names", [])
        self.sink_patterns = pattern.get("sink_patterns", [])
        self.sink_scopes = pattern.get("sink_scopes", [])
        self.path_constraints = pattern.get("path_constraints", [])

class VulnerabilityFinding:
    def __init__(
        self,
        rule: VulnerabilityRule,
        taint_path: Dict[str, Any],
        confidence: float,
        risk_score: float,
        match_reasons: List[str],
        remediation: str,
    ):
        self.rule_id = rule.rule_id
        self.name = rule.name
        self.owasp_category = rule.owasp_category
        self.severity = rule.severity
        self.description = rule.description
        self.taint_path = taint_path
        self.confidence = confidence
        self.risk_score = risk_score
        self.match_reasons = match_reasons
        self.remediation = remediation

class RuleEngine:
    def __init__(self, rules_file: str):
        self.rules = self.load_rules(rules_file)
        with open(rules_file, "r") as f:
            config = yaml.safe_load(f)
        self.severity_weights = config.get("risk_assessment", {}).get("severity_weights", {})
        self.confidence_factors = config.get("risk_assessment", {}).get("confidence_factors", {})
        self.sensitive_data_patterns = config.get("pattern_extensions", {}).get("sensitive_data_patterns", {})
        self.sanitization_functions = config.get("pattern_extensions", {}).get("sanitization_functions", {})
        self.context_multipliers = config.get("pattern_extensions", {}).get("context_rules", {})

    def load_rules(self, rules_file: str) -> List[VulnerabilityRule]:
        with open(rules_file, "r") as f:
            data = yaml.safe_load(f)
        return [VulnerabilityRule(rule) for rule in data.get("rules", [])]

    def load_graph_data(self, folder: str) -> Dict[str, Any]:
        folder_path = Path(folder)
        data = {}
        for file in ["codegraph.json", "taint_analysis.json", "cfg.json", "dfg.json"]:
            file_path = folder_path / file
            if file_path.exists():
                with open(file_path, "r") as f:
                    data[file.replace(".json", "")] = json.load(f)
        return data

    def analyze_vulnerabilities(self, graph_data: Dict[str, Any]) -> List[VulnerabilityFinding]:
        findings = []
        taint_data = graph_data.get("taint_analysis", {})
        codegraph = graph_data.get("codegraph", {})
        tainted_paths = taint_data.get("taintedPaths", [])

        for path in tainted_paths:
            for rule in self.rules:
                finding = self.evaluate_rule(rule, path, codegraph)
                if finding:
                    findings.append(finding)

        # Apply false-positive filters
        findings = self.apply_false_positive_filters(findings, codegraph)
        return findings

    def apply_false_positive_filters(self, findings: List[VulnerabilityFinding], codegraph: Dict[str, Any]) -> List[VulnerabilityFinding]:
        filtered_findings = []
        for finding in findings:
            # Skip findings for irrelevant categories (e.g., SQL/Command Injection without database/command sinks)
            if finding.owasp_category == "A03:2021" and finding.rule_id in ["OWASP-A03-001", "OWASP-A03-003"]:
                sink_name = finding.taint_path["sinkName"].lower()
                if not any(pattern in sink_name for pattern in ["execute", "query", "createQuery", "prepareStatement", "Runtime.exec", "ProcessBuilder", "executeCommand", "system"]):
                    continue
            # Skip deserialization/command execution findings without specific sinks
            if finding.owasp_category in ["A06:2021", "A08:2021"]:
                sink_name = finding.taint_path["sinkName"].lower()
                if not any(pattern in sink_name for pattern in ["readObject", "deserialize", "fromXML", "fromJSON", "eval", "compile", "loadClass", "invoke"]):
                    continue
            filtered_findings.append(finding)
        return filtered_findings

    def evaluate_rule(
        self, rule: VulnerabilityRule, taint_path: Dict[str, Any], codegraph: Dict[str, Any]
    ) -> VulnerabilityFinding:
        confidence = 0.0
        match_reasons = []

        # Check source
        source_node = taint_path["pathNodes"][0]
        source_name = source_node.get("name", "").lower()
        source_type = source_node.get("type", "")

        if rule.source_types and source_type not in rule.source_types:
            return None
        if rule.source_types:
            confidence += 0.3
            match_reasons.append(f"Source type matches: {source_type}")

        if rule.source_names and any(name.lower() in source_name for name in rule.source_names):
            confidence += 0.2
            match_reasons.append(f"Source name matches: {source_name}")

        # Check sink
        sink_node = taint_path["pathNodes"][-1]
        sink_name = sink_node.get("name", "").lower()
        sink_type = sink_node.get("type", "")
        sink_scope = sink_node.get("scope", "").lower()

        # Enhanced sink matching logic
        sink_matches = False
        for name in rule.sink_names:
            if name.lower() in sink_name:
                confidence += 0.4
                match_reasons.append(f"Sink name matches: {name}")
                sink_matches = True
                break

        for pattern in rule.sink_patterns:
            if pattern.endswith("*"):
                if sink_name.startswith(pattern[:-1].lower()):
                    confidence += 0.4
                    match_reasons.append(f"Sink pattern matches: {pattern}")
                    sink_matches = True
                    break
            elif pattern.lower() in sink_name:
                confidence += 0.4
                match_reasons.append(f"Sink pattern matches: {pattern}")
                sink_matches = True
                break

        if not sink_matches and rule.sink_types and sink_type in rule.sink_types:
            confidence += 0.2
            match_reasons.append(f"Sink type matches: {sink_type}")
            sink_matches = True

        if rule.sink_scopes and any(scope.lower() in sink_scope for scope in rule.sink_scopes):
            confidence += 0.1
            match_reasons.append(f"Sink scope matches: {sink_scope}")
            sink_matches = True

        if not sink_matches:
            return None

        # Enhanced sanitization detection
        sanitization_found = False
        for node in taint_path["pathNodes"]:
            node_name = node.get("name", "").lower()
            
            # Check against path constraints
            for constraint in rule.path_constraints:
                not_contains = constraint.get("not_contains", [])
                if isinstance(not_contains, str):
                    not_contains = [not_contains]
                for sanitizer in not_contains:
                    if sanitizer.lower() in node_name:
                        confidence *= 0.2  # Stronger reduction for sanitization
                        match_reasons.append(f"Sanitization detected: {sanitizer}")
                        sanitization_found = True
                        break
            
            # Check against sanitization functions with regex for specific patterns
            for category, functions in self.sanitization_functions.items():
                for func in functions:
                    # Check for method calls or variable names indicating sanitization
                    if re.search(rf'\b{func.lower()}\b|\bsanitized\b', node_name):
                        confidence *= 0.2  # Stronger reduction for sanitization
                        match_reasons.append(f"Sanitization function detected: {func} ({category})")
                        sanitization_found = True
                        break

        # Adjust severity for logging-related issues
        if rule.owasp_category == "A03:2021" and rule.rule_id == "OWASP-A03-002":  # Log Injection/Forging
            if not sanitization_found:
                rule.severity = "MEDIUM"  # Default to Medium unless sensitive data is detected
            else:
                rule.severity = "LOW"  # Downgrade to Low if sanitized

        # Enhanced sensitive data detection
        for category, patterns in self.sensitive_data_patterns.items():
            for pattern in patterns:
                if pattern.lower() in source_name:
                    confidence += 0.2
                    match_reasons.append(f"Sensitive data pattern detected: {pattern} ({category})")
                    if rule.owasp_category == "A03:2021" and rule.rule_id == "OWASP-A03-002":
                        rule.severity = "HIGH"  # Upgrade to High for sensitive data in logs
                    break

        # Apply context multiplier
        context = codegraph.get("context", "general")
        context_multiplier = next((c["multiplier"] for c in self.context_multipliers if c["context"] == context), 1.0)
        confidence *= context_multiplier

        # Apply path complexity
        path_length = len(taint_path["pathNodes"])
        complexity_type = (
            "direct_flow" if path_length == 2 else
            "single_transformation" if path_length == 3 else
            "multiple_transformations"
        )
        confidence *= self.confidence_factors.get(complexity_type, 0.5)

        # Calculate risk score
        severity_weight = self.severity_weights.get(rule.severity, 1.0)
        risk_score = severity_weight * confidence

        if confidence < 0.5:
            return None

        # Generate remediation
        remediation = self.generate_remediation(rule)

        return VulnerabilityFinding(
            rule=rule,
            taint_path=taint_path,
            confidence=round(confidence, 2),
            risk_score=round(risk_score, 2),
            match_reasons=match_reasons,
            remediation=remediation,
        )

    def generate_remediation(self, rule: VulnerabilityRule) -> str:
        remediation_map = {
            "OWASP-A03-002": "Sanitize user input before logging using methods like replaceAll for special characters. Use structured logging with parameterized messages. Exclude sensitive data from logs.",
            "OWASP-A02-001": "Encrypt or hash sensitive data before logging. Implement data classification and masking policies. Avoid logging PII or credentials.",
            "OWASP-A03-001": "Use parameterized queries or prepared statements for SQL operations. Implement input validation and SQL injection prevention measures.",
            "OWASP-A03-003": "Validate and sanitize all user input for system commands. Use whitelisting for allowed commands. Avoid Runtime.exec or ProcessBuilder.",
            "OWASP-A01-001": "Implement role-based access control (RBAC). Validate user permissions before sensitive operations.",
            "OWASP-A01-002": "Use indirect object references. Validate user ownership of resources before access.",
            "OWASP-A02-002": "Encrypt sensitive data before storage using strong algorithms (e.g., AES-256). Avoid plain-text storage.",
            "OWASP-A04-001": "Implement robust input validation and whitelisting for all user inputs. Use secure coding practices.",
            "OWASP-A05-001": "Disable debug and trace logging in production. Mask sensitive information in logs.",
            "OWASP-A06-001": "Validate and sanitize input before deserialization. Use safe deserialization libraries like Jackson with strict type checking.",
            "OWASP-A07-001": "Use secure password hashing (e.g., bcrypt, Argon2). Avoid storing plain-text passwords.",
            "OWASP-A08-001": "Avoid dynamic code execution (e.g., eval, compile). Validate and sanitize inputs used in code execution paths.",
            "OWASP-A09-001": "Implement tamper-proof security logging for sensitive operations. Ensure logs capture sufficient context for auditing.",
            "OWASP-A10-001": "Whitelist allowed URLs for server-side requests. Implement network-level protections to prevent SSRF.",
        }
        return remediation_map.get(rule.rule_id, "Review the identified vulnerability and implement appropriate security controls.")

    def generate_report(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        severity_counts = {}
        category_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            category_counts[finding.owasp_category] = category_counts.get(finding.owasp_category, 0) + 1

        findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        findings_json = [
            {
                "ruleId": f.rule_id,
                "name": f.name,
                "owaspCategory": f.owasp_category,
                "severity": f.severity,
                "description": f.description,
                "confidence": f.confidence,
                "riskScore": f.risk_score,
                "remediation": f.remediation,
                "matchReasons": f.match_reasons,
                "taintPath": {
                    "sourceName": f.taint_path["sourceName"],
                    "sinkName": f.taint_path["sinkName"],
                    "pathLength": len(f.taint_path["pathNodes"]),
                    "vulnerability": f.taint_path["vulnerability"],
                },
            }
            for f in findings
        ]

        return {
            "summary": {
                "totalFindings": len(findings),
                "severityBreakdown": severity_counts,
                "owaspCategoryBreakdown": category_counts,
            },
            "findings": findings_json,
            "timestamp": int(datetime.now().timestamp() * 1000),
            "analyzer": "Python Rule Engine v1.2",  # Updated version
        }

    def print_summary(self, findings: List[VulnerabilityFinding]):
        print("\n🛡️ OWASP Vulnerability Analysis Results")
        print("========================================")

        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        print("\n📊 Summary:")
        print(f"   Total Vulnerabilities: {len(findings)}")
        print(f"   Critical: {severity_counts.get('CRITICAL', 0)}")
        print(f"   High: {severity_counts.get('HIGH', 0)}")
        print(f"   Medium: {severity_counts.get('MEDIUM', 0)}")
        print(f"   Low: {severity_counts.get('LOW', 0)}")

        print("\n🔍 Top Findings:")
        findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        for i, finding in enumerate(findings[:5], 1):
            print(f"   {i}. {finding.name} ({finding.severity}) - Risk Score: {finding.risk_score}")
            print(f"      Path: {finding.taint_path['sourceName']} → {finding.taint_path['sinkName']}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python rule_engine.py <output_folder> [output_file]")
        sys.exit(1)

    output_folder = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "owasp_vulnerabilities.json"
    rules_file = "rules.yaml"

    try:
        engine = RuleEngine(rules_file)
        graph_data = engine.load_graph_data(output_folder)
        findings = engine.analyze_vulnerabilities(graph_data)
        report = engine.generate_report(findings)

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        engine.print_summary(findings)
        print(f"\n📝 Report saved to {output_file}")

    except Exception as e:
        print(f"Error analyzing vulnerabilities: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()