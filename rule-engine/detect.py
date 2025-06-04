import json
import yaml
from pathlib import Path
from typing import List, Dict, Any
import uuid
from datetime import datetime
import sys

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

        return findings

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

        if rule.sink_types and sink_type in rule.sink_types:
            confidence += 0.2
            match_reasons.append(f"Sink type matches: {sink_type}")
            sink_matches = True

        if rule.sink_scopes and any(scope.lower() in sink_scope for scope in rule.sink_scopes):
            confidence += 0.1
            match_reasons.append(f"Sink scope matches: {sink_scope}")
            sink_matches = True

        if not sink_matches:
            return None

        # Check path constraints
        sanitization_found = False
        for node in taint_path["pathNodes"]:
            node_name = node.get("name", "").lower()
            for constraint in rule.path_constraints:
                not_contains = constraint.get("not_contains", [])
                if isinstance(not_contains, str):
                    not_contains = [not_contains]
                for sanitizer in not_contains:
                    if sanitizer.lower() in node_name:
                        confidence *= 0.3
                        match_reasons.append(f"Sanitization detected: {sanitizer}")
                        sanitization_found = True
                        break

        # Check sensitive data
        for category, patterns in self.sensitive_data_patterns.items():
            for pattern in patterns:
                if pattern.lower() in source_name:
                    confidence += 0.2
                    match_reasons.append(f"Sensitive data pattern detected: {pattern} ({category})")
                    break

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
            "OWASP-A03-002": "Sanitize user input before logging. Use structured logging with parameterized messages. Consider excluding sensitive data from logs.",
            "OWASP-A02-001": "Encrypt or hash sensitive data before logging. Implement data classification and masking policies.",
            "OWASP-A03-001": "Use parameterized queries or prepared statements. Implement input validation and SQL injection prevention measures.",
            "OWASP-A03-003": "Validate and sanitize all user input. Use whitelisting for allowed commands. Consider safer alternatives to system commands.",
            "OWASP-A01-002": "Implement proper authorization checks. Validate user permissions before accessing objects. Use indirect object references.",
            "OWASP-A01-001": "Implement authorization checks before sensitive operations. Use role-based access control.",
            "OWASP-A02-002": "Encrypt sensitive data before storage. Use strong cryptographic algorithms.",
            "OWASP-A04-001": "Implement robust input validation for all user inputs. Use whitelisting where possible.",
            "OWASP-A05-001": "Disable debug logging in production. Mask sensitive information in logs.",
            "OWASP-A06-001": "Validate and sanitize input before deserialization. Use safe deserialization libraries.",
            "OWASP-A07-001": "Use secure password hashing (e.g., bcrypt, Argon2). Avoid storing plain-text passwords.",
            "OWASP-A08-001": "Avoid dynamic code execution. Validate and sanitize all inputs used in code execution.",
            "OWASP-A09-001": "Implement comprehensive security logging for sensitive operations. Ensure logs are tamper-proof.",
            "OWASP-A10-001": "Validate and whitelist URLs for server-side requests. Implement network-level protections.",
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
            "analyzer": "Python Rule Engine v1.0",
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