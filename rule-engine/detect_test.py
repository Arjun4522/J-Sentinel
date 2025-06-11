import yaml
import json
import glob
import re
from typing import List, Dict, Any, Set, Tuple, Optional
from pathlib import Path
from dataclasses import dataclass
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Rule:
    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data["id"]
        self.category = rule_data["category"]
        self.graph = rule_data["graph"]
        self.pattern = rule_data["pattern"]
        self.severity = rule_data["severity"]
        self.description = rule_data["description"]
        self.remediation = rule_data["remediation"]

@dataclass
class Vulnerability:
    def __init__(self, rule: Rule, location: str, details: str, context: Dict[str, Any] = None):
        self.rule_id = rule.id
        self.category = rule.category
        self.severity = rule.severity
        self.location = location
        self.details = rule.description
        self.remediation = rule.remediation
        self.context = context or {}

class EnhancedVulnerabilityDetector:
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.rules = self.load_rules()
        self.graphs = self.load_graphs()
        self.node_cache = {}  # Cache for faster node lookups
        self.edge_cache = {}  # Cache for edge lookups
        self._build_caches()

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing config file: {e}")
            raise

    def load_rules(self) -> List[Rule]:
        """Load security rules from YAML files"""
        rules = []
        rules_pattern = self.config.get("rules_dir", "rules") + "/*.yaml"
        
        for rule_file in glob.glob(rules_pattern):
            try:
                with open(rule_file, "r") as f:
                    rule_data = yaml.safe_load(f)
                    if isinstance(rule_data, list):
                        rules.extend(Rule(rule) for rule in rule_data)
                    else:
                        rules.append(Rule(rule_data))
                logger.info(f"Loaded rules from {rule_file}")
            except Exception as e:
                logger.error(f"Error loading rules from {rule_file}: {e}")
        
        logger.info(f"Total rules loaded: {len(rules)}")
        return rules

    def load_graphs(self) -> Dict[str, Dict]:
        """Load code analysis graphs (AST, CFG, DFG)"""
        graphs = {}
        graphs_pattern = self.config.get("graphs_dir", "graphs") + "/*.json"
        
        for graph_file in glob.glob(graphs_pattern):
            try:
                graph_type = Path(graph_file).stem
                with open(graph_file, "r") as f:
                    graphs[graph_type] = json.load(f)
                logger.info(f"Loaded {graph_type} graph from {graph_file}")
            except Exception as e:
                logger.error(f"Error loading graph from {graph_file}: {e}")
        
        return graphs

    def _build_caches(self):
        """Build caches for faster node and edge lookups"""
        for graph_type, graph in self.graphs.items():
            # Build node cache by type and ID
            self.node_cache[graph_type] = {
                'by_type': defaultdict(list),
                'by_id': {}
            }
            
            nodes = graph.get("nodes", [])
            for node in nodes:
                node_type = node.get("type")
                node_id = node.get("id")
                
                if node_type:
                    self.node_cache[graph_type]['by_type'][node_type].append(node)
                if node_id is not None:
                    self.node_cache[graph_type]['by_id'][node_id] = node
            
            # Build edge cache
            self.edge_cache[graph_type] = {
                'by_type': defaultdict(list),
                'by_source': defaultdict(list),
                'by_target': defaultdict(list)
            }
            
            edges = graph.get("edges", [])
            for edge in edges:
                edge_type = edge.get("type")
                source = edge.get("source")
                target = edge.get("target")
                
                if edge_type:
                    self.edge_cache[graph_type]['by_type'][edge_type].append(edge)
                if source is not None:
                    self.edge_cache[graph_type]['by_source'][source].append(edge)
                if target is not None:
                    self.edge_cache[graph_type]['by_target'][target].append(edge)

    def evaluate_rule(self, rule: Rule, graph: Dict) -> List[Vulnerability]:
        """Evaluate a single rule against a graph"""
        findings = []
        
        if rule.graph not in self.graphs:
            return findings

        try:
            # Get matched nodes based on pattern
            matched_node_sets = self._match_nodes(rule, graph)
            
            if not matched_node_sets:
                return findings

            # If rule has edge patterns, match them
            if rule.pattern.get("edges"):
                findings.extend(self._match_edges(rule, graph, matched_node_sets))
            else:
                # For rules without edges, create findings for matched nodes
                findings.extend(self._create_node_findings(rule, graph, matched_node_sets))

        except Exception as e:
            logger.error(f"Error evaluating rule {rule.id}: {e}")

        return findings

    def _match_nodes(self, rule: Rule, graph: Dict) -> List[List[Dict]]:
        """Match nodes based on rule pattern"""
        matched_sets = []
        graph_type = rule.graph
        
        for node_pattern in rule.pattern.get("nodes", []):
            node_type = node_pattern.get("type")
            attributes = node_pattern.get("attributes", {})
            
            matched_nodes = []
            
            # Use cache for faster lookup
            candidate_nodes = self.node_cache.get(graph_type, {}).get('by_type', {}).get(node_type, [])
            
            for node in candidate_nodes:
                if self._match_attributes(node, attributes):
                    matched_nodes.append(node)
            
            if matched_nodes:
                matched_sets.append(matched_nodes)
        
        return matched_sets

    def _match_edges(self, rule: Rule, graph: Dict, matched_node_sets: List[List[Dict]]) -> List[Vulnerability]:
        """Match edges based on rule pattern"""
        findings = []
        graph_type = rule.graph
        
        for edge_pattern in rule.pattern.get("edges", []):
            edge_type = edge_pattern.get("type")
            source_type = edge_pattern.get("source_type")
            target_type = edge_pattern.get("target_type")
            
            # Get edges of the specified type
            candidate_edges = self.edge_cache.get(graph_type, {}).get('by_type', {}).get(edge_type, [])
            
            for edge in candidate_edges:
                source_node = self.node_cache.get(graph_type, {}).get('by_id', {}).get(edge.get("source"))
                target_node = self.node_cache.get(graph_type, {}).get('by_id', {}).get(edge.get("target"))
                
                if (source_node and target_node and
                    source_node.get("type") == source_type and
                    target_node.get("type") == target_type):
                    
                    # Check if nodes match the pattern requirements
                    if self._validate_edge_nodes(rule, source_node, target_node, matched_node_sets):
                        location = self._get_enhanced_location(graph, target_node)
                        context = self._build_context(rule, source_node, target_node, edge)
                        
                        findings.append(Vulnerability(
                            rule,
                            location,
                            f"Found {edge_type} from {source_type} to {target_type}",
                            context
                        ))
        
        return findings

    def _validate_edge_nodes(self, rule: Rule, source_node: Dict, target_node: Dict, 
                           matched_node_sets: List[List[Dict]]) -> bool:
        """Validate that edge nodes satisfy the rule requirements"""
        # Check if source and target nodes are in the matched sets
        source_in_set = any(source_node in node_set for node_set in matched_node_sets)
        target_in_set = any(target_node in node_set for node_set in matched_node_sets)
        
        return source_in_set or target_in_set

    def _create_node_findings(self, rule: Rule, graph: Dict, 
                            matched_node_sets: List[List[Dict]]) -> List[Vulnerability]:
        """Create findings for rules that only match nodes (no edges)"""
        findings = []
        
        for node_set in matched_node_sets:
            for node in node_set:
                location = self._get_enhanced_location(graph, node)
                context = self._build_node_context(rule, node)
                
                findings.append(Vulnerability(
                    rule,
                    location,
                    f"Found {node.get('type')} with matching attributes",
                    context
                ))
        
        return findings

    def _match_attributes(self, node: Dict, attributes: Dict) -> bool:
        """Enhanced attribute matching with support for complex patterns"""
        for key, pattern in attributes.items():
            node_value = node.get(key)
            
            if node_value is None:
                return False
            
            # Convert to string for pattern matching
            node_value_str = str(node_value)
            
            if isinstance(pattern, str):
                if pattern.startswith("^"):
                    # Regex pattern
                    try:
                        if not re.search(pattern, node_value_str, re.IGNORECASE):
                            return False
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern {pattern}: {e}")
                        return False
                else:
                    # Exact match (case-insensitive for strings)
                    if isinstance(node_value, str):
                        if node_value.lower() != pattern.lower():
                            return False
                    elif node_value != pattern:
                        return False
            elif isinstance(pattern, (list, tuple)):
                # Multiple possible values
                if node_value not in pattern:
                    return False
            elif node_value != pattern:
                return False
        
        return True

    def _get_enhanced_location(self, graph: Dict, node: Dict) -> str:
        """Get enhanced location information including file, line, and column"""
        # Try to get location from node itself
        if "location" in node:
            loc = node["location"]
            return f"{loc.get('file', 'Unknown')}:{loc.get('line', 0)}:{loc.get('column', 0)}"
        
        # Try to get from node attributes
        file_name = node.get("file") or node.get("filename") or node.get("source")
        line_num = node.get("line") or node.get("lineNumber") or node.get("startLine")
        col_num = node.get("column") or node.get("columnNumber") or node.get("startColumn")
        
        if file_name:
            location = str(file_name)
            if line_num is not None:
                location += f":{line_num}"
                if col_num is not None:
                    location += f":{col_num}"
            return location
        
        # Fallback: search for FILE nodes in the graph
        for graph_node in graph.get("nodes", []):
            if graph_node.get("type") == "FILE":
                return f"{graph_node.get('name', 'Unknown')}:0:0"
        
        return "Unknown:0:0"

    def _build_context(self, rule: Rule, source_node: Dict, target_node: Dict, edge: Dict) -> Dict[str, Any]:
        """Build context information for vulnerability"""
        return {
            "source_node": {
                "type": source_node.get("type"),
                "name": source_node.get("name"),
                "attributes": {k: v for k, v in source_node.items() 
                            if k not in ["id", "type"] and not k.startswith("_")}
            },
            "target_node": {
                "type": target_node.get("type"),
                "name": target_node.get("name"),
                "attributes": {k: v for k, v in target_node.items() 
                            if k not in ["id", "type"] and not k.startswith("_")}
            },
            "edge": {
                "type": edge.get("type"),
                "attributes": {k: v for k, v in edge.items() 
                            if k not in ["source", "target", "type"]}
            }
        }

    def _build_node_context(self, rule: Rule, node: Dict) -> Dict[str, Any]:
        """Build context information for node-only vulnerabilities"""
        return {
            "node": {
                "type": node.get("type"),
                "name": node.get("name"),
                "attributes": {k: v for k, v in node.items() 
                            if k not in ["id", "type"] and not k.startswith("_")}
            }
        }

    def _get_severity_priority(self, severity: str) -> int:
        """Get numeric priority for severity levels"""
        priorities = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        return priorities.get(severity, 0)

    def analyze(self) -> Dict:
        """Main analysis method"""
        logger.info("Starting vulnerability analysis...")
        
        all_findings = []
        rule_stats = defaultdict(int)
        
        for rule in self.rules:
            # Iterate through all available graphs instead of checking rule.graph
            for graph_type, graph in self.graphs.items():
                logger.debug(f"Evaluating rule {rule.id} against graph {graph_type}")
                findings = self.evaluate_rule(rule, graph)
                # Add graph type to context for clarity in findings
                for finding in findings:
                    finding.context['graph_type'] = graph_type
                all_findings.extend(findings)
                rule_stats[rule.category] += len(findings)
                
                if findings:
                    logger.info(f"Rule {rule.id} found {len(findings)} issues in {graph_type} graph")

        # Sort findings by severity (Critical first)
        all_findings.sort(key=lambda x: self._get_severity_priority(x.severity), reverse=True)

        # Generate comprehensive report
        report = {
            "scanId": self._get_scan_id(),
            "timestamp": self._get_timestamp(),
            "summary": {
                "totalIssues": len(all_findings),
                "bySeverity": {
                    severity: sum(1 for v in all_findings if v.severity == severity)
                    for severity in ["Critical", "High", "Medium", "Low"]
                },
                "byCategory": dict(rule_stats),
                "rulesEvaluated": len(self.rules) * len(self.graphs),  # Reflect multi-graph evaluation
                "graphsAnalyzed": list(self.graphs.keys())
            },
            "vulnerabilities": [
                {
                    "ruleId": v.rule_id,
                    "category": v.category,
                    "severity": v.severity,
                    "location": v.location,
                    "details": v.details,
                    "remediation": v.remediation,
                    "context": v.context
                }
                for v in findings
            ]
        }

        # Save report
        output_path = self.config.get("output_path", "report.json")
        try:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Vulnerability report saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")

        return report

        # Save report
        output_path = self.config.get("output_path", "vulnerability_report.json")
        try:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Vulnerability report saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")

        return report

    def _get_scan_id(self) -> str:
        """Get scan ID from graphs or generate one"""
        for graph in self.graphs.values():
            if "scanId" in graph:
                return graph["scanId"]
        return f"scan_{hash(str(self.graphs.keys()))}"

    def _get_timestamp(self) -> int:
        """Get timestamp from graphs or current time"""
        import time
        for graph in self.graphs.values():
            if "timestamp" in graph:
                return graph["timestamp"]
        return int(time.time())

    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics"""
        return {
            "rules_loaded": len(self.rules),
            "graphs_loaded": len(self.graphs),
            "rules_by_category": {
                category: len([r for r in self.rules if category in r.category])
                for category in set(r.category for r in self.rules)
            },
            "rules_by_severity": {
                severity: len([r for r in self.rules if r.severity == severity])
                for severity in set(r.severity for r in self.rules)
            },
            "rules_by_graph": {
                graph: len([r for r in self.rules if r.graph == graph])
                for graph in set(r.graph for r in self.rules)
            }
        }

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced OWASP Top 10 Vulnerability Detector")
    parser.add_argument("--config", default="config.yaml", help="Configuration file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--stats", action="store_true", help="Show detector statistics")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        detector = EnhancedVulnerabilityDetector(args.config)
        
        if args.stats:
            stats = detector.get_statistics()
            print("Detector Statistics:")
            print(json.dumps(stats, indent=2))
        
        report = detector.analyze()
        
        print(f"\nScan completed!")
        print(f"Total issues found: {report['summary']['totalIssues']}")
        print(f"By severity: {report['summary']['bySeverity']}")
        print(f"Report saved to: {detector.config.get('output_path', 'vulnerability_report.json')}")
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
