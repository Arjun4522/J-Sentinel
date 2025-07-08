import yaml
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set

# Import from local models file
from models import CodeGraph, CodeNode, EdgeType, TaintLabel

class TaintAnalyzer:
    def __init__(self, graph: CodeGraph, rules_path: str):
        self.graph = graph
        self.graph.build_nx_graph()
        self.rules = self._load_rules(rules_path)
        self.taint_map: Dict[int, Set[TaintLabel]] = {}
        self.sanitizers = set()

    def _load_rules(self, path: str) -> dict:
        with open(path) as f:
            rules = yaml.safe_load(f)
            self.sanitizers = set(rules.get("sanitizers", []))
            return rules

    def analyze(self) -> List[dict]:
        # Parallel source identification
        with ThreadPoolExecutor() as executor:
            sources = list(executor.map(
                self._identify_sources,
                self.rules["sources"]
            ))
        
        # Propagate taint from all sources
        for source_nodes in sources:
            for node in source_nodes:
                self._propagate(node.id, {TaintLabel.UNSAFE_INPUT})

        # Check sinks
        findings = []
        for sink_rule in self.rules["sinks"]:
            findings.extend(self._check_sinks(sink_rule))
        
        return findings

    def _identify_sources(self, rule: dict) -> List[CodeNode]:
        return [
            node for node in self.graph.nodes.values()
            if self._matches_rule(node, rule)
        ]

    def _matches_rule(self, node: CodeNode, rule: dict) -> bool:
        if node.type.value not in rule["types"]:
            return False
        if "names" in rule and node.name not in rule["names"]:
            return False
        return True

    def _propagate(self, node_id: int, taints: Set[TaintLabel]):
        if node_id in self.taint_map:
            if taints.issubset(self.taint_map[node_id]):
                return  # Already processed
            self.taint_map[node_id].update(taints)
        else:
            self.taint_map[node_id] = taints.copy()

        node = self.graph.nodes[node_id]
        
        # Handle sanitization
        if node.name in self.sanitizers:
            self.taint_map[node_id].clear()
            return

        # Propagate through edges
        for successor in self.graph.nx_graph.successors(node_id):
            edge_type = self.graph.nx_graph.edges[node_id, successor]["type"]
            
            if edge_type == EdgeType.DATA_FLOW:
                self._propagate(successor, taints)
            elif edge_type == EdgeType.CONTROL_FLOW:
                self._propagate(successor, taints - {TaintLabel.UNSAFE_INPUT})

    def _check_sinks(self, rule: dict) -> List[dict]:
        findings = []
        for node in self.graph.nodes.values():
            if not self._matches_rule(node, rule):
                continue
            if node.id not in self.taint_map:
                continue
            
            findings.append({
                "type": rule["vulnerability"],
                "node": node.model_dump(),
                "taint_path": self._backtrack(node.id),
                "severity": rule.get("severity", "high")
            })
        return findings

    def _backtrack(self, sink_id: int) -> List[dict]:
        path = []
        current = sink_id
        
        while current is not None:
            path.append(self.graph.nodes[current].model_dump())
            predecessors = list(self.graph.nx_graph.predecessors(current))
            tainted_preds = [p for p in predecessors 
                           if p in self.taint_map]
            
            if not tainted_preds:
                break
                
            current = tainted_preds[0]  # Follow first tainted predecessor
        
        return path[::-1]  # Reverse to show source-to-sink