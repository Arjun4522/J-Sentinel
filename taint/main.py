import json
import sys
import os
from typing import Dict, Any

# Add current directory to path to import local modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import CodeGraph, CodeNode, CodeEdge
from engine import TaintAnalyzer

def load_graph(json_path: str) -> CodeGraph:
    with open(json_path) as f:
        data = json.load(f)
        nodes = {n["id"]: CodeNode(**n) for n in data["nodes"]}
        edges = [CodeEdge(**e) for e in data["edges"]]
        return CodeGraph(nodes=nodes, edges=edges)

def analyze_code(graph_path: str, rules_path: str) -> Dict[str, Any]:
    graph = load_graph(graph_path)
    analyzer = TaintAnalyzer(graph, rules_path)
    findings = analyzer.analyze()
    
    return {
        "stats": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "tainted_nodes": len(analyzer.taint_map),
            "vulnerabilities": len(findings)
        },
        "findings": findings
    }

def main():
    if len(sys.argv) != 3:
        print("Usage: python main.py <graph_json_path> <rules_yaml_path>")
        sys.exit(1)
    
    try:
        result = analyze_code(sys.argv[1], sys.argv[2])
        print(json.dumps(result, indent=2))
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()