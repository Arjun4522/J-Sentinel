from enum import Enum
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict
from networkx import DiGraph

class NodeType(str, Enum):
    METHOD = "METHOD"
    PARAMETER = "PARAMETER"
    VARIABLE = "LOCAL_VARIABLE"
    CALL = "METHOD_CALL"
    LITERAL = "STRING_LITERAL"
    ASSIGNMENT = "ASSIGNMENT"
    FIELD = "FIELD"
    FILE = "FILE"
    CLASS = "CLASS"
    OBJECT_CREATION = "OBJECT_CREATION"
    TYPE_CATCH_CALL = "TYPE_CATCH_CALL"
    TRY_CATCH_BLOCK = "TRY_CATCH_BLOCK"
    BINARY_EXPRESSION = "BINARY_EXPRESSION"
    IMPORT = "IMPORT"
    IF_STATEMENT = "IF_STATEMENT"
    WHILE_LOOP = "WHILE_LOOP"
    FIELD_ACCESS = "FIELD_ACCESS"

class EdgeType(str, Enum):
    DATA_FLOW = "DATA_FLOW"
    CONTROL_FLOW = "CONTROL_FLOW"
    DECLARES = "DECLARES"
    CONTAINS = "CONTAINS"
    INVOKES = "INVOKES"
    ACCESSES = "ACCESSES"
    CONTAINS_EXPRESSION = "CONTAINS_EXPRESSION"
    CONTAINS_ASSIGNMENT = "CONTAINS_ASSIGNMENT"
    CONTAINS_LITERAL = "CONTAINS_LITERAL"
    CONTAINS_CONTROL_FLOW = "CONTAINS_CONTROL_FLOW"
    CONTAINS_EXCEPTION_HANDLING = "CONTAINS_EXCEPTION_HANDLING"
    IMPORTS = "IMPORTS"

class TaintLabel(str, Enum):
    UNSAFE_INPUT = "UNSAFE_INPUT"
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"

class CodeNode(BaseModel):
    id: int
    type: NodeType
    name: Optional[str] = None
    data_type: Optional[str] = None
    value: Optional[str] = None

class CodeEdge(BaseModel):
    source: int
    target: int
    type: EdgeType

class CodeGraph(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    nodes: Dict[int, CodeNode]
    edges: List[CodeEdge]
    nx_graph: Optional[DiGraph] = None  # NetworkX representation

    def build_nx_graph(self):
        self.nx_graph = DiGraph()
        for node in self.nodes.values():
            self.nx_graph.add_node(node.id, **node.model_dump())
        for edge in self.edges:
            self.nx_graph.add_edge(edge.source, edge.target, type=edge.type)