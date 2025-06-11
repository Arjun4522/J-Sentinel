// Graph Generation Library for SAST Analysis
export interface GraphNode {
  id: string;
  type: string;
  label: string;
  line?: number;
  column?: number;
  code?: string;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label?: string;
  metadata?: Record<string, any>;
}

export interface ControlFlowGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  entry: string;
  exit: string;
  metadata: {
    language: string;
    filename: string;
    generatedAt: string;
  };
}

export interface DataFlowGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  variables: Map<string, VariableInfo>;
  metadata: {
    language: string;
    filename: string;
    generatedAt: string;
  };
}

export interface VariableInfo {
  name: string;
  type?: string;
  definitionSites: string[];
  useSites: string[];
  scope: string;
}

export class GraphGenerator {
  static generateControlFlowGraph(ast: any, language: string, filename: string): ControlFlowGraph {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    
    let nodeCounter = 0;
    
    // Create entry and exit nodes
    const entryNode: GraphNode = {
      id: 'entry',
      type: 'entry',
      label: 'Entry',
      metadata: { isSpecial: true }
    };
    
    const exitNode: GraphNode = {
      id: 'exit',
      type: 'exit',
      label: 'Exit',
      metadata: { isSpecial: true }
    };
    
    nodes.push(entryNode, exitNode);
    
    // Process AST nodes based on language
    if (language === 'javascript' || language === 'typescript') {
      this.processJavaScriptCFG(ast, nodes, edges, nodeCounter);
    } else if (language === 'python') {
      this.processPythonCFG(ast, nodes, edges, nodeCounter);
    } else if (language === 'java') {
      this.processJavaCFG(ast, nodes, edges, nodeCounter);
    }
    
    // Connect entry to first node
    if (nodes.length > 2) {
      edges.push({
        id: `entry_to_${nodes[2].id}`,
        source: 'entry',
        target: nodes[2].id,
        type: 'control_flow',
        label: 'start'
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
  
  static generateDataFlowGraph(ast: any, language: string, filename: string): DataFlowGraph {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const variables = new Map<string, VariableInfo>();
    
    let nodeCounter = 0;
    
    // Process AST for data flow analysis
    if (language === 'javascript' || language === 'typescript') {
      this.processJavaScriptDFG(ast, nodes, edges, variables, nodeCounter);
    } else if (language === 'python') {
      this.processPythonDFG(ast, nodes, edges, variables, nodeCounter);
    } else if (language === 'java') {
      this.processJavaDFG(ast, nodes, edges, variables, nodeCounter);
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
  
  private static processJavaScriptCFG(ast: any, nodes: GraphNode[], edges: GraphEdge[], nodeCounter: number): void {
    if (!ast.body) return;
    
    let prevNodeId: string | null = null;
    
    ast.body.forEach((node: any, index: number) => {
      const nodeId = `node_${nodeCounter++}`;
      
      const cfgNode: GraphNode = {
        id: nodeId,
        type: node.type || 'statement',
        label: this.generateNodeLabel(node),
        line: node.line,
        code: node.code,
        metadata: {
          astType: node.type,
          originalIndex: index
        }
      };
      
      nodes.push(cfgNode);
      
      // Connect to previous node
      if (prevNodeId) {
        edges.push({
          id: `${prevNodeId}_to_${nodeId}`,
          source: prevNodeId,
          target: nodeId,
          type: 'control_flow',
          label: 'sequential'
        });
      }
      
      prevNodeId = nodeId;
    });
    
    // Connect last node to exit
    if (prevNodeId) {
      edges.push({
        id: `${prevNodeId}_to_exit`,
        source: prevNodeId,
        target: 'exit',
        type: 'control_flow',
        label: 'end'
      });
    }
  }
  
  private static processPythonCFG(ast: any, nodes: GraphNode[], edges: GraphEdge[], nodeCounter: number): void {
    if (!ast.body) return;
    
    let prevNodeId: string | null = null;
    
    ast.body.forEach((node: any, index: number) => {
      const nodeId = `node_${nodeCounter++}`;
      
      const cfgNode: GraphNode = {
        id: nodeId,
        type: node.type || 'statement',
        label: this.generateNodeLabel(node),
        line: node.line,
        code: node.code,
        metadata: {
          astType: node.type,
          indent: node.indent || 0,
          originalIndex: index
        }
      };
      
      nodes.push(cfgNode);
      
      if (prevNodeId) {
        edges.push({
          id: `${prevNodeId}_to_${nodeId}`,
          source: prevNodeId,
          target: nodeId,
          type: 'control_flow',
          label: 'sequential'
        });
      }
      
      prevNodeId = nodeId;
    });
    
    if (prevNodeId) {
      edges.push({
        id: `${prevNodeId}_to_exit`,
        source: prevNodeId,
        target: 'exit',
        type: 'control_flow',
        label: 'end'
      });
    }
  }
  
  private static processJavaCFG(ast: any, nodes: GraphNode[], edges: GraphEdge[], nodeCounter: number): void {
    if (!ast.classes) return;
    
    let prevNodeId: string | null = null;
    
    ast.classes.forEach((cls: any) => {
      const classNodeId = `class_${nodeCounter++}`;
      
      nodes.push({
        id: classNodeId,
        type: 'class',
        label: `Class: ${cls.name}`,
        line: cls.line,
        metadata: {
          className: cls.name,
          astType: 'ClassDeclaration'
        }
      });
      
      if (prevNodeId) {
        edges.push({
          id: `${prevNodeId}_to_${classNodeId}`,
          source: prevNodeId,
          target: classNodeId,
          type: 'control_flow',
          label: 'class_definition'
        });
      }
      
      prevNodeId = classNodeId;
      
      // Process methods
      if (cls.methods) {
        cls.methods.forEach((method: any) => {
          const methodNodeId = `method_${nodeCounter++}`;
          
          nodes.push({
            id: methodNodeId,
            type: 'method',
            label: `Method: ${method.name}`,
            line: method.line,
            code: method.code,
            metadata: {
              methodName: method.name,
              astType: 'MethodDeclaration'
            }
          });
          
          edges.push({
            id: `${classNodeId}_to_${methodNodeId}`,
            source: classNodeId,
            target: methodNodeId,
            type: 'control_flow',
            label: 'method_definition'
          });
        });
      }
    });
    
    if (prevNodeId) {
      edges.push({
        id: `${prevNodeId}_to_exit`,
        source: prevNodeId,
        target: 'exit',
        type: 'control_flow',
        label: 'end'
      });
    }
  }
  
  private static processJavaScriptDFG(ast: any, nodes: GraphNode[], edges: GraphEdge[], variables: Map<string, VariableInfo>, nodeCounter: number): void {
    if (!ast.body) return;
    
    ast.body.forEach((node: any, index: number) => {
      const nodeId = `dfg_node_${nodeCounter++}`;
      
      nodes.push({
        id: nodeId,
        type: node.type || 'statement',
        label: this.generateNodeLabel(node),
        line: node.line,
        code: node.code
      });
      
      // Track variable definitions and uses
      if (node.type === 'VariableDeclaration') {
        const varMatch = node.code?.match(/(?:var|let|const)\s+(\w+)/);
        if (varMatch) {
          const varName = varMatch[1];
          variables.set(varName, {
            name: varName,
            definitionSites: [nodeId],
            useSites: [],
            scope: 'local'
          });
        }
      }
    });
  }
  
  private static processPythonDFG(ast: any, nodes: GraphNode[], edges: GraphEdge[], variables: Map<string, VariableInfo>, nodeCounter: number): void {
    if (!ast.body) return;
    
    ast.body.forEach((node: any, index: number) => {
      const nodeId = `dfg_node_${nodeCounter++}`;
      
      nodes.push({
        id: nodeId,
        type: node.type || 'statement',
        label: this.generateNodeLabel(node),
        line: node.line,
        code: node.code
      });
      
      // Track variable assignments
      if (node.type === 'Assign') {
        const varMatch = node.code?.match(/(\w+)\s*=/);
        if (varMatch) {
          const varName = varMatch[1];
          variables.set(varName, {
            name: varName,
            definitionSites: [nodeId],
            useSites: [],
            scope: 'local'
          });
        }
      }
    });
  }
  
  private static processJavaDFG(ast: any, nodes: GraphNode[], edges: GraphEdge[], variables: Map<string, VariableInfo>, nodeCounter: number): void {
    if (!ast.classes) return;
    
    ast.classes.forEach((cls: any) => {
      // Process fields
      if (cls.fields) {
        cls.fields.forEach((field: any) => {
          const nodeId = `dfg_field_${nodeCounter++}`;
          
          nodes.push({
            id: nodeId,
            type: 'field',
            label: `Field Declaration`,
            line: field.line,
            code: field.code
          });
          
          const fieldMatch = field.code?.match(/(\w+)\s+(\w+)/);
          if (fieldMatch) {
            const fieldName = fieldMatch[2];
            variables.set(fieldName, {
              name: fieldName,
              type: fieldMatch[1],
              definitionSites: [nodeId],
              useSites: [],
              scope: 'class'
            });
          }
        });
      }
    });
  }
  
  private static generateNodeLabel(node: any): string {
    if (node.name) {
      return `${node.type}: ${node.name}`;
    }
    if (node.code) {
      return node.code.length > 30 
        ? `${node.code.substring(0, 30)}...`
        : node.code;
    }
    return node.type || 'Unknown';
  }
}
