// JavaScript/TypeScript AST Parser
export interface JavaScriptAST {
  type: string;
  body: any[];
  sourceType?: string;
  range?: [number, number];
  loc?: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
}

export class JavaScriptParser {
  static parse(code: string): JavaScriptAST {
    // Simple token-based parsing for basic patterns
    // In a real implementation, you'd use a proper parser like Esprima or Acorn
    
    const lines = code.split('\n');
    const ast: JavaScriptAST = {
      type: 'Program',
      body: [],
      sourceType: 'script'
    };

    // Basic pattern detection for security analysis
    lines.forEach((line, index) => {
      const trimmedLine = line.trim();
      
      // Function declarations
      if (trimmedLine.includes('function ') || trimmedLine.includes('=> ')) {
        ast.body.push({
          type: 'FunctionDeclaration',
          line: index + 1,
          code: trimmedLine
        });
      }
      
      // Variable declarations
      if (trimmedLine.includes('var ') || trimmedLine.includes('let ') || trimmedLine.includes('const ')) {
        ast.body.push({
          type: 'VariableDeclaration',
          line: index + 1,
          code: trimmedLine
        });
      }
      
      // Method calls
      if (trimmedLine.includes('(') && trimmedLine.includes(')')) {
        ast.body.push({
          type: 'CallExpression',
          line: index + 1,
          code: trimmedLine
        });
      }
    });

    return ast;
  }

  static generateCFG(ast: JavaScriptAST): any {
    // Generate Control Flow Graph
    const cfg = {
      nodes: [],
      edges: [],
      entry: null,
      exit: null
    };

    ast.body.forEach((node, index) => {
      cfg.nodes.push({
        id: index,
        type: node.type,
        line: node.line,
        code: node.code
      });
    });

    // Connect sequential nodes
    for (let i = 0; i < cfg.nodes.length - 1; i++) {
      cfg.edges.push({
        from: i,
        to: i + 1,
        type: 'sequential'
      });
    }

    return cfg;
  }

  static generateDFG(ast: JavaScriptAST): any {
    // Generate Data Flow Graph
    const dfg = {
      nodes: [],
      edges: [],
      variables: new Map()
    };

    ast.body.forEach((node, index) => {
      dfg.nodes.push({
        id: index,
        type: node.type,
        line: node.line,
        code: node.code
      });

      // Track variable definitions and uses
      if (node.type === 'VariableDeclaration') {
        const varMatch = node.code.match(/(?:var|let|const)\s+(\w+)/);
        if (varMatch) {
          const varName = varMatch[1];
          dfg.variables.set(varName, { defined: index, used: [] });
        }
      }
    });

    return dfg;
  }
}
