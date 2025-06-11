import { useState } from "react";
import { Network, Eye, Download, Code, GitBranch } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import type { ControlFlowGraph, DataFlowGraph } from "@/lib/graph-generator";

interface GraphViewerProps {
  cfg?: ControlFlowGraph;
  dfg?: DataFlowGraph;
  filename: string;
}

export default function GraphViewer({ cfg, dfg, filename }: GraphViewerProps) {
  const [selectedTab, setSelectedTab] = useState("cfg");
  const { toast } = useToast();

  const downloadGraph = (graph: any, type: string) => {
    try {
      const graphData = {
        ...graph,
        exportedAt: new Date().toISOString(),
        exportType: type,
        filename
      };

      const blob = new Blob([JSON.stringify(graphData, null, 2)], {
        type: 'application/json'
      });
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}-${type}-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast({
        title: "Graph Downloaded",
        description: `${type.toUpperCase()} graph exported successfully.`
      });
    } catch (error) {
      toast({
        title: "Download Failed",
        description: "Failed to download the graph data.",
        variant: "destructive"
      });
    }
  };

  const downloadDotFormat = (graph: any, type: string) => {
    try {
      let dotContent = `digraph ${type} {\n`;
      dotContent += `  rankdir=TB;\n`;
      dotContent += `  node [shape=box, style=rounded];\n\n`;

      // Add nodes
      graph.nodes.forEach((node: any) => {
        const label = node.label || node.type || 'Unknown';
        const escapedLabel = label.replace(/"/g, '\\"');
        const color = node.metadata?.isSpecial ? 'lightblue' : 'lightgray';
        dotContent += `  "${node.id}" [label="${escapedLabel}", fillcolor=${color}, style=filled];\n`;
      });

      dotContent += '\n';

      // Add edges
      graph.edges.forEach((edge: any) => {
        const label = edge.label || edge.type || '';
        dotContent += `  "${edge.source}" -> "${edge.target}"`;
        if (label) {
          dotContent += ` [label="${label}"]`;
        }
        dotContent += ';\n';
      });

      dotContent += '}';

      const blob = new Blob([dotContent], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}-${type}.dot`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast({
        title: "DOT File Downloaded",
        description: `${type.toUpperCase()} graph exported as DOT format for Graphviz.`
      });
    } catch (error) {
      toast({
        title: "Export Failed",
        description: "Failed to export the graph as DOT format.",
        variant: "destructive"
      });
    }
  };

  const renderGraphStats = (graph: any, type: string) => (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      <div className="text-center">
        <div className="text-2xl font-bold text-primary">{graph.nodes.length}</div>
        <div className="text-sm text-gray-600">Nodes</div>
      </div>
      <div className="text-center">
        <div className="text-2xl font-bold text-primary">{graph.edges.length}</div>
        <div className="text-sm text-gray-600">Edges</div>
      </div>
      {type === 'CFG' && (
        <>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">1</div>
            <div className="text-sm text-gray-600">Entry Point</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">1</div>
            <div className="text-sm text-gray-600">Exit Point</div>
          </div>
        </>
      )}
      {type === 'DFG' && (
        <>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">
              {graph.variables instanceof Map 
                ? graph.variables.size 
                : Object.keys(graph.variables || {}).length}
            </div>
            <div className="text-sm text-gray-600">Variables</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">
              {graph.variables instanceof Map
                ? Array.from(graph.variables.values()).filter((v: any) => v.definitionSites?.length > 0).length
                : Object.values(graph.variables || {}).filter((v: any) => v.definitionSites?.length > 0).length}
            </div>
            <div className="text-sm text-gray-600">Definitions</div>
          </div>
        </>
      )}
    </div>
  );

  const renderNodeList = (nodes: any[]) => (
    <div className="space-y-2 max-h-64 overflow-y-auto">
      {nodes.map((node) => (
        <div key={node.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
          <div className="flex-1">
            <div className="flex items-center space-x-2">
              <Badge variant="outline" className="text-xs">
                {node.type}
              </Badge>
              <span className="font-medium text-sm">{node.label}</span>
            </div>
            {node.line && (
              <div className="text-xs text-gray-500 mt-1">
                Line {node.line}{node.column && `, Column ${node.column}`}
              </div>
            )}
            {node.code && (
              <div className="text-xs text-gray-700 mt-1 font-mono bg-gray-100 p-1 rounded">
                {node.code.length > 50 ? `${node.code.substring(0, 50)}...` : node.code}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );

  const renderVariableList = (variables: Map<string, any> | Record<string, any>) => (
    <div className="space-y-2 max-h-64 overflow-y-auto">
      {(variables instanceof Map 
        ? Array.from(variables.entries()) 
        : Object.entries(variables || {})
      ).map(([name, info]) => (
        <div key={name} className="p-3 bg-gray-50 rounded-lg">
          <div className="flex items-center space-x-2 mb-2">
            <Badge variant="secondary" className="text-xs">
              {info.scope || 'local'}
            </Badge>
            <span className="font-medium">{name}</span>
            {info.type && (
              <Badge variant="outline" className="text-xs">
                {info.type}
              </Badge>
            )}
          </div>
          <div className="text-xs text-gray-600">
            <div>Definitions: {info.definitionSites?.length || 0}</div>
            <div>Uses: {info.useSites?.length || 0}</div>
          </div>
        </div>
      ))}
    </div>
  );

  if (!cfg && !dfg) {
    return (
      <Card className="bg-white rounded-xl border border-gray-200">
        <CardContent className="p-12 text-center">
          <Network className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">No Graphs Available</h3>
          <p className="text-gray-600">
            Graph generation is not available for this analysis.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-white rounded-xl border border-gray-200">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center">
            <Network className="w-5 h-5 mr-2 text-primary" />
            Code Analysis Graphs - {filename}
          </div>
          <div className="flex space-x-2">
            {cfg && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadGraph(cfg, 'cfg')}
                >
                  <Download className="w-4 h-4 mr-1" />
                  CFG JSON
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadDotFormat(cfg, 'cfg')}
                >
                  <Code className="w-4 h-4 mr-1" />
                  CFG DOT
                </Button>
              </>
            )}
            {dfg && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadGraph(dfg, 'dfg')}
                >
                  <Download className="w-4 h-4 mr-1" />
                  DFG JSON
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadDotFormat(dfg, 'dfg')}
                >
                  <GitBranch className="w-4 h-4 mr-1" />
                  DFG DOT
                </Button>
              </>
            )}
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs value={selectedTab} onValueChange={setSelectedTab}>
          <TabsList className="grid w-full grid-cols-2">
            {cfg && (
              <TabsTrigger value="cfg" className="flex items-center">
                <GitBranch className="w-4 h-4 mr-2" />
                Control Flow Graph
              </TabsTrigger>
            )}
            {dfg && (
              <TabsTrigger value="dfg" className="flex items-center">
                <Network className="w-4 h-4 mr-2" />
                Data Flow Graph
              </TabsTrigger>
            )}
          </TabsList>

          {cfg && (
            <TabsContent value="cfg" className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold text-gray-900 mb-4">Control Flow Graph Statistics</h4>
                {renderGraphStats(cfg, 'CFG')}
              </div>

              <div>
                <h4 className="text-lg font-semibold text-gray-900 mb-4">
                  Graph Metadata
                </h4>
                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-600">Language:</span>
                      <span className="font-medium ml-2">{cfg.metadata.language}</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Generated:</span>
                      <span className="font-medium ml-2">
                        {new Date(cfg.metadata.generatedAt).toLocaleString()}
                      </span>
                    </div>
                    <div>
                      <span className="text-gray-600">Entry Node:</span>
                      <span className="font-medium ml-2">{cfg.entry}</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Exit Node:</span>
                      <span className="font-medium ml-2">{cfg.exit}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-lg font-semibold text-gray-900 mb-4">
                  Control Flow Nodes ({cfg.nodes.length})
                </h4>
                {renderNodeList(cfg.nodes)}
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="flex items-start">
                  <Eye className="w-5 h-5 text-blue-600 mt-0.5 mr-3" />
                  <div>
                    <h4 className="text-sm font-semibold text-blue-900 mb-1">Visualization Tip</h4>
                    <p className="text-sm text-blue-800">
                      Download the DOT format and use tools like Graphviz, yEd, or online viewers like 
                      viz.js to visualize the control flow graph structure.
                    </p>
                  </div>
                </div>
              </div>
            </TabsContent>
          )}

          {dfg && (
            <TabsContent value="dfg" className="space-y-6">
              <div>
                <h4 className="text-lg font-semibold text-gray-900 mb-4">Data Flow Graph Statistics</h4>
                {renderGraphStats(dfg, 'DFG')}
              </div>

              <div>
                <h4 className="text-lg font-semibold text-gray-900 mb-4">
                  Graph Metadata
                </h4>
                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-600">Language:</span>
                      <span className="font-medium ml-2">{dfg.metadata.language}</span>
                    </div>
                    <div>
                      <span className="text-gray-600">Generated:</span>
                      <span className="font-medium ml-2">
                        {new Date(dfg.metadata.generatedAt).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-lg font-semibold text-gray-900 mb-4">
                  Data Flow Nodes ({dfg.nodes.length})
                </h4>
                {renderNodeList(dfg.nodes)}
              </div>

              {dfg.variables && (
                (dfg.variables instanceof Map && dfg.variables.size > 0) ||
                (!(dfg.variables instanceof Map) && Object.keys(dfg.variables).length > 0)
              ) && (
                <div>
                  <h4 className="text-lg font-semibold text-gray-900 mb-4">
                    Variable Analysis ({dfg.variables instanceof Map 
                      ? dfg.variables.size 
                      : Object.keys(dfg.variables || {}).length})
                  </h4>
                  {renderVariableList(dfg.variables)}
                </div>
              )}

              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-start">
                  <Network className="w-5 h-5 text-green-600 mt-0.5 mr-3" />
                  <div>
                    <h4 className="text-sm font-semibold text-green-900 mb-1">Data Flow Analysis</h4>
                    <p className="text-sm text-green-800">
                      This graph shows how data flows through your code, tracking variable definitions, 
                      uses, and dependencies. Use it to identify potential data leaks and security vulnerabilities.
                    </p>
                  </div>
                </div>
              </div>
            </TabsContent>
          )}
        </Tabs>
      </CardContent>
    </Card>
  );
}