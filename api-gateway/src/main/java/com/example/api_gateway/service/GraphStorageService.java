package com.example.apigateway.service;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class GraphStorageService {

    // In-memory storage for code graphs (use a database in production)
    private final Map<String, JSONObject> graphStorage = new HashMap<>();

    // Store the code graph with the scanId as the key
    public void storeGraph(String scanId, JSONObject codeGraph) {
        graphStorage.put(scanId, codeGraph);
    }

    // Retrieve the full code graph by scanId
    public JSONObject getGraph(String scanId) {
        return graphStorage.get(scanId);
    }

    // Extract CFG (Control Flow Graph) from the code graph
    public JSONObject getCFG(String scanId) {
        JSONObject codeGraph = graphStorage.get(scanId);
        if (codeGraph == null) {
            return null;
        }
        JSONObject cfg = new JSONObject();
        cfg.put("scanId", scanId);

        // Filter nodes related to control flow
        JSONArray nodes = codeGraph.getJSONArray("nodes");
        JSONArray cfgNodes = new JSONArray();
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            String type = node.getString("type");
            if (type.equals("IF_STATEMENT") || type.equals("FOR_LOOP") || type.equals("WHILE_LOOP") || type.equals("TRY_CATCH_BLOCK")) {
                cfgNodes.put(node);
            }
        }

        // Filter edges related to control flow
        JSONArray edges = codeGraph.getJSONArray("edges");
        JSONArray cfgEdges = new JSONArray();
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            if (edge.getString("type").equals("CONTAINS_CONTROL_FLOW") || edge.getString("type").equals("CONTAINS_EXCEPTION_HANDLING")) {
                cfgEdges.put(edge);
            }
        }

        cfg.put("nodes", cfgNodes);
        cfg.put("edges", cfgEdges);
        return cfg;
    }

    // Extract DFG (Data Flow Graph) from the code graph
    public JSONObject getDFG(String scanId) {
        JSONObject codeGraph = graphStorage.get(scanId);
        if (codeGraph == null) {
            return null;
        }
        JSONObject dfg = new JSONObject();
        dfg.put("scanId", scanId);

        // Filter nodes related to data flow (e.g., variables, assignments)
        JSONArray nodes = codeGraph.getJSONArray("nodes");
        JSONArray dfgNodes = new JSONArray();
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            String type = node.getString("type");
            if (type.equals("LOCAL_VARIABLE") || type.equals("PARAMETER") || type.equals("ASSIGNMENT") || type.equals("METHOD_CALL")) {
                dfgNodes.put(node);
            }
        }

        // Filter edges related to data flow
        JSONArray edges = codeGraph.getJSONArray("edges");
        JSONArray dfgEdges = new JSONArray();
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            if (edge.getString("type").equals("DATA_FLOW")) {
                dfgEdges.put(edge);
            }
        }

        dfg.put("nodes", dfgNodes);
        dfg.put("edges", dfgEdges);
        return dfg;
    }

    // Extract AST (Abstract Syntax Tree) from the code graph
    public JSONObject getAST(String scanId) {
        JSONObject codeGraph = graphStorage.get(scanId);
        if (codeGraph == null) {
            return null;
        }
        JSONObject ast = new JSONObject();
        ast.put("scanId", scanId);

        // Filter nodes for AST (all structural nodes like CLASS, METHOD, etc.)
        JSONArray nodes = codeGraph.getJSONArray("nodes");
        JSONArray astNodes = new JSONArray();
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            String type = node.getString("type");
            if (type.equals("FILE") || type.equals("CLASS") || type.equals("METHOD") || type.equals("METHOD_CALL") ||
                type.equals("PARAMETER") || type.equals("LOCAL_VARIABLE") || type.equals("BINARY_EXPRESSION") ||
                type.equals("STRING_LITERAL") || type.equals("FIELD_ACCESS")) {
                astNodes.put(node);
            }
        }

        // Filter edges for AST (structural relationships like CONTAINS, DECLARES)
        JSONArray edges = codeGraph.getJSONArray("edges");
        JSONArray astEdges = new JSONArray();
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            String type = edge.getString("type");
            if (type.equals("CONTAINS") || type.equals("DECLARES") || type.equals("INVOKES") || type.equals("CONTAINS_EXPRESSION") ||
                type.equals("CONTAINS_LITERAL") || type.equals("ACCESSES")) {
                astEdges.put(edge);
            }
        }

        ast.put("nodes", astNodes);
        ast.put("edges", astEdges);
        return ast;
    }
}