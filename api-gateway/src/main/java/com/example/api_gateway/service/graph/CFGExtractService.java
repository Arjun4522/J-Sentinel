package com.example.api_gateway.service;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class CFGExtractService {

    private static final Logger logger = LoggerFactory.getLogger(CFGExtractService.class);
    private final GraphStorageService graphStorageService;

    public CFGExtractService(GraphStorageService graphStorageService) {
        this.graphStorageService = graphStorageService;
    }

    public JSONObject extractCFG(String scanId) {
        logger.info("Extracting CFG for scanId: {}", scanId);
        JSONObject codeGraph = graphStorageService.getGraph(scanId);
        if (codeGraph == null) {
            logger.warn("No code graph found for scanId: {}", scanId);
            return null;
        }

        JSONObject cfg = new JSONObject();
        cfg.put("scanId", scanId);
        cfg.put("type", "ControlFlowGraph");

        JSONArray cfgNodes = new JSONArray();
        JSONArray cfgEdges = new JSONArray();
        cfg.put("nodes", cfgNodes);
        cfg.put("edges", cfgEdges);

        // Extract control flow-related nodes
        JSONArray nodes = codeGraph.getJSONArray("nodes");
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            String nodeType = node.getString("type");
            if (nodeType.equals("IF_STATEMENT") || nodeType.equals("FOR_LOOP") ||
                nodeType.equals("WHILE_LOOP") || nodeType.equals("FOR_EACH_LOOP") ||
                nodeType.equals("METHOD") || nodeType.equals("CONSTRUCTOR") ||
                nodeType.equals("RETURN_STATEMENT") || nodeType.equals("TRY_CATCH_BLOCK")) {
                cfgNodes.put(node);
            }
        }

        // Extract control flow-related edges
        JSONArray edges = codeGraph.getJSONArray("edges");
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            String edgeType = edge.getString("type");
            if (edgeType.equals("CONTAINS_CONTROL_FLOW") || edgeType.equals("CONTAINS") ||
                edgeType.equals("CONTAINS_EXCEPTION")) {
                cfgEdges.put(edge);
            }
        }

        JSONObject stats = new JSONObject();
        stats.put("totalNodes", cfgNodes.length());
        stats.put("totalEdges", cfgEdges.length());
        cfg.put("statistics", stats);

        logger.info("CFG extracted for scanId: {}, nodes: {}, edges: {}", scanId, cfgNodes.length(), cfgEdges.length());
        return cfg;
    }
}