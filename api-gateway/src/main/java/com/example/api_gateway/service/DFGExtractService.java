package com.example.api_gateway.service;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class DFGExtractService {

    private static final Logger logger = LoggerFactory.getLogger(DFGExtractService.class);
    private final GraphStorageService graphStorageService;

    public DFGExtractService(GraphStorageService graphStorageService) {
        this.graphStorageService = graphStorageService;
    }

    public JSONObject extractDFG(String scanId) {
        logger.info("Extracting DFG for scanId: {}", scanId);
        JSONObject codeGraph = graphStorageService.getGraph(scanId);
        if (codeGraph == null) {
            logger.warn("No code graph found for scanId: {}", scanId);
            return null;
        }

        JSONObject dfg = new JSONObject();
        dfg.put("scanId", scanId);
        dfg.put("type", "DataFlowGraph");

        JSONArray dfgNodes = new JSONArray();
        JSONArray dfgEdges = new JSONArray();
        dfg.put("nodes", dfgNodes);
        dfg.put("edges", dfgEdges);

        // Extract data flow-related nodes
        JSONArray nodes = codeGraph.getJSONArray("nodes");
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            String nodeType = node.getString("type");
            if (nodeType.equals("LOCAL_VARIABLE") || nodeType.equals("PARAMETER") ||
                nodeType.equals("FIELD") || nodeType.equals("ASSIGNMENT") ||
                nodeType.equals("METHOD_CALL") || nodeType.equals("FIELD_ACCESS")) {
                dfgNodes.put(node);
            }
        }

        // Extract data flow-related edges
        JSONArray edges = codeGraph.getJSONArray("edges");
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            String edgeType = edge.getString("type");
            if (edgeType.equals("DATA_FLOW") || edgeType.equals("DECLARES") ||
                edgeType.equals("INVOKES") || edgeType.equals("ACCESSES")) {
                dfgEdges.put(edge);
            }
        }

        JSONObject stats = new JSONObject();
        stats.put("totalNodes", dfgNodes.length());
        stats.put("totalEdges", dfgEdges.length());
        dfg.put("statistics", stats);

        logger.info("DFG extracted for scanId: {}, nodes: {}, edges: {}", scanId, dfgNodes.length(), dfgEdges.length());
        return dfg;
    }
}