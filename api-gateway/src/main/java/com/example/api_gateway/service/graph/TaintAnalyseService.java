package com.example.api_gateway.service;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class TaintAnalyseService {

    private static final Logger logger = LoggerFactory.getLogger(TaintAnalyseService.class);
    private final GraphStorageService graphStorageService;

    private static final Set<String> TAINT_SOURCES = new HashSet<>(Arrays.asList(
        "getParameter", "readLine", "getInputStream", "nextLine", "read"
    ));
    private static final Set<String> SENSITIVE_SINKS = new HashSet<>(Arrays.asList(
        "executeQuery", "println", "print", "info", "debug", "warn", "error", "log", "severe", "warning"
    ));

    public TaintAnalyseService(GraphStorageService graphStorageService) {
        this.graphStorageService = graphStorageService;
    }

    public JSONObject analyzeCodeGraph(String scanId) {
        logger.info("Starting taint analysis for scanId: {}", scanId);
        JSONObject codeGraph = graphStorageService.getGraph(scanId);
        if (codeGraph == null) {
            logger.warn("No code graph found for scanId: {}", scanId);
            return null;
        }

        JSONArray taintedPaths = analyzeGraph(codeGraph);
        JSONObject result = new JSONObject();
        result.put("scanId", scanId);
        result.put("timestamp", System.currentTimeMillis());
        result.put("taintedPaths", taintedPaths);
        logger.info("Taint analysis completed for scanId: {}, found {} tainted paths", scanId, taintedPaths.length());
        return result;
    }

    private JSONArray analyzeGraph(JSONObject codeGraph) {
        JSONArray nodes = codeGraph.getJSONArray("nodes");
        JSONArray edges = codeGraph.getJSONArray("edges");
        JSONArray taintedPaths = new JSONArray();

        Map<Integer, JSONObject> nodeMap = new HashMap<>();
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            nodeMap.put(node.getInt("id"), node);
        }

        Map<Integer, Set<Integer>> adjacencyMap = buildAdjacencyMap(edges);
        Map<Integer, Set<Integer>> dataFlowMap = buildDataFlowMap(edges, nodeMap);

        List<Integer> sources = new ArrayList<>();
        List<Integer> sinks = new ArrayList<>();
        Map<Integer, Set<Integer>> taintedVariables = new HashMap<>();

        for (JSONObject node : nodeMap.values()) {
            String type = node.getString("type");
            if (type.equals("METHOD_CALL") && TAINT_SOURCES.contains(node.getString("name"))) {
                sources.add(node.getInt("id"));
                logger.debug("Found taint source (method call): {} (ID: {})", node.getString("name"), node.getInt("id"));
            } else if (type.equals("PARAMETER")) {
                sources.add(node.getInt("id"));
                logger.debug("Found taint source (parameter): {} (ID: {})", node.getString("name"), node.getInt("id"));
            }
        }

        for (JSONObject node : nodeMap.values()) {
            if (node.getString("type").equals("METHOD_CALL") && SENSITIVE_SINKS.contains(node.getString("name"))) {
                boolean isTainted = false;
                if (node.has("arguments") && node.getInt("arguments") > 0) {
                    for (Integer sourceId : sources) {
                        if (findReachableNodes(sourceId, dataFlowMap).contains(node.getInt("id"))) {
                            isTainted = true;
                            break;
                        }
                    }
                }
                if (isTainted) {
                    sinks.add(node.getInt("id"));
                    logger.debug("Found sensitive sink: {} (ID: {})", node.getString("name"), node.getInt("id"));
                }
            }
        }

        for (JSONObject node : nodeMap.values()) {
            if (node.getString("type").equals("LOCAL_VARIABLE") && node.has("initializer")) {
                String initializer = node.getString("initializer");
                for (Integer sourceId : sources) {
                    JSONObject sourceNode = nodeMap.get(sourceId);
                    if (initializer.contains(sourceNode.optString("name", ""))) {
                        taintedVariables.computeIfAbsent(node.getInt("id"), k -> new HashSet<>()).add(sourceId);
                        logger.debug("Tainted variable: {} (ID: {}) from source ID: {}", node.getString("name"), node.getInt("id"), sourceId);
                    }
                }
            }
        }

        for (Integer sourceId : sources) {
            JSONObject sourceNode = nodeMap.get(sourceId);
            logger.debug("Analyzing paths from source: {} (ID: {})", sourceNode.getString("name"), sourceId);
            Set<Integer> reachableSinks = findReachableSinks(sourceId, sinks, dataFlowMap, nodeMap);

            for (Integer sinkId : reachableSinks) {
                JSONObject sinkNode = nodeMap.get(sinkId);
                List<Integer> path = findPath(sourceId, sinkId, adjacencyMap, dataFlowMap, nodeMap);

                if (path != null) {
                    JSONObject pathObj = new JSONObject();
                    JSONArray pathNodes = new JSONArray();

                    for (Integer nodeId : path) {
                        JSONObject node = nodeMap.get(nodeId);
                        JSONObject pathNode = new JSONObject();
                        pathNode.put("id", nodeId);
                        pathNode.put("type", node.getString("type"));
                        pathNode.put("name", node.optString("name", ""));
                        if (node.has("scope")) {
                            pathNode.put("scope", node.getString("scope"));
                        }
                        pathNodes.put(pathNode);
                    }

                    String severity = determineSeverity(sourceNode, sinkNode, nodeMap, dataFlowMap);
                    pathObj.put("pathNodes", pathNodes);
                    pathObj.put("sourceId", sourceId);
                    pathObj.put("sinkId", sinkId);
                    pathObj.put("sourceName", sourceNode.getString("name"));
                    pathObj.put("sinkName", sinkNode.getString("name"));
                    pathObj.put("vulnerability", "Potential taint flow from " + sourceNode.getString("name") + " to " + sinkNode.getString("name"));
                    pathObj.put("severity", severity);

                    taintedPaths.put(pathObj);
                    logger.debug("Found taint path: {}", path);
                }
            }
        }

        return taintedPaths;
    }

    private Map<Integer, Set<Integer>> buildAdjacencyMap(JSONArray edges) {
        Map<Integer, Set<Integer>> adjacencyMap = new HashMap<>();
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            int source = edge.getInt("source");
            int target = edge.getInt("target");
            String type = edge.getString("type");

            if (type.equals("CONTAINS") || type.equals("INVOKES") ||
                type.equals("CONTAINS_CONTROL_FLOW") ||
                type.equals("CONTAINS_EXPRESSION") || type.equals("DATA_FLOW")) {
                adjacencyMap.computeIfAbsent(source, k -> new HashSet<>()).add(target);
                if (type.equals("CONTAINS_EXPRESSION") || type.equals("INVOKES") || type.equals("DATA_FLOW")) {
                    adjacencyMap.computeIfAbsent(target, k -> new HashSet<>()).add(source);
                }
            }
        }
        return adjacencyMap;
    }

    private Map<Integer, Set<Integer>> buildDataFlowMap(JSONArray edges, Map<Integer, JSONObject> nodeMap) {
        Map<Integer, Set<Integer>> dataFlowMap = new HashMap<>();
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            if (edge.getString("type").equals("DATA_FLOW")) {
                int source = edge.getInt("source");
                int target = edge.getInt("target");
                dataFlowMap.computeIfAbsent(source, k -> new HashSet<>()).add(target);
                dataFlowMap.computeIfAbsent(target, k -> new HashSet<>()).add(source);
            }
        }

        for (Object obj : edges) {
            JSONObject edge = (JSONObject) obj;
            if (edge.getString("type").equals("INVOKES")) {
                int source = edge.getInt("source");
                int target = edge.getInt("target");
                JSONObject targetNode = nodeMap.get(target);
                if (targetNode.getString("type").equals("METHOD_CALL")) {
                    String calledMethodName = targetNode.getString("name");
                    for (JSONObject node : nodeMap.values()) {
                        if (node.getString("type").equals("METHOD") && node.getString("name").equals(calledMethodName)) {
                            dataFlowMap.computeIfAbsent(source, k -> new HashSet<>()).add(node.getInt("id"));
                            dataFlowMap.computeIfAbsent(node.getInt("id"), k -> new HashSet<>()).add(source);
                        }
                    }
                }
            }
        }
        return dataFlowMap;
    }

    private Set<Integer> findReachableNodes(Integer sourceId, Map<Integer, Set<Integer>> adjacencyMap) {
        Set<Integer> reachable = new HashSet<>();
        Set<Integer> visited = new HashSet<>();
        Queue<Integer> queue = new LinkedList<>();

        queue.offer(sourceId);
        visited.add(sourceId);

        while (!queue.isEmpty()) {
            Integer currentId = queue.poll();
            reachable.add(currentId);

            Set<Integer> neighbors = adjacencyMap.getOrDefault(currentId, new HashSet<>());
            for (Integer neighbor : neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    queue.offer(neighbor);
                }
            }
        }
        return reachable;
    }

    private Set<Integer> findReachableSinks(Integer sourceId, List<Integer> sinks,
                                           Map<Integer, Set<Integer>> dataFlowMap,
                                           Map<Integer, JSONObject> nodeMap) {
        Set<Integer> reachableSinks = new HashSet<>();
        Set<Integer> visited = new HashSet<>();
        Queue<Integer> queue = new LinkedList<>();

        queue.offer(sourceId);
        visited.add(sourceId);

        while (!queue.isEmpty()) {
            Integer currentId = queue.poll();

            if (sinks.contains(currentId) && !currentId.equals(sourceId)) {
                reachableSinks.add(currentId);
            }

            Set<Integer> neighbors = dataFlowMap.getOrDefault(currentId, new HashSet<>());
            for (Integer neighbor : neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    queue.offer(neighbor);
                }
            }
        }
        return reachableSinks;
    }

    private List<Integer> findPath(Integer sourceId, Integer sinkId,
                                  Map<Integer, Set<Integer>> adjacencyMap,
                                  Map<Integer, Set<Integer>> dataFlowMap,
                                  Map<Integer, JSONObject> nodeMap) {
        Map<Integer, Integer> parent = new HashMap<>();
        Set<Integer> visited = new HashSet<>();
        Queue<Integer> queue = new LinkedList<>();

        queue.offer(sourceId);
        visited.add(sourceId);
        parent.put(sourceId, null);

        while (!queue.isEmpty()) {
            Integer currentId = queue.poll();

            if (currentId.equals(sinkId)) {
                List<Integer> path = new ArrayList<>();
                Integer current = sinkId;
                while (current != null) {
                    path.add(0, current);
                    current = parent.get(current);
                }
                return path;
            }

            Set<Integer> neighbors = new HashSet<>();
            neighbors.addAll(adjacencyMap.getOrDefault(currentId, new HashSet<>()));
            neighbors.addAll(dataFlowMap.getOrDefault(currentId, new HashSet<>()));

            for (Integer neighbor : neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    parent.put(neighbor, currentId);
                    queue.offer(neighbor);
                }
            }
        }
        return null;
    }

    private String determineSeverity(JSONObject sourceNode, JSONObject sinkNode,
                                    Map<Integer, JSONObject> nodeMap,
                                    Map<Integer, Set<Integer>> dataFlowMap) {
        boolean isStaticString = sinkNode.has("arguments") && sinkNode.getInt("arguments") == 1 &&
            nodeMap.values().stream().anyMatch(node ->
                node.getString("type").equals("STRING_LITERAL") &&
                dataFlowMap.getOrDefault(sinkNode.getInt("id"), new HashSet<>()).contains(node.getInt("id")));

        if (isStaticString) {
            return "LOW";
        }
        if (SENSITIVE_SINKS.contains(sinkNode.getString("name")) &&
            (sourceNode.getString("type").equals("PARAMETER") || TAINT_SOURCES.contains(sourceNode.getString("name")))) {
            return "HIGH";
        }
        if (sinkNode.getString("name").equals("severe") || sinkNode.getString("name").equals("error")) {
            return "MEDIUM";
        }
        return "HIGH";
    }
}