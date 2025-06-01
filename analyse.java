import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;

public class analyse_test {
    private static String apiEndpoint = "http://localhost:8080/api/graph";
    private static String outputPath = "taint_analysis.json";
    private static String scanId = "";
    private static String apiUser = "user";
    private static String apiPassword = "secret";

    private static final Set<String> TAINT_SOURCES = new HashSet<>(Arrays.asList(
        "getParameter", "readLine", "getInputStream", "nextLine", "read"
    ));
    private static final Set<String> SENSITIVE_SINKS = new HashSet<>(Arrays.asList(
        "executeQuery", "println", "print", "info", "debug", "warn", "error", "log", "severe", "warning"
    ));

    public static void main(String[] args) throws IOException {
        parseArguments(args);
        if (scanId.isEmpty()) {
            System.err.println("Error: --scanId is required");
            return;
        }
        JSONObject codeGraph = readCodeGraph();
        if (codeGraph == null) {
            System.err.println("Error: Could not read code graph from API");
            return;
        }
        JSONArray taintedPaths = analyzeCodeGraph(codeGraph);
        JSONObject result = new JSONObject();
        result.put("scanId", codeGraph.getString("scanId"));
        result.put("timestamp", System.currentTimeMillis());
        result.put("taintedPaths", taintedPaths);
        saveResults(result);
        System.out.println("Taint analysis completed. Results saved to " + outputPath);
        System.out.println("Found " + taintedPaths.length() + " tainted paths");
    }

    private static void parseArguments(String[] args) {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--endpoint":
                    if (i + 1 < args.length) {
                        apiEndpoint = args[++i];
                    }
                    break;
                case "--output":
                    if (i + 1 < args.length) {
                        outputPath = args[++i];
                    }
                    break;
                case "--scanId":
                    if (i + 1 < args.length) {
                        scanId = args[++i];
                    }
                    break;
                case "--user":
                    if (i + 1 < args.length) {
                        apiUser = args[++i];
                    }
                    break;
                case "--password":
                    if (i + 1 < args.length) {
                        apiPassword = args[++i];
                    }
                    break;
            }
        }
    }

    private static JSONObject readCodeGraph() throws IOException {
        String url = apiEndpoint + (apiEndpoint.contains("?") ? "&" : "?") + "scanId=" + scanId;
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            String auth = (System.getenv("API_USER") != null ? System.getenv("API_USER") : apiUser) + ":" +
                          (System.getenv("API_PASSWORD") != null ? System.getenv("API_PASSWORD") : apiPassword);
            String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
            conn.setRequestProperty("Authorization", "Basic " + encodedAuth);

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                System.err.println("Failed to fetch code graph: HTTP " + responseCode);
                try (java.io.InputStream errorStream = conn.getErrorStream()) {
                    if (errorStream != null) {
                        System.err.println("Error details: " + new String(errorStream.readAllBytes()));
                    }
                }
                return null;
            }
            try (java.io.InputStream is = conn.getInputStream()) {
                String jsonText = new String(is.readAllBytes());
                return new JSONObject(jsonText);
            }
        } catch (IOException e) {
            System.err.println("Error fetching code graph from API: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static JSONArray analyzeCodeGraph(JSONObject codeGraph) {
        JSONArray nodes = codeGraph.getJSONArray("nodes");
        JSONArray edges = codeGraph.getJSONArray("edges");
        JSONArray taintedPaths = new JSONArray();

        Map<Integer, JSONObject> nodeMap = new HashMap<>();
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            int nodeId = node.getInt("id");
            nodeMap.put(nodeId, node);
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
                System.out.println("Found taint source (method call): " + node.getString("name") + " (ID: " + node.getInt("id") + ")");
            } else if (type.equals("PARAMETER")) {
                sources.add(node.getInt("id"));
                System.out.println("Found taint source (parameter): " + node.getString("name") + " (ID: " + node.getInt("id") + ")");
            }
        }

        for (JSONObject node : nodeMap.values()) {
            if (node.getString("type").equals("METHOD_CALL") && SENSITIVE_SINKS.contains(node.getString("name"))) {
                boolean isTainted = false;
                if (node.has("arguments") && node.getInt("arguments") > 0) {
                    for (Integer sourceId : sources) {
                        Set<Integer> reachableNodes = findReachableNodes(sourceId, dataFlowMap);
                        if (reachableNodes.contains(node.getInt("id"))) {
                            isTainted = true;
                            break;
                        }
                    }
                }
                if (isTainted) {
                    sinks.add(node.getInt("id"));
                    System.out.println("Found sensitive sink: " + node.getString("name") + " (ID: " + node.getInt("id") + ")");
                } else {
                    System.out.println("Excluded sink (no tainted arguments): " + node.getString("name") + " (ID: " + node.getInt("id") + ")");
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
                        System.out.println("Tainted variable: " + node.getString("name") + " (ID: " + node.getInt("id") + ") from source ID: " + sourceId);
                    }
                }
            }
        }

        for (Integer sourceId : sources) {
            JSONObject sourceNode = nodeMap.get(sourceId);
            System.out.println("Analyzing paths from source: " + sourceNode.getString("name") + " (ID: " + sourceId + ")");

            Set<Integer> reachableSinks = findReachableSinks(sourceId, sinks, dataFlowMap, nodeMap);
            System.out.println("Reachable sinks from source " + sourceId + ": " + reachableSinks);

            for (Integer sinkId : reachableSinks) {
                JSONObject sinkNode = nodeMap.get(sinkId);
                List<Integer> path = findPath(sourceId, sinkId, adjacencyMap, dataFlowMap, nodeMap);

                if (path != null) {
                    System.out.println("Found taint path: " + path);

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
                } else {
                    System.out.println("No path found from source " + sourceId + " to sink " + sinkId);
                }
            }
        }

        return taintedPaths;
    }

    private static Map<Integer, Set<Integer>> buildAdjacencyMap(JSONArray edges) {
        Map<Integer, Set<Integer>> adjacencyMap = new HashMap<>();

        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            int source = edge.getInt("source");
            int target = edge.getInt("target");
            String type = edge.getString("type");

            System.out.println("Processing edge: " + edge);
            if (type.equals("CONTAINS") || type.equals("INVOKES") || 
                type.equals("CONTAINS_CONTROL_FLOW") || 
                type.equals("CONTAINS_EXPRESSION") || 
                type.equals("DATA_FLOW")) {
                adjacencyMap.computeIfAbsent(source, k -> new HashSet<>()).add(target);
                if (type.equals("CONTAINS_EXPRESSION") || type.equals("INVOKES") || type.equals("DATA_FLOW")) {
                    adjacencyMap.computeIfAbsent(target, k -> new HashSet<>()).add(source);
                }
            }
        }

        return adjacencyMap;
    }

    private static Map<Integer, Set<Integer>> buildDataFlowMap(JSONArray edges, Map<Integer, JSONObject> nodeMap) {
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

    private static Set<Integer> findReachableNodes(Integer sourceId, Map<Integer, Set<Integer>> adjacencyMap) {
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

    private static Set<Integer> findReachableSinks(Integer sourceId, List<Integer> sinks, 
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

    private static List<Integer> findPath(Integer sourceId, Integer sinkId, 
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

    private static String determineSeverity(JSONObject sourceNode, JSONObject sinkNode, 
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

    private static void saveResults(JSONObject result) throws IOException {
        try (java.io.FileWriter file = new java.io.FileWriter(outputPath)) {
            file.write(result.toString(2));
            System.out.println("Successfully saved results to " + outputPath);
        } catch (IOException e) {
            System.err.println("Error saving results to " + outputPath + ": " + e.getMessage());
            throw e;
        }
    }
}