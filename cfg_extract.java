import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.logging.*;
import java.util.stream.Collectors;
import java.util.Base64;

public class cfg_extract {
    private static final Logger LOGGER = Logger.getLogger(cfg_extract.class.getName());
    private static String apiEndpoint = "https://localhost:8000/api/graph"; // Secure default
    private static String outputPath = "cfg.json";
    private static boolean verbose = false;

    // Node types relevant for CFG
    private static final Set<String> CFG_NODE_TYPES = new HashSet<>(Arrays.asList(
        "METHOD", "CONSTRUCTOR", "METHOD_CALL", "OBJECT_CREATION", "ASSIGNMENT",
        "BINARY_EXPRESSION", "RETURN_STATEMENT", "IF_STATEMENT", "FOR_LOOP",
        "WHILE_LOOP", "FOR_EACH_LOOP", "TRY_CATCH_BLOCK", "TYPE_CATCH_CALL",
        "LOCAL_VARIABLE", "PARAMETER", "FIELD_ACCESS"
    ));

    // Edge types relevant for CFG
    private static final Set<String> CFG_EDGE_TYPES = new HashSet<>(Arrays.asList(
        "CONTAINS_CONTROL_FLOW", "CONTAINS_EXCEPTION_HANDLING", "INVOKES", "CONTAINS"
    ));

    public static void main(String[] args) throws IOException {
        String scanId = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--endpoint":
                    if (i + 1 < args.length) apiEndpoint = validateEndpoint(args[++i]);
                    break;
                case "--scanId":
                    if (i + 1 < args.length) scanId = validateScanId(args[++i]);
                    break;
                case "--output":
                    if (i + 1 < args.length) outputPath = validateOutputPath(args[++i]);
                    break;
                case "--verbose":
                    verbose = true;
                    break;
                default:
                    LOGGER.warning("Unknown argument: " + args[i]);
            }
        }

        if (scanId == null) {
            System.err.println("Usage: java cfg_extract --scanId <scan-id> [--endpoint <url>] [--output <path>] [--verbose]");
            System.exit(1);
        }

        try {
            LOGGER.info("Fetching code graph for scanId: " + scanId);
            JSONObject codeGraph = fetchCodeGraph(scanId);
            if (codeGraph == null) {
                LOGGER.severe("Failed to fetch code graph");
                System.exit(1);
            }

            LOGGER.info("Extracting CFG from code graph");
            Map<String, Object> cfgResult = extractCFG(codeGraph);
            JSONObject cfg = (JSONObject) cfgResult.get("cfg");
            Map<Integer, JSONObject> nodeMap = (Map<Integer, JSONObject>) cfgResult.get("nodeMap");
            validateCFG(cfg, nodeMap);
            saveCFG(cfg, outputPath);
            System.out.println("CFG saved to: " + outputPath);
            LOGGER.info("CFG extraction completed. Nodes: " + cfg.getJSONArray("nodes").length() +
                        ", Edges: " + cfg.getJSONArray("edges").length());
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during CFG extraction", e);
            System.exit(1);
        }
    }

    private static String validateEndpoint(String endpoint) {
        if (!endpoint.matches("https?://[a-zA-Z0-9.:\\-/?=&]+")) {
            throw new IllegalArgumentException("Invalid API endpoint: " + endpoint);
        }
        return endpoint;
    }

    private static String validateScanId(String id) {
        if (!id.matches("[a-f0-9\\-]{36}")) {
            throw new IllegalArgumentException("Invalid scan ID format: " + id);
        }
        return id;
    }

    private static String validateOutputPath(String path) {
        if (!path.endsWith(".json") || path.contains("..")) {
            throw new IllegalArgumentException("Invalid output path: " + path);
        }
        return path;
    }

    private static JSONObject fetchCodeGraph(String scanId) throws IOException {
        String url = apiEndpoint + (apiEndpoint.contains("?") ? "&" : "?") + "scanId=" + scanId;
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Basic " + getSecureAuth());
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                String errorDetails = readErrorStream(conn.getErrorStream());
                LOGGER.severe("Failed to fetch code graph: HTTP " + responseCode + " - " + errorDetails);
                return null;
            }

            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                return new JSONObject(br.lines().collect(Collectors.joining()));
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error fetching code graph", e);
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String getSecureAuth() {
        String user = System.getenv("API_USER") != null ? System.getenv("API_USER") : "user";
        String pass = System.getenv("API_PASSWORD") != null ? System.getenv("API_PASSWORD") : "secret";
        return Base64.getEncoder().encodeToString((user + ":" + pass).getBytes());
    }

    private static String readErrorStream(InputStream errorStream) throws IOException {
        if (errorStream == null) return "No error details available";
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    public static Map<String, Object> extractCFG(JSONObject codeGraph) {
        JSONObject cfg = new JSONObject();
        cfg.put("scanId", codeGraph.getString("scanId"));
        cfg.put("type", "ControlFlowGraph");
        cfg.put("timestamp", System.currentTimeMillis());

        JSONArray cfgNodes = new JSONArray();
        JSONArray cfgEdges = new JSONArray();
        cfg.put("nodes", cfgNodes);
        cfg.put("edges", cfgEdges);

        // Build node and edge maps for efficient lookup
        Map<Integer, JSONObject> nodeMap = new HashMap<>();
        Map<Integer, Set<Integer>> methodToNodes = new HashMap<>();
        Map<String, Set<Integer>> methodNameToIds = new HashMap<>();
        JSONArray nodes = codeGraph.getJSONArray("nodes");

        // Extract relevant nodes and build maps
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            int nodeId = node.getInt("id");
            String nodeType = node.getString("type");
            if (CFG_NODE_TYPES.contains(nodeType)) {
                cfgNodes.put(node);
                nodeMap.put(nodeId, node);

                if (nodeType.equals("METHOD") || nodeType.equals("CONSTRUCTOR")) {
                    methodToNodes.computeIfAbsent(nodeId, k -> new HashSet<>()).add(nodeId);
                    String name = node.getString("name");
                    methodNameToIds.computeIfAbsent(name, k -> new HashSet<>()).add(nodeId);
                }
            }
        }

        // Extract control flow edges and infer additional edges
        JSONArray edges = codeGraph.getJSONArray("edges");
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            String edgeType = edge.getString("type");
            int source = edge.getInt("source");
            int target = edge.getInt("target");

            if (CFG_EDGE_TYPES.contains(edgeType) && nodeMap.containsKey(source) && nodeMap.containsKey(target)) {
                cfgEdges.put(edge);

                // Add method-to-nodes mapping
                if (edgeType.equals("CONTAINS") || edgeType.equals("CONTAINS_CONTROL_FLOW")) {
                    JSONObject sourceNode = nodeMap.get(source);
                    if (sourceNode != null && (sourceNode.getString("type").equals("METHOD") ||
                                               sourceNode.getString("type").equals("CONSTRUCTOR"))) {
                        methodToNodes.computeIfAbsent(source, k -> new HashSet<>()).add(target);
                    }
                }
            }
        }

        // Infer sequential edges within methods
        for (Map.Entry<Integer, Set<Integer>> entry : methodToNodes.entrySet()) {
            int methodId = entry.getKey();
            List<Integer> methodNodes = entry.getValue().stream()
                .filter(id -> !nodeMap.get(id).getString("type").equals("METHOD") &&
                              !nodeMap.get(id).getString("type").equals("CONSTRUCTOR"))
                .sorted().collect(Collectors.toList());

            for (int i = 0; i < methodNodes.size() - 1; i++) {
                JSONObject seqEdge = new JSONObject();
                seqEdge.put("source", methodNodes.get(i));
                seqEdge.put("target", methodNodes.get(i + 1));
                seqEdge.put("type", "SEQUENTIAL_FLOW");
                cfgEdges.put(seqEdge);
            }
        }

        // Infer conditional edges for IF_STATEMENT
        for (int i = 0; i < cfgNodes.length(); i++) {
            JSONObject node = cfgNodes.getJSONObject(i);
            if (node.getString("type").equals("IF_STATEMENT")) {
                int ifId = node.getInt("id");
                // Find then/else branches (approximated via CONTAINS_CONTROL_FLOW targets)
                for (int j = 0; j < edges.length(); j++) {
                    JSONObject edge = edges.getJSONObject(j);
                    if (edge.getInt("source") == ifId && edge.getString("type").equals("CONTAINS_CONTROL_FLOW")) {
                        int targetId = edge.getInt("target");
                        JSONObject condEdge = new JSONObject();
                        condEdge.put("source", ifId);
                        condEdge.put("target", targetId);
                        condEdge.put("type", node.optBoolean("hasElse", false) ? "ELSE_BRANCH" : "THEN_BRANCH");
                        cfgEdges.put(condEdge);
                    }
                }
            }
        }

        // Infer loop edges for loops
        for (int i = 0; i < cfgNodes.length(); i++) {
            JSONObject node = cfgNodes.getJSONObject(i);
            String nodeType = node.getString("type");
            if (nodeType.equals("FOR_LOOP") || nodeType.equals("WHILE_LOOP") || nodeType.equals("FOR_EACH_LOOP")) {
                int loopId = node.getInt("id");
                for (int j = 0; j < edges.length(); j++) {
                    JSONObject edge = edges.getJSONObject(j);
                    if (edge.getInt("source") == loopId && edge.getString("type").equals("CONTAINS_CONTROL_FLOW")) {
                        JSONObject loopEdge = new JSONObject();
                        loopEdge.put("source", loopId);
                        loopEdge.put("target", edge.getInt("target"));
                        loopEdge.put("type", "LOOP_BODY");
                        cfgEdges.put(loopEdge);
                    }
                }
            }
        }

        // Link method calls to method definitions
        for (int i = 0; i < cfgNodes.length(); i++) {
            JSONObject node = cfgNodes.getJSONObject(i);
            String nodeType = node.getString("type");
            if (nodeType.equals("METHOD_CALL") || nodeType.equals("OBJECT_CREATION")) {
                int callId = node.getInt("id");
                String methodName = node.getString(nodeType.equals("METHOD_CALL") ? "name" : "className");
                Set<Integer> targetIds = methodNameToIds.getOrDefault(methodName, new HashSet<>());
                for (int targetId : targetIds) {
                    JSONObject callEdge = new JSONObject();
                    callEdge.put("source", callId);
                    callEdge.put("target", targetId);
                    callEdge.put("type", "CALLS");
                    cfgEdges.put(callEdge);
                }
            }
        }

        // Link try-catch blocks to catch clauses
        for (int i = 0; i < cfgNodes.length(); i++) {
            JSONObject node = cfgNodes.getJSONObject(i);
            if (node.getString("type").equals("TRY_CATCH_BLOCK")) {
                int tryId = node.getInt("id");
                for (int j = 0; j < edges.length(); j++) {
                    JSONObject edge = edges.getJSONObject(j);
                    if (edge.getInt("source") == tryId && edge.getString("type").equals("DECLARES")) {
                        int catchId = edge.getInt("target");
                        JSONObject catchNode = nodeMap.get(catchId);
                        if (catchNode != null && catchNode.getString("type").equals("TYPE_CATCH_CALL")) {
                            JSONObject catchEdge = new JSONObject();
                            catchEdge.put("source", tryId);
                            catchEdge.put("target", catchId);
                            catchEdge.put("type", "CATCH_BRANCH");
                            cfgEdges.put(catchEdge);
                        }
                    }
                }
            }
        }

        // Compute statistics
        JSONObject stats = new JSONObject();
        stats.put("totalNodes", cfgNodes.length());
        stats.put("totalEdges", cfgEdges.length());
        stats.put("controlFlowNodes", countControlFlowNodes(cfgNodes));
        stats.put("methodCalls", countMethodCalls(cfgNodes));
        cfg.put("statistics", stats);

        if (verbose) {
            LOGGER.info("CFG Nodes: " + cfgNodes.length() + ", Edges: " + cfgEdges.length());
        }

        Map<String, Object> result = new HashMap<>();
        result.put("cfg", cfg);
        result.put("nodeMap", nodeMap);
        return result;
    }

    private static int countControlFlowNodes(JSONArray nodes) {
        int count = 0;
        for (int i = 0; i < nodes.length(); i++) {
            String type = nodes.getJSONObject(i).getString("type");
            if (type.equals("IF_STATEMENT") || type.equals("FOR_LOOP") ||
                type.equals("WHILE_LOOP") || type.equals("FOR_EACH_LOOP") ||
                type.equals("TRY_CATCH_BLOCK")) {
                count++;
            }
        }
        return count;
    }

    private static int countMethodCalls(JSONArray nodes) {
        int count = 0;
        for (int i = 0; i < nodes.length(); i++) {
            String type = nodes.getJSONObject(i).getString("type");
            if (type.equals("METHOD_CALL") || type.equals("OBJECT_CREATION")) {
                count++;
            }
        }
        return count;
    }

    private static void validateCFG(JSONObject cfg, Map<Integer, JSONObject> nodeMap) {
        JSONArray nodes = cfg.getJSONArray("nodes");
        JSONArray edges = cfg.getJSONArray("edges");
        Set<Integer> nodeIds = new HashSet<>();
        Set<Integer> referencedIds = new HashSet<>();

        for (int i = 0; i < nodes.length(); i++) {
            nodeIds.add(nodes.getJSONObject(i).getInt("id"));
        }

        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            int source = edge.getInt("source");
            int target = edge.getInt("target");
            referencedIds.add(source);
            referencedIds.add(target);
            if (!nodeIds.contains(source) || !nodeIds.contains(target)) {
                LOGGER.warning("Invalid edge: source=" + source + ", target=" + target + " not in nodes");
            }
        }

        for (int id : nodeIds) {
            if (!referencedIds.contains(id) && !nodeMap.get(id).getString("type").equals("METHOD") &&
                !nodeMap.get(id).getString("type").equals("CONSTRUCTOR")) {
                LOGGER.warning("Orphaned node detected: ID=" + id);
            }
        }

        if (nodes.length() == 0 || edges.length() == 0) {
            LOGGER.severe("Empty CFG generated");
            throw new RuntimeException("Invalid CFG: No nodes or edges");
        }
    }

    public static void saveCFG(JSONObject cfg, String outputPath) throws IOException {
        File outputFile = new File(outputPath);
        outputFile.getParentFile().mkdirs();
        try (FileWriter file = new FileWriter(outputFile)) {
            file.write(cfg.toString(2));
            LOGGER.info("CFG saved to: " + outputPath);
        }
    }
}