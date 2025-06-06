import com.github.javaparser.ast.Node;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.regex.Pattern;
import java.util.Base64;

// Production-grade taint analyzer with precise, path-sensitive, sink-aware taint analysis
public class analyse {
    private static final Logger LOGGER = Logger.getLogger(analyse.class.getName());

    // Configurable properties
    private static String apiEndpoint = "http://localhost:8080/api/graph";
    private static String outputPath = "taint_analysis.json";
    private static String scanId = "";
    private static String apiUser = "user";
    private static String apiPassword = "secret";
    private static boolean verbose = false;

    // Analysis constraints for precision and performance
    private static final int MAX_PATH_LENGTH = 25;
    private static final int MAX_PATHS_PER_SOURCE = 10;
    private static final double MIN_CONFIDENCE_THRESHOLD = 0.95; // Targeting >95% accuracy
    private static final double SANITIZER_CONFIDENCE_REDUCTION = 0.05;
    private static final double VALIDATION_CONFIDENCE_BOOST = 0.1;

    // Taint sources (aligned with OWASP Top 10)
    private static final Map<String, TaintSourceInfo> TAINT_SOURCES = new HashMap<>();
    // Sensitive sinks
    private static final Map<String, SinkInfo> SENSITIVE_SINKS = new HashMap<>();
    // Sanitization and validation methods
    private static final Set<String> SANITIZATION_METHODS = new HashSet<>();
    private static final Set<String> VALIDATION_METHODS = new HashSet<>();
    // Confidence modifiers for transformations
    private static final Map<String, Double> CONFIDENCE_MODIFIERS = new HashMap<>();
    private static final Pattern SANITIZER_REGEX = Pattern.compile(
        "(?i)^(escape|encode|sanitize|clean|filter|purify|strip|normalize|remove)"
    );
    private static final Pattern VALIDATION_REGEX = Pattern.compile(
        "(?i)isvalid|validate|check|verify|assert|ensure|matches|is[A-Z][a-zA-Z]*$"
    );

    static {
        // Initialize taint sources
        TAINT_SOURCES.put("getParameter", new TaintSourceInfo("HTTP_PARAMETER", 0.98, true, "A03:2021"));
        TAINT_SOURCES.put("getHeader", new TaintSourceInfo("HTTP_HEADER", 0.95, true, "A03:2021"));
        TAINT_SOURCES.put("getCookieValue", new TaintSourceInfo("HTTP_COOKIE", 0.95, true, "A03:2021"));
        TAINT_SOURCES.put("readLine", new TaintSourceInfo("USER_INPUT", 0.90, true, "A03:2021"));
        TAINT_SOURCES.put("getInputStream", new TaintSourceInfo("INPUT_STREAM", 0.85, true, "A03:2021"));
        TAINT_SOURCES.put("nextLine", new TaintSourceInfo("SCANNER_INPUT", 0.90, true, "A03:2021"));
        TAINT_SOURCES.put("read", new TaintSourceInfo("FILE_INPUT", 0.80, false, "A04:2021"));
        TAINT_SOURCES.put("getProperty", new TaintSourceInfo("SYSTEM_PROPERTY", 0.65, false, "A04:2021"));
        TAINT_SOURCES.put("getenv", new TaintSourceInfo("ENVIRONMENT_VAR", 0.65, false, "A04:2021"));
        TAINT_SOURCES.put("getAttribute", new TaintSourceInfo("SESSION_ATTRIBUTE", 0.90, true, "A03:2021"));
        TAINT_SOURCES.put("getPathInfo", new TaintSourceInfo("PATH_INFO", 0.95, true, "A03:2021"));
        TAINT_SOURCES.put("getQueryString", new TaintSourceInfo("QUERY_STRING", 0.98, true, "A03:2021"));
        TAINT_SOURCES.put("getBytes", new TaintSourceInfo("BYTE_ARRAY_INPUT", 0.85, true, "A03:2021"));

        // Initialize sensitive sinks
        SENSITIVE_SINKS.put("executeQuery", new SinkInfo("SQL_INJECTION", 1.0, true, "A03:2021"));
        SENSITIVE_SINKS.put("executeUpdate", new SinkInfo("SQL_INJECTION", 1.0, true, "A03:2021"));
        SENSITIVE_SINKS.put("exec", new SinkInfo("COMMAND_INJECTION", 1.0, true, "A03:2021"));
        SENSITIVE_SINKS.put("prepareStatement", new SinkInfo("SQL_INJECTION", 0.95, true, "A03:2021"));
        SENSITIVE_SINKS.put("createQuery", new SinkInfo("SQL_INJECTION", 0.95, true, "A03:2021"));
        SENSITIVE_SINKS.put("println", new SinkInfo("LOG_INJECTION", 0.70, false, "A09:2021"));
        SENSITIVE_SINKS.put("print", new SinkInfo("LOG_INJECTION", 0.70, false, "A09:2021"));
        SENSITIVE_SINKS.put("info", new SinkInfo("LOG_INJECTION", 0.75, false, "A09:2021"));
        SENSITIVE_SINKS.put("debug", new SinkInfo("LOG_INJECTION", 0.65, false, "A09:2021"));
        SENSITIVE_SINKS.put("write", new SinkInfo("FILE_WRITE", 0.90, true, "A04:2021"));
        SENSITIVE_SINKS.put("sendRedirect", new SinkInfo("OPEN_REDIRECT", 0.95, true, "A01:2021"));
        SENSITIVE_SINKS.put("forward", new SinkInfo("OPEN_REDIRECT", 0.90, true, "A01:2021"));
        SENSITIVE_SINKS.put("include", new SinkInfo("PATH_TRAVERSAL", 0.95, true, "A04:2021"));
        SENSITIVE_SINKS.put("eval", new SinkInfo("CODE_INJECTION", 1.0, true, "A03:2021"));
        SENSITIVE_SINKS.put("readObject", new SinkInfo("DESERIALIZATION", 0.95, true, "A08:2021"));
        SENSITIVE_SINKS.put("openConnection", new SinkInfo("SSRF", 0.90, true, "A10:2021"));
        SENSITIVE_SINKS.put("readValue", new SinkInfo("VULNERABLE_COMPONENT", 0.85, true, "A06:2021"));
        SENSITIVE_SINKS.put("digest", new SinkInfo("CRYPTO_WEAKNESS", 0.80, false, "A02:2021"));

        // Initialize sanitization methods
        SANITIZATION_METHODS.addAll(Arrays.asList(
            "escapeHtml", "escapeXml", "escapeSql", "encodeForHTML", "encodeForSQL",
            "sanitize", "clean", "filter", "purify", "strip", "removeSpecialChars",
            "normalizeInput", "encodeURIComponent", "htmlspecialchars",
            "addSlashes", "stripTags", "replaceAll"
        ));

        // Initialize validation methods
        VALIDATION_METHODS.addAll(Arrays.asList(
            "isValid", "validate", "check", "verify", "assertValid", "ensure",
            "matchesPattern", "isNumeric", "isAlpha", "isEmail", "isAlphanumeric",
            "checkLength", "isEmpty", "isBlank", "restrict"
        ));

        // Initialize confidence modifiers
        CONFIDENCE_MODIFIERS.put("toString", 0.95);
        CONFIDENCE_MODIFIERS.put("valueOf", 0.90);
        CONFIDENCE_MODIFIERS.put("trim", 0.95);
        CONFIDENCE_MODIFIERS.put("substring", 0.85);
        CONFIDENCE_MODIFIERS.put("toLowerCase", 0.95);
        CONFIDENCE_MODIFIERS.put("toUpperCase", 0.95);
        CONFIDENCE_MODIFIERS.put("replaceAll", 0.80);
        CONFIDENCE_MODIFIERS.put("concat", 0.90);
        CONFIDENCE_MODIFIERS.put("format", 0.85);
    }

    // Data structures
    static class TaintSourceInfo {
        String category;
        double baseConfidence;
        boolean isUserControlled;
        String owaspCategory;

        TaintSourceInfo(String category, double baseConfidence, boolean isUserControlled, String owaspCategory) {
            this.category = category;
            this.baseConfidence = baseConfidence;
            this.isUserControlled = isUserControlled;
            this.owaspCategory = owaspCategory;
        }
    }

    static class SinkInfo {
        String vulnerabilityType;
        double severity;
        boolean requiresValidation;
        String owaspCategory;

        SinkInfo(String vulnerabilityType, double severity, boolean requiresValidation, String owaspCategory) {
            this.vulnerabilityType = vulnerabilityType;
            this.severity = severity;
            this.requiresValidation = requiresValidation;
            this.owaspCategory = owaspCategory;
        }
    }

    static class TaintFlowNode {
        int nodeId;
        String nodeType;
        String nodeName;
        double confidence;
        Set<String> taintLabels;
        boolean isSanitized;
        boolean isValidated;
        List<Integer> transformationChain;
        String methodContext;
        String fileName;
        int lineNumber;

        TaintFlowNode(int nodeId, String nodeType, String nodeName, double confidence, String methodContext, String fileName, int lineNumber) {
            this.nodeId = nodeId;
            this.nodeType = nodeType;
            this.nodeName = nodeName;
            this.confidence = confidence;
            this.taintLabels = new HashSet<>();
            this.isSanitized = false;
            this.isValidated = false;
            this.transformationChain = new ArrayList<>();
            this.methodContext = methodContext;
            this.fileName = fileName;
            this.lineNumber = lineNumber;
        }
    }

    static class TaintPath {
        List<TaintFlowNode> path;
        double overallConfidence;
        String vulnerabilityType;
        String severity;
        boolean hasSanitization;
        boolean hasValidation;
        Set<String> taintLabels;
        String owaspCategory;
        String sourceFile;
        String sinkFile;

        TaintPath() {
            this.path = new ArrayList<>();
            this.overallConfidence = 1.0;
            this.taintLabels = new HashSet<>();
            this.hasSanitization = false;
            this.hasValidation = false;
        }
    }

    public static void main(String[] args) {
        try {
            parseArguments(args);
            if (scanId.isEmpty()) {
                LOGGER.severe("Error: --scanId is required");
                System.exit(1);
            }

            // Fetch code graph, DFG, and CFG
            JSONObject codeGraph = readCodeGraph();
            JSONObject dfg = readDFG();
            JSONObject cfg = readCFG();
            if (codeGraph == null || dfg == null || cfg == null) {
                LOGGER.severe("Error: Could not read code graph, DFG, or CFG");
                System.exit(1);
            }

            // Perform taint analysis
            JSONArray taintedPaths = analyzeGraphs(codeGraph, dfg, cfg);
            JSONObject result = new JSONObject();
            result.put("scanId", scanId);
            result.put("timestamp", System.currentTimeMillis());
            result.put("taintedPaths", taintedPaths);
            result.put("analysisMetadata", generateAnalysisMetadata(codeGraph, dfg, cfg, taintedPaths));

            saveResults(result);
            LOGGER.info("Taint analysis completed. Results saved to " + outputPath);
            if (verbose) {
                System.out.println("Found " + taintedPaths.length() + " tainted paths");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Unexpected error during analysis", e);
            System.exit(1);
        }
    }

    private static void parseArguments(String[] args) {
        for (int i = 0; i < args.length; i++) {
            try {
                switch (args[i]) {
                    case "--endpoint":
                        if (i + 1 < args.length) {
                            apiEndpoint = validateEndpoint(args[++i]);
                        }
                        break;
                    case "--output":
                        if (i + 1 < args.length) {
                            outputPath = validateFilePath(args[++i]);
                        }
                        break;
                    case "--scanId":
                        if (i + 1 < args.length) {
                            scanId = validateScanId(args[++i]);
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
                    case "--verbose":
                        verbose = true;
                        break;
                    default:
                        LOGGER.warning("Unknown argument: " + args[i]);
                }
            } catch (IllegalArgumentException e) {
                LOGGER.severe(e.getMessage());
                System.exit(1);
            }
        }
    }

    private static String validateEndpoint(String endpoint) {
        if (!endpoint.matches("https?://[a-zA-Z0-9.:/\\-?=&]+")) {
            throw new IllegalArgumentException("Invalid API endpoint: " + endpoint);
        }
        return endpoint;
    }

    private static String validateFilePath(String path) {
        if (!path.endsWith(".json") || path.contains("..")) {
            throw new IllegalArgumentException("Invalid output path: " + path);
        }
        return path;
    }

    private static String validateScanId(String id) {
        if (!id.matches("[a-f0-9\\-]{36}")) {
            throw new IllegalArgumentException("Invalid scan ID format: " + id);
        }
        return id;
    }

    private static JSONObject readCodeGraph() throws IOException {
        String url = apiEndpoint + (apiEndpoint.contains("?") ? "&" : "?") + "scanId=" + scanId;
        return fetchJsonFromApi(url);
    }

    private static JSONObject readDFG() throws IOException {
        File dfgFile = new File("dfg.json");
        if (!dfgFile.exists()) {
            LOGGER.warning("DFG file not found locally, attempting to fetch from API");
            String url = apiEndpoint.replace("/graph", "/dfg") + (apiEndpoint.contains("?") ? "&" : "?") + "scanId=" + scanId;
            return fetchJsonFromApi(url);
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(dfgFile, StandardCharsets.UTF_8))) {
            String content = reader.lines().collect(Collectors.joining("\n"));
            return new JSONObject(content);
        }
    }

    private static JSONObject readCFG() throws IOException {
        File cfgFile = new File("cfg.json");
        if (!cfgFile.exists()) {
            LOGGER.warning("CFG file not found locally, attempting to fetch from API");
            String url = apiEndpoint.replace("/graph", "/cfg") + (apiEndpoint.contains("?") ? "&" : "?") + "scanId=" + scanId;
            return fetchJsonFromApi(url);
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(cfgFile, StandardCharsets.UTF_8))) {
            String content = reader.lines().collect(Collectors.joining("\n"));
            return new JSONObject(content);
        }
    }

    private static JSONObject fetchJsonFromApi(String url) throws IOException {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Basic " + getSecureAuth());
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                String errorDetails = readErrorStream(conn.getErrorStream());
                LOGGER.severe("Failed to fetch JSON: HTTP " + responseCode + " - " + errorDetails);
                return null;
            }

            try (InputStream is = conn.getInputStream()) {
                return new JSONObject(new String(is.readAllBytes(), StandardCharsets.UTF_8));
            }
        } catch (IOException | JSONException e) {
            LOGGER.log(Level.SEVERE, "Error fetching JSON from API", e);
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static String getSecureAuth() {
        String user = System.getenv("API_USER") != null ? System.getenv("API_USER") : apiUser;
        String pass = System.getenv("API_PASSWORD") != null ? System.getenv("API_PASSWORD") : apiPassword;
        return Base64.getEncoder().encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));
    }

    private static String readErrorStream(InputStream errorStream) throws IOException {
        if (errorStream == null) return "No error details available";
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    private static JSONArray analyzeGraphs(JSONObject codeGraph, JSONObject dfg, JSONObject cfg) {
        JSONArray nodes = codeGraph.getJSONArray("nodes");
        JSONArray dfgNodes = dfg.getJSONArray("nodes");
        JSONArray cfgNodes = cfg.getJSONArray("nodes");
        JSONArray dfgEdges = dfg.getJSONArray("edges");
        JSONArray cfgEdges = cfg.getJSONArray("edges");

        // Build analysis structures
        Map<Integer, JSONObject> nodeMap = buildNodeMap(nodes);
        Map<Integer, JSONObject> dfgNodeMap = buildNodeMap(dfgNodes);
        Map<Integer, JSONObject> cfgNodeMap = buildNodeMap(cfgNodes);
        Map<Integer, Set<Integer>> dataFlowMap = buildEnhancedDataFlowMap(dfgEdges, nodeMap);
        Map<Integer, Set<Integer>> controlFlowMap = buildControlFlowMap(cfgEdges, nodeMap);
        Map<String, Set<Integer>> methodToNodesMap = buildMethodToNodesMap(nodeMap);

        // Merge DFG and CFG node information
        mergeNodeInformation(nodeMap, dfgNodeMap, cfgNodeMap);

        // Identify sources, sinks, sanitizers, and validators
        Map<Integer, TaintFlowNode> sources = identifyEnhancedSources(nodeMap);
        Map<Integer, TaintFlowNode> sinks = identifyEnhancedSinks(nodeMap);
        Set<Integer> sanitizers = identifySanitizers(nodeMap);
        Set<Integer> validators = identifyValidators(nodeMap);

        if (verbose) {
            LOGGER.info(String.format(
                "Analysis Summary: Sources=%d, Sinks=%d, Sanitizers=%d, Validators=%d, DFG Nodes=%d, CFG Nodes=%d",
                sources.size(), sinks.size(), sanitizers.size(), validators.size(), dfgNodes.length(), cfgNodes.length()
            ));
        }

        // Perform path-sensitive taint analysis
        JSONArray taintedPaths = new JSONArray();
        for (Map.Entry<Integer, TaintFlowNode> sourceEntry : sources.entrySet()) {
            Integer sourceId = sourceEntry.getKey();
            TaintFlowNode sourceNode = sourceEntry.getValue();

            if (verbose) {
                LOGGER.info("Analyzing source: " + sourceNode.nodeName + " (ID: " + sourceId + ")");
            }

            Map<Integer, TaintFlowNode> taintedNodes = propagateTaint(
                sourceId, sourceNode, nodeMap, dataFlowMap, controlFlowMap,
                sanitizers, validators, methodToNodesMap
            );

            for (Map.Entry<Integer, TaintFlowNode> sinkEntry : sinks.entrySet()) {
                Integer sinkId = sinkEntry.getKey();
                TaintFlowNode sinkNode = sinkEntry.getValue();

                if (taintedNodes.containsKey(sinkId)) {
                    List<TaintPath> paths = findPathSensitivePaths(
                        sourceId, sinkId, taintedNodes, dataFlowMap, controlFlowMap,
                        nodeMap, sanitizers, validators
                    );

                    for (TaintPath path : paths) {
                        if (isValidTaintPath(path, sourceNode, sinkNode)) {
                            JSONObject pathObj = createEnhancedPathObject(path, sourceNode, sinkNode);
                            taintedPaths.put(pathObj);
                            if (verbose) {
                                LOGGER.info("Found taint path: " +
                                    path.path.stream().map(n -> n.nodeName).collect(Collectors.joining(" -> ")));
                            }
                        }
                    }
                }
            }
        }

        return taintedPaths;
    }

    private static Map<Integer, JSONObject> buildNodeMap(JSONArray nodes) {
        Map<Integer, JSONObject> nodeMap = new HashMap<>(nodes.length());
        for (int i = 0; i < nodes.length(); i++) {
            JSONObject node = nodes.getJSONObject(i);
            nodeMap.put(node.getInt("id"), node);
        }
        return nodeMap;
    }

    private static void mergeNodeInformation(Map<Integer, JSONObject> nodeMap, Map<Integer, JSONObject> dfgNodeMap, Map<Integer, JSONObject> cfgNodeMap) {
        for (Map.Entry<Integer, JSONObject> entry : nodeMap.entrySet()) {
            Integer nodeId = entry.getKey();
            JSONObject node = entry.getValue();
            JSONObject dfgNode = dfgNodeMap.get(nodeId);
            JSONObject cfgNode = cfgNodeMap.get(nodeId);

            if (dfgNode != null) {
                if (dfgNode.has("fileName")) node.put("fileName", dfgNode.getString("fileName"));
                if (dfgNode.has("lineNumber")) node.put("lineNumber", dfgNode.getInt("lineNumber"));
            }
            if (cfgNode != null) {
                if (cfgNode.has("fileName")) node.put("fileName", cfgNode.getString("fileName"));
                if (cfgNode.has("lineNumber")) node.put("lineNumber", cfgNode.getInt("lineNumber"));
            }
        }
    }

    private static Map<Integer, Set<Integer>> buildEnhancedDataFlowMap(JSONArray edges, Map<Integer, JSONObject> nodeMap) {
        Map<Integer, Set<Integer>> dataFlowMap = new HashMap<>();
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            String edgeType = edge.getString("type");
            int source = edge.getInt("source");
            int target = edge.getInt("target");

            if ("DATA_FLOW".equals(edgeType) || "DECLARES".equals(edgeType) || "ACCESSES".equals(edgeType)) {
                dataFlowMap.computeIfAbsent(source, k -> new HashSet<>()).add(target);
            }
            if ("INVOKES".equals(edgeType)) {
                JSONObject targetNode = nodeMap.get(target);
                if (targetNode != null && "METHOD_CALL".equals(targetNode.getString("type"))) {
                    findAndLinkMethodParameters(source, target, nodeMap, dataFlowMap);
                }
            }
            if ("CONTAINS_ASSIGNMENT".equals(edgeType)) {
                dataFlowMap.computeIfAbsent(target, k -> new HashSet<>()).add(source);
            }
        }
        return dataFlowMap;
    }

    private static void findAndLinkMethodParameters(
            Integer source, Integer target, Map<Integer, JSONObject> nodeMap,
            Map<Integer, Set<Integer>> dataFlowMap) {
        JSONObject targetNode = nodeMap.get(target);
        String methodName = targetNode.getString("name");
        int argCount = targetNode.optInt("arguments", 0);
        for (int i = 1; i <= argCount; i++) {
            Integer paramId = findParameterNode(source, i, nodeMap);
            if (paramId != null) {
                dataFlowMap.computeIfAbsent(paramId, k -> new HashSet<>()).add(target);
            }
        }
    }

    private static Integer findParameterNode(Integer methodId, int index, Map<Integer, JSONObject> nodeMap) {
        for (Map.Entry<Integer, JSONObject> entry : nodeMap.entrySet()) {
            JSONObject node = entry.getValue();
            if ("PARAMETER".equals(node.getString("type")) && node.has("index") && node.getInt("index") == index) {
                return entry.getKey();
            }
        }
        return null;
    }

    private static Map<Integer, Set<Integer>> buildControlFlowMap(JSONArray edges, Map<Integer, JSONObject> nodeMap) {
        Map<Integer, Set<Integer>> controlFlowMap = new HashMap<>();
        for (int i = 0; i < edges.length(); i++) {
            JSONObject edge = edges.getJSONObject(i);
            String edgeType = edge.getString("type");
            if ("CONTAINS_CONTROL_FLOW".equals(edgeType) || "SEQUENTIAL_FLOW".equals(edgeType) ||
                "THEN_BRANCH".equals(edgeType) || "ELSE_BRANCH".equals(edgeType) ||
                "LOOP_BODY".equals(edgeType) || "CATCH_BRANCH".equals(edgeType)) {
                int source = edge.getInt("source");
                int target = edge.getInt("target");
                controlFlowMap.computeIfAbsent(source, k -> new HashSet<>()).add(target);
            }
        }
        return controlFlowMap;
    }

    private static Map<String, Set<Integer>> buildMethodToNodesMap(Map<Integer, JSONObject> nodeMap) {
        Map<String, Set<Integer>> methodToNodesMap = new HashMap<>();
        for (Map.Entry<Integer, JSONObject> entry : nodeMap.entrySet()) {
            JSONObject node = entry.getValue();
            String nodeType = node.getString("type");
            if ("METHOD".equals(nodeType) || "CONSTRUCTOR".equals(nodeType)) {
                String methodName = node.getString("name");
                methodToNodesMap.computeIfAbsent(methodName, k -> new HashSet<>()).add(entry.getKey());
            }
        }
        return methodToNodesMap;
    }

    private static Map<Integer, TaintFlowNode> identifyEnhancedSources(Map<Integer, JSONObject> nodeMap) {
        Map<Integer, TaintFlowNode> sources = new HashMap<>();
        for (Map.Entry<Integer, JSONObject> entry : nodeMap.entrySet()) {
            JSONObject node = entry.getValue();
            String nodeType = node.getString("type");
            String nodeName = node.optString("name", "");
            String methodContext = node.optString("scope", "");
            String fileName = node.optString("fileName", "Unknown");
            int lineNumber = node.optInt("lineNumber", -1);

            if ("METHOD_CALL".equals(nodeType) && TAINT_SOURCES.containsKey(nodeName)) {
                TaintSourceInfo sourceInfo = TAINT_SOURCES.get(nodeName);
                TaintFlowNode taintNode = new TaintFlowNode(
                    entry.getKey(), nodeType, nodeName, sourceInfo.baseConfidence, methodContext, fileName, lineNumber
                );
                taintNode.taintLabels.add(sourceInfo.category);
                sources.put(entry.getKey(), taintNode);
            }
            if ("PARAMETER".equals(nodeType)) {
                double confidence = determineParameterConfidence(node, nodeMap);
                if (confidence >= MIN_CONFIDENCE_THRESHOLD) {
                    TaintFlowNode taintNode = new TaintFlowNode(
                        entry.getKey(), nodeType, nodeName, confidence, methodContext, fileName, lineNumber
                    );
                    taintNode.taintLabels.add("USER_PARAMETER");
                    sources.put(entry.getKey(), taintNode);
                }
            }
            if ("FIELD".equals(nodeType) && isUserInputField(node)) {
                TaintFlowNode taintNode = new TaintFlowNode(
                    entry.getKey(), nodeType, nodeName, 0.95, methodContext, fileName, lineNumber
                );
                taintNode.taintLabels.add("USER_FIELD");
                sources.put(entry.getKey(), taintNode);
            }
            if ("TYPE_ARRAY_CALL".equals(nodeType) && nodeName.equals("args")) {
                TaintFlowNode taintNode = new TaintFlowNode(
                    entry.getKey(), nodeType, "args[0]", 0.98, methodContext, fileName, lineNumber
                );
                taintNode.taintLabels.add("CLI_INPUT");
                sources.put(entry.getKey(), taintNode);
            }
        }
        return sources;
    }

    private static double determineParameterConfidence(JSONObject node, Map<Integer, JSONObject> nodeMap) {
        String methodContext = node.optString("scope", "");
        String dataType = node.optString("dataType", "");
        if (methodContext.contains("HttpServletRequest") || methodContext.contains("ServletRequest") ||
            dataType.contains("String") || dataType.contains("InputStream")) {
            return 0.98;
        }
        return 0.5;
    }

    private static boolean isUserInputField(JSONObject node) {
        String name = node.optString("name", "").toLowerCase();
        String dataType = node.optString("dataType", "").toLowerCase();
        return (name.contains("input") || name.contains("request") || name.contains("param") ||
                dataType.contains("string") || dataType.contains("inputstream"));
    }

    private static Map<Integer, TaintFlowNode> identifyEnhancedSinks(Map<Integer, JSONObject> nodeMap) {
        Map<Integer, TaintFlowNode> sinks = new HashMap<>();
        for (Map.Entry<Integer, JSONObject> entry : nodeMap.entrySet()) {
            JSONObject node = entry.getValue();
            String nodeType = node.getString("type");
            String nodeName = node.optString("name", "");
            String methodContext = node.optString("scope", "");
            String fileName = node.optString("fileName", "Unknown");
            int lineNumber = node.optInt("lineNumber", -1);

            if ("METHOD_CALL".equals(nodeType) && SENSITIVE_SINKS.containsKey(nodeName)) {
                SinkInfo sinkInfo = SENSITIVE_SINKS.get(nodeName);
                TaintFlowNode taintNode = new TaintFlowNode(
                    entry.getKey(), nodeType, nodeName, sinkInfo.severity, methodContext, fileName, lineNumber
                );
                taintNode.taintLabels.add(sinkInfo.vulnerabilityType);
                sinks.put(entry.getKey(), taintNode);
            }
            if ("OBJECT_CREATION".equals(nodeType) && nodeName.equals("FileWriter")) {
                TaintFlowNode taintNode = new TaintFlowNode(
                    entry.getKey(), nodeType, nodeName, 0.95, methodContext, fileName, lineNumber
                );
                taintNode.taintLabels.add("PATH_TRAVERSAL");
                sinks.put(entry.getKey(), taintNode);
            }
        }
        return sinks;
    }

    private static Set<Integer> identifySanitizers(Map<Integer, JSONObject> nodeMap) {
        Set<Integer> sanitizers = new HashSet<>();
        for (Map.Entry<Integer, JSONObject> entry : nodeMap.entrySet()) {
            JSONObject node = entry.getValue();
            String nodeType = node.getString("type");
            String nodeName = node.optString("name", "");

            if ("METHOD_CALL".equals(nodeType) && isSanitizationMethod(nodeName)) {
                sanitizers.add(entry.getKey());
            }
        }
        return sanitizers;
    }

    private static Set<Integer> identifyValidators(Map<Integer, JSONObject> nodeMap) {
        Set<Integer> validators = new HashSet<>();
        for (Map.Entry<Integer, JSONObject> entry : nodeMap.entrySet()) {
            JSONObject node = entry.getValue();
            String nodeType = node.getString("type");
            String nodeName = node.optString("name", "");

            if ("METHOD_CALL".equals(nodeType) && isValidationMethod(nodeName)) {
                validators.add(entry.getKey());
            }
        }
        return validators;
    }

    private static boolean isSanitizationMethod(String methodName) {
        return SANITIZATION_METHODS.contains(methodName.toLowerCase()) ||
               SANITIZER_REGEX.matcher(methodName).find();
    }

    private static boolean isValidationMethod(String methodName) {
        return VALIDATION_METHODS.contains(methodName.toLowerCase()) ||
               VALIDATION_REGEX.matcher(methodName).find();
    }

    private static Map<Integer, TaintFlowNode> propagateTaint(
            Integer sourceId, TaintFlowNode sourceNode, Map<Integer, JSONObject> nodeMap,
            Map<Integer, Set<Integer>> dataFlowMap, Map<Integer, Set<Integer>> controlFlowMap,
            Set<Integer> sanitizers, Set<Integer> validators, Map<String, Set<Integer>> methodToNodesMap) {
        Map<Integer, TaintFlowNode> taintedNodes = new HashMap<>();
        Queue<Integer> worklist = new LinkedList<>();
        Set<Integer> visited = new HashSet<>();
        Map<Integer, Integer> visitCount = new HashMap<>();
        Map<Integer, Double> contextConfidence = new HashMap<>();

        taintedNodes.put(sourceId, sourceNode);
        worklist.offer(sourceId);
        contextConfidence.put(sourceId, sourceNode.confidence);

        while (!worklist.isEmpty()) {
            Integer currentId = worklist.poll();
            if (currentId == null) continue;

            visitCount.put(currentId, visitCount.getOrDefault(currentId, 0) + 1);
            if (visitCount.get(currentId) > 5) continue; // Prevent cycles

            TaintFlowNode currentTaint = taintedNodes.get(currentId);
            if (currentTaint == null || currentTaint.confidence < MIN_CONFIDENCE_THRESHOLD) continue;

            visited.add(currentId);

            // Process data flow successors
            Set<Integer> successors = dataFlowMap.getOrDefault(currentId, new HashSet<>());
            for (Integer successor : successors) {
                if (!visited.contains(successor)) {
                    TaintFlowNode newTaint = propagateTaintToNode(
                        currentTaint, successor, nodeMap, sanitizers, validators, controlFlowMap
                    );
                    if (newTaint != null && newTaint.confidence >= MIN_CONFIDENCE_THRESHOLD) {
                        taintedNodes.put(successor, newTaint);
                        worklist.offer(successor);
                        contextConfidence.put(successor, newTaint.confidence);
                    }
                }
            }

            // Process control flow dependencies
            Set<Integer> controlSuccessors = controlFlowMap.getOrDefault(currentId, new HashSet<>());
            for (Integer successor : controlSuccessors) {
                if (!visited.contains(successor)) {
                    TaintFlowNode newTaint = propagateTaintToNode(
                        currentTaint, successor, nodeMap, sanitizers, validators, controlFlowMap
                    );
                    if (newTaint != null && newTaint.confidence >= MIN_CONFIDENCE_THRESHOLD) {
                        taintedNodes.put(successor, newTaint);
                        worklist.offer(successor);
                        contextConfidence.put(successor, newTaint.confidence * 0.9); // Control flow reduces confidence
                    }
                }
            }

            // Inter-procedural analysis
            JSONObject currentNode = nodeMap.get(currentId);
            if (currentNode != null && "METHOD_CALL".equals(currentNode.getString("type"))) {
                handleMethodCallTaintPropagation(
                    currentId, currentTaint, nodeMap, methodToNodesMap,
                    taintedNodes, worklist, visited, contextConfidence
                );
            }
        }

        return taintedNodes;
    }

    private static TaintFlowNode propagateTaintToNode(
            TaintFlowNode sourceTaint, Integer targetId, Map<Integer, JSONObject> nodeMap,
            Set<Integer> sanitizers, Set<Integer> validators, Map<Integer, Set<Integer>> controlFlowMap) {
        JSONObject targetNode = nodeMap.get(targetId);
        if (targetNode == null) return null;

        String targetType = targetNode.getString("type");
        String targetName = targetNode.optString("name", "");
        String methodContext = targetNode.optString("scope", "");
        String fileName = targetNode.optString("fileName", "Unknown");
        int lineNumber = targetNode.optInt("lineNumber", -1);

        double confidenceMultiplier = 1.0;
        boolean isSanitized = sourceTaint.isSanitized || sanitizers.contains(targetId) || isSanitizationMethod(targetName);
        boolean isValidated = sourceTaint.isValidated || validators.contains(targetId) || isValidationMethod(targetName);

        if (isSanitized) {
            confidenceMultiplier *= SANITIZER_CONFIDENCE_REDUCTION;
        }
        if (isValidated) {
            confidenceMultiplier += VALIDATION_CONFIDENCE_BOOST;
            if (confidenceMultiplier > 1.0) confidenceMultiplier = 1.0;
        }
        if (CONFIDENCE_MODIFIERS.containsKey(targetName)) {
            confidenceMultiplier *= CONFIDENCE_MODIFIERS.get(targetName);
        }
        if (controlFlowMap.containsKey(targetId)) {
            confidenceMultiplier *= 0.95; // Adjust for control flow dependencies
        }

        double newConfidence = sourceTaint.confidence * confidenceMultiplier;
        if (newConfidence < MIN_CONFIDENCE_THRESHOLD) return null;

        TaintFlowNode newTaint = new TaintFlowNode(
            targetId, targetType, targetName, newConfidence, methodContext, fileName, lineNumber
        );
        newTaint.taintLabels.addAll(sourceTaint.taintLabels);
        newTaint.isSanitized = isSanitized;
        newTaint.isValidated = isValidated;
        newTaint.transformationChain.addAll(sourceTaint.transformationChain);
        newTaint.transformationChain.add(targetId);

        return newTaint;
    }

    private static void handleMethodCallTaintPropagation(
            Integer currentId, TaintFlowNode currentTaint, Map<Integer, JSONObject> nodeMap,
            Map<String, Set<Integer>> methodToNodesMap, Map<Integer, TaintFlowNode> taintedNodes,
            Queue<Integer> worklist, Set<Integer> visited, Map<Integer, Double> contextConfidence) {
        JSONObject currentNode = nodeMap.get(currentId);
        String methodName = currentNode.getString("name");

        Set<Integer> methodNodes = methodToNodesMap.getOrDefault(methodName, new HashSet<>());
        for (Integer methodNodeId : methodNodes) {
            JSONObject methodNode = nodeMap.get(methodNodeId);
            if (methodNode == null) continue;

            // Propagate taint to method parameters and return statements
            for (Map.Entry<Integer, JSONObject> entry : nodeMap.entrySet()) {
                JSONObject node = entry.getValue();
                String nodeType = node.getString("type");
                String fileName = node.optString("fileName", "Unknown");
                int lineNumber = node.optInt("lineNumber", -1);

                if ("PARAMETER".equals(nodeType) || "RETURN_STATEMENT".equals(nodeType)) {
                    TaintFlowNode newTaint = new TaintFlowNode(
                        entry.getKey(), nodeType, node.optString("name", "return"),
                        currentTaint.confidence * 0.95, methodNode.getString("name"), fileName, lineNumber
                    );
                    newTaint.taintLabels.addAll(currentTaint.taintLabels);
                    newTaint.isSanitized = currentTaint.isSanitized;
                    newTaint.isValidated = currentTaint.isValidated;
                    newTaint.transformationChain.addAll(currentTaint.transformationChain);
                    newTaint.transformationChain.add(entry.getKey());
                    taintedNodes.put(entry.getKey(), newTaint);
                    if (!visited.contains(entry.getKey())) {
                        worklist.offer(entry.getKey());
                        contextConfidence.put(entry.getKey(), newTaint.confidence);
                    }
                }
            }
        }
    }

    private static List<TaintPath> findPathSensitivePaths(
            Integer sourceId, Integer sinkId, Map<Integer, TaintFlowNode> taintedNodes,
            Map<Integer, Set<Integer>> dataFlowMap, Map<Integer, Set<Integer>> controlFlowMap,
            Map<Integer, JSONObject> nodeMap, Set<Integer> sanitizers, Set<Integer> validators) {
        List<TaintPath> paths = new ArrayList<>();
        Set<Integer> visited = new HashSet<>();
        List<TaintFlowNode> currentPath = new ArrayList<>();
        Map<Integer, Set<Integer>> combinedFlowMap = new HashMap<>();

        // Combine data and control flow maps for path-sensitive analysis
        for (Integer nodeId : nodeMap.keySet()) {
            Set<Integer> successors = new HashSet<>();
            successors.addAll(dataFlowMap.getOrDefault(nodeId, new HashSet<>()));
            successors.addAll(controlFlowMap.getOrDefault(nodeId, new HashSet<>()));
            combinedFlowMap.put(nodeId, successors);
        }

        findPathsDFS(
            sourceId, sinkId, taintedNodes, combinedFlowMap, nodeMap,
            visited, currentPath, paths, sanitizers, validators
        );

        // Prioritize paths with higher confidence and fewer sanitizers
        paths.sort((p1, p2) -> {
            int compare = Double.compare(p2.overallConfidence, p1.overallConfidence);
            if (compare == 0) {
                return Boolean.compare(p1.hasSanitization, p2.hasSanitization);
            }
            return compare;
        });

        return paths.stream().limit(MAX_PATHS_PER_SOURCE).collect(Collectors.toList());
    }

    private static void findPathsDFS(
            Integer currentId, Integer targetId, Map<Integer, TaintFlowNode> taintedNodes,
            Map<Integer, Set<Integer>> flowMap, Map<Integer, JSONObject> nodeMap,
            Set<Integer> visited, List<TaintFlowNode> currentPath, List<TaintPath> foundPaths,
            Set<Integer> sanitizers, Set<Integer> validators) {
        if (visited.contains(currentId) || currentPath.size() > MAX_PATH_LENGTH) return;

        TaintFlowNode currentTaint = taintedNodes.get(currentId);
        if (currentTaint == null) return;

        visited.add(currentId);
        currentPath.add(currentTaint);

        if (currentId.equals(targetId)) {
            TaintPath path = new TaintPath();
            path.path.addAll(currentPath);
            path.overallConfidence = calculatePathConfidence(currentPath);
            path.hasSanitization = currentPath.stream().anyMatch(n -> n.isSanitized);
            path.hasValidation = currentPath.stream().anyMatch(n -> n.isValidated);
            path.taintLabels.addAll(currentPath.get(currentPath.size() - 1).taintLabels);
            path.vulnerabilityType = currentTaint.taintLabels.iterator().hasNext() ?
                currentTaint.taintLabels.iterator().next() : "UNKNOWN";
            path.severity = String.valueOf(currentTaint.confidence);
            path.owaspCategory = SENSITIVE_SINKS.getOrDefault(currentTaint.nodeName, new SinkInfo("UNKNOWN", 0.5, false, "UNKNOWN")).owaspCategory;
            path.sourceFile = currentPath.get(0).fileName;
            path.sinkFile = currentTaint.fileName;
            foundPaths.add(path);
        } else {
            Set<Integer> successors = flowMap.getOrDefault(currentId, new HashSet<>());
            for (Integer successor : successors) {
                if (taintedNodes.containsKey(successor)) {
                    findPathsDFS(
                        successor, targetId, taintedNodes, flowMap, nodeMap,
                        visited, currentPath, foundPaths, sanitizers, validators
                    );
                }
            }
        }

        visited.remove(currentId);
        currentPath.remove(currentPath.size() - 1);
    }

    private static double calculatePathConfidence(List<TaintFlowNode> path) {
        double confidence = path.stream()
            .mapToDouble(n -> n.confidence)
            .reduce(1.0, (a, b) -> a * b);
        // Adjust confidence based on path length
        confidence *= Math.pow(0.99, path.size());
        return confidence;
    }

    private static boolean isValidTaintPath(TaintPath path, TaintFlowNode sourceNode, TaintFlowNode sinkNode) {
        if (path.overallConfidence < MIN_CONFIDENCE_THRESHOLD) return false;
        if (path.hasSanitization && sinkNode.taintLabels.contains("SQL_INJECTION")) return false;
        if (path.hasSanitization && sinkNode.taintLabels.contains("COMMAND_INJECTION")) return false;
        if (path.path.size() < 2 || path.path.size() > MAX_PATH_LENGTH) return false;
        if (sinkNode.taintLabels.stream().noneMatch(label -> SENSITIVE_SINKS.containsKey(sinkNode.nodeName))) return false;
        if (path.hasValidation && !SENSITIVE_SINKS.get(sinkNode.nodeName).requiresValidation) return false;
        return true;
    }

    private static JSONObject createEnhancedPathObject(TaintPath path, TaintFlowNode sourceNode, TaintFlowNode sinkNode) {
        JSONObject pathObj = new JSONObject();
        JSONArray pathArray = new JSONArray();
        for (TaintFlowNode node : path.path) {
            JSONObject nodeObj = new JSONObject();
            nodeObj.put("id", node.nodeId);
            nodeObj.put("type", node.nodeType);
            nodeObj.put("name", node.nodeName);
            nodeObj.put("confidence", node.confidence);
            nodeObj.put("taintLabels", new JSONArray(node.taintLabels));
            nodeObj.put("isSanitized", node.isSanitized);
            nodeObj.put("isValidated", node.isValidated);
            nodeObj.put("methodContext", node.methodContext);
            nodeObj.put("fileName", node.fileName);
            nodeObj.put("lineNumber", node.lineNumber);
            pathArray.put(nodeObj);
        }
        pathObj.put("path", pathArray);
        pathObj.put("source", sourceNode.nodeName);
        pathObj.put("sink", sinkNode.nodeName);
        pathObj.put("vulnerabilityType", path.vulnerabilityType);
        pathObj.put("owaspCategory", path.owaspCategory);
        pathObj.put("overallConfidence", path.overallConfidence);
        pathObj.put("hasSanitization", path.hasSanitization);
        pathObj.put("hasValidation", path.hasValidation);
        pathObj.put("taintLabels", new JSONArray(path.taintLabels));
        pathObj.put("sourceFile", path.sourceFile);
        pathObj.put("sinkFile", path.sinkFile);
        return pathObj;
    }

    private static JSONObject generateAnalysisMetadata(JSONObject codeGraph, JSONObject dfg, JSONObject cfg, JSONArray taintedPaths) {
        JSONObject metadata = new JSONObject();
        metadata.put("nodeCount", codeGraph.getJSONArray("nodes").length());
        metadata.put("edgeCount", codeGraph.getJSONArray("edges").length());
        metadata.put("dfgNodeCount", dfg.getJSONArray("nodes").length());
        metadata.put("dfgEdgeCount", dfg.getJSONArray("edges").length());
        metadata.put("cfgNodeCount", cfg.getJSONArray("nodes").length());
        metadata.put("cfgEdgeCount", cfg.getJSONArray("edges").length());
        metadata.put("taintedPathCount", taintedPaths.length());
        metadata.put("analysisTimestamp", System.currentTimeMillis());
        metadata.put("toolVersion", "2.0.0");
        metadata.put("confidenceThreshold", MIN_CONFIDENCE_THRESHOLD);
        return metadata;
    }

    private static void saveResults(JSONObject result) throws IOException {
        File outputFile = new File(outputPath);
        outputFile.getParentFile().mkdirs();
        try (FileWriter writer = new FileWriter(outputFile, StandardCharsets.UTF_8)) {
            writer.write(result.toString(2));
        }
        LOGGER.info("Results successfully written to " + outputPath);
    }
}