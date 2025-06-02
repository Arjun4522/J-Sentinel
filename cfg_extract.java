import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class cfg_extract {

    private static String apiEndpoint = "http://localhost:8080/api/graph";
    private static String outputPath = "cfg.json";

    public static void main(String[] args) throws IOException {
        String scanId = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--endpoint":
                    if (i + 1 < args.length) apiEndpoint = args[++i];
                    break;
                case "--scanId":
                    if (i + 1 < args.length) scanId = args[++i];
                    break;
                case "--output":
                    if (i + 1 < args.length) outputPath = args[++i];
                    break;
            }
        }

        if (scanId == null) {
            System.err.println("Usage: java cfg_extract --scanId <scan-id> [--endpoint <url>] [--output <path>]");
            return;
        }

        JSONObject codeGraph = fetchCodeGraph(scanId);
        JSONObject cfg = extractCFG(codeGraph);
        saveCFG(cfg, outputPath);
        System.out.println("CFG saved to: " + outputPath);
    }

    private static JSONObject fetchCodeGraph(String scanId) throws IOException {
        URL url = new URL(apiEndpoint + "?scanId=" + scanId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Basic " + 
            Base64.getEncoder().encodeToString("user:secret".getBytes()));

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException("Failed to fetch code graph: HTTP error code " + responseCode);
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }
        return new JSONObject(response.toString());
    }

    public static JSONObject extractCFG(JSONObject codeGraph) {
        JSONObject cfg = new JSONObject();
        cfg.put("scanId", codeGraph.getString("scanId"));
        cfg.put("type", "ControlFlowGraph");

        JSONArray cfgNodes = new JSONArray();
        JSONArray cfgEdges = new JSONArray();
        cfg.put("nodes", cfgNodes);
        cfg.put("edges", cfgEdges);

        // Extract control flow-related nodes (e.g., IF_STATEMENT, FOR_LOOP, etc.)
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

        // Extract control flow-related edges (e.g., CONTAINS_CONTROL_FLOW, CONTAINS)
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

        return cfg;
    }

    public static void saveCFG(JSONObject cfg, String outputPath) throws IOException {
        try (FileWriter file = new FileWriter(outputPath)) {
            file.write(cfg.toString(2));
        }
    }
}