import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class dfg_extract {

    private static String apiEndpoint = "http://localhost:8080/api/graph";
    private static String outputPath = "dfg.json";

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
            System.err.println("Usage: java dfg_extract --scanId <scan-id> [--endpoint <url>] [--output <path>]");
            return;
        }

        JSONObject codeGraph = fetchCodeGraph(scanId);
        JSONObject dfg = extractDFG(codeGraph);
        saveDFG(dfg, outputPath);
        System.out.println("DFG saved to: " + outputPath);
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

    public static JSONObject extractDFG(JSONObject codeGraph) {
        JSONObject dfg = new JSONObject();
        dfg.put("scanId", codeGraph.getString("scanId"));
        dfg.put("type", "DataFlowGraph");

        JSONArray dfgNodes = new JSONArray();
        JSONArray dfgEdges = new JSONArray();
        dfg.put("nodes", dfgNodes);
        dfg.put("edges", dfgEdges);

        // Extract data flow-related nodes (e.g., LOCAL_VARIABLE, PARAMETER, etc.)
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

        // Extract data flow-related edges (e.g., DATA_FLOW, DECLARES)
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

        return dfg;
    }

    public static void saveDFG(JSONObject dfg, String outputPath) throws IOException {
        try (FileWriter file = new FileWriter(outputPath)) {
            file.write(dfg.toString(2));
        }
    }
}