import org.json.JSONObject;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class ast_extract {

    private static String apiEndpoint = "http://localhost:8080/api/graph";
    private static String outputPath = "ast.json";

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
            System.err.println("Usage: java fetch_graph --scanId <scan-id> [--endpoint <url>] [--output <path>]");
            return;
        }

        String jsonContent = fetchGraphJson(scanId);
        saveJson(jsonContent, outputPath);
        System.out.println("Graph JSON saved to: " + outputPath);
    }

    private static String fetchGraphJson(String scanId) throws IOException {
        URL url = new URL(apiEndpoint + "?scanId=" + scanId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");

        String auth = System.getenv("API_USER") != null ? System.getenv("API_USER") : "user";
        String password = System.getenv("API_PASSWORD") != null ? System.getenv("API_PASSWORD") : "secret";
        String encodedAuth = Base64.getEncoder().encodeToString((auth + ":" + password).getBytes());
        conn.setRequestProperty("Authorization", "Basic " + encodedAuth);

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            String errorMessage;
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getErrorStream()))) {
                errorMessage = br.lines().collect(java.util.stream.Collectors.joining("\n"));
            }
            throw new IOException("Failed to fetch graph: HTTP " + responseCode + " - " + errorMessage);
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }
        return response.toString();
    }

    private static void saveJson(String jsonContent, String outputPath) throws IOException {
        JSONObject jsonObject = new JSONObject(jsonContent);
        try (FileWriter file = new FileWriter(outputPath)) {
            file.write(jsonObject.toString(2));
        }
    }
}