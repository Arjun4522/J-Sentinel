import java.io.*;
import java.util.*;
import java.util.regex.Pattern;
import org.json.*;

/**
 * OWASP Vulnerability Detector
 * Analyzes taint analysis results against OWASP vulnerability patterns
 */
public class OwaspVulnerabilityDetector {
    
    private List<VulnerabilityRule> rules;
    private Map<String, Double> severityWeights;
    private Map<String, Double> confidenceFactors;
    
    public OwaspVulnerabilityDetector() {
        initializeRules();
        initializeWeights();
    }
    
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java OwaspVulnerabilityDetector <taint-analysis-file> [output-file]");
            System.exit(1);
        }
        
        String inputFile = args[0];
        String outputFile = args.length > 1 ? args[1] : "owasp_vulnerabilities.json";
        
        OwaspVulnerabilityDetector detector = new OwaspVulnerabilityDetector();
        
        try {
            // Load and analyze taint data
            String taintData = readFile(inputFile);
            JSONObject taintAnalysis = new JSONObject(taintData);
            
            // Detect vulnerabilities
            List<VulnerabilityFinding> findings = detector.analyzeVulnerabilities(taintAnalysis);
            
            // Generate report
            JSONObject report = detector.generateReport(findings);
            
            // Save results
            writeFile(outputFile, report.toString(2));
            
            // Print summary
            detector.printSummary(findings);
            
        } catch (Exception e) {
            System.err.println("Error analyzing vulnerabilities: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Initialize OWASP vulnerability detection rules
     */
    private void initializeRules() {
        rules = new ArrayList<>();
        
        // OWASP A03:2021 - Log Injection
        rules.add(new VulnerabilityRule(
            "OWASP-A03-002",
            "Log Injection/Forging",
            "A03:2021",
            "MEDIUM",
            "Unsanitized user input in log statements can lead to log injection",
            Arrays.asList("PARAMETER", "HTTP_REQUEST"),
            Arrays.asList("info", "debug", "warn", "error", "log", "println"),
            Arrays.asList("METHOD_CALL"),
            Arrays.asList("logger", "System.out", "System.err"),
            Arrays.asList("sanitize", "escape", "clean", "validate")
        ));
        
        // OWASP A02:2021 - Sensitive Data Exposure
        rules.add(new VulnerabilityRule(
            "OWASP-A02-001",
            "Sensitive Data in Logs",
            "A02:2021",
            "HIGH",
            "Sensitive data exposed through logging without encryption",
            Arrays.asList("PARAMETER"),
            Arrays.asList("info", "debug", "warn", "error", "log", "println", "print"),
            Arrays.asList("METHOD_CALL"),
            Arrays.asList("logger", "System.out", "System.err", "console"),
            Arrays.asList("encrypt", "hash", "mask", "sanitize")
        ));
        
        // OWASP A03:2021 - SQL Injection
        rules.add(new VulnerabilityRule(
            "OWASP-A03-001",
            "SQL Injection",
            "A03:2021",
            "CRITICAL",
            "User input directly used in SQL queries without sanitization",
            Arrays.asList("PARAMETER", "HTTP_REQUEST"),
            Arrays.asList("execute", "query", "createQuery", "prepareStatement"),
            Arrays.asList("DATABASE_CALL", "METHOD_CALL"),
            Arrays.asList(),
            Arrays.asList("sanitize", "escape", "parameterized", "prepared")
        ));
        
        // OWASP A03:2021 - Command Injection
        rules.add(new VulnerabilityRule(
            "OWASP-A03-003",
            "Command Injection",
            "A03:2021",
            "CRITICAL",
            "User input used in system commands without sanitization",
            Arrays.asList("PARAMETER", "HTTP_REQUEST"),
            Arrays.asList("exec", "ProcessBuilder", "executeCommand", "system"),
            Arrays.asList("METHOD_CALL"),
            Arrays.asList("Runtime"),
            Arrays.asList("sanitize", "escape", "whitelist", "validate")
        ));
        
        // OWASP A01:2021 - Broken Access Control
        rules.add(new VulnerabilityRule(
            "OWASP-A01-002",
            "Insecure Direct Object Reference",
            "A01:2021",
            "HIGH",
            "User input directly used to access objects without validation",
            Arrays.asList("PARAMETER"),
            Arrays.asList("delete", "remove", "get", "find"),
            Arrays.asList("DATABASE_CALL", "FILE_ACCESS"),
            Arrays.asList(),
            Arrays.asList("validate", "authorize", "checkOwnership")
        ));
    }
    
    /**
     * Initialize severity weights and confidence factors
     */
    private void initializeWeights() {
        severityWeights = Map.of(
            "CRITICAL", 10.0,
            "HIGH", 7.0,
            "MEDIUM", 4.0,
            "LOW", 1.0
        );
        
        confidenceFactors = Map.of(
            "direct_flow", 1.0,
            "single_transformation", 0.8,
            "multiple_transformations", 0.6,
            "sanitization_present", 0.3
        );
    }
    
    /**
     * Analyze taint paths for OWASP vulnerabilities
     */
    public List<VulnerabilityFinding> analyzeVulnerabilities(JSONObject taintAnalysis) {
        List<VulnerabilityFinding> findings = new ArrayList<>();
        
        JSONArray taintedPaths = taintAnalysis.getJSONArray("taintedPaths");
        
        for (int i = 0; i < taintedPaths.length(); i++) {
            JSONObject path = taintedPaths.getJSONObject(i);
            
            // Extract path information
            TaintPath taintPath = parseTaintPath(path);
            
            // Check against each rule
            for (VulnerabilityRule rule : rules) {
                VulnerabilityFinding finding = evaluateRule(rule, taintPath);
                if (finding != null) {
                    findings.add(finding);
                }
            }
        }
        
        return findings;
    }
    
    /**
     * Parse taint path from JSON
     */
    private TaintPath parseTaintPath(JSONObject pathJson) {
        TaintPath path = new TaintPath();
        path.sourceId = pathJson.getInt("sourceId");
        path.sinkId = pathJson.getInt("sinkId");
        path.sourceName = pathJson.getString("sourceName");
        path.sinkName = pathJson.getString("sinkName");
        path.vulnerability = pathJson.getString("vulnerability");
        path.severity = pathJson.getString("severity");
        
        JSONArray pathNodes = pathJson.getJSONArray("pathNodes");
        path.nodes = new ArrayList<>();
        
        for (int i = 0; i < pathNodes.length(); i++) {
            JSONObject node = pathNodes.getJSONObject(i);
            PathNode pathNode = new PathNode();
            pathNode.name = node.getString("name");
            pathNode.id = node.getInt("id");
            pathNode.type = node.getString("type");
            if (node.has("scope")) {
                pathNode.scope = node.getString("scope");
            }
            path.nodes.add(pathNode);
        }
        
        return path;
    }
    
    /**
     * Evaluate a single rule against a taint path
     */
    private VulnerabilityFinding evaluateRule(VulnerabilityRule rule, TaintPath path) {
        double confidence = 0.0;
        List<String> matchReasons = new ArrayList<>();
        
        // Check source type match
        PathNode sourceNode = path.nodes.get(0);
        if (rule.sourceTypes.contains(sourceNode.type)) {
            confidence += 0.3;
            matchReasons.add("Source type matches: " + sourceNode.type);
        } else {
            return null; // No match
        }
        
        // Check sink pattern match
        PathNode sinkNode = path.nodes.get(path.nodes.size() - 1);
        boolean sinkMatches = false;
        
        // Check sink names
        for (String sinkName : rule.sinkNames) {
            if (sinkNode.name.toLowerCase().contains(sinkName.toLowerCase())) {
                confidence += 0.4;
                matchReasons.add("Sink name matches: " + sinkName);
                sinkMatches = true;
                break;
            }
        }
        
        // Check sink types
        if (rule.sinkTypes.contains(sinkNode.type)) {
            confidence += 0.2;
            matchReasons.add("Sink type matches: " + sinkNode.type);
            sinkMatches = true;
        }
        
        if (!sinkMatches) {
            return null; // No sink match
        }
        
        // Check sink scope if specified
        if (!rule.sinkScopes.isEmpty() && sinkNode.scope != null) {
            for (String scope : rule.sinkScopes) {
                if (sinkNode.scope.toLowerCase().contains(scope.toLowerCase())) {
                    confidence += 0.1;
                    matchReasons.add("Sink scope matches: " + scope);
                    break;
                }
            }
        }
        
        // Check for sanitization (reduces confidence)
        boolean sanitizationFound = false;
        for (PathNode node : path.nodes) {
            for (String sanitizer : rule.excludePatterns) {
                if (node.name.toLowerCase().contains(sanitizer.toLowerCase())) {
                    confidence *= 0.3; // Significantly reduce confidence
                    matchReasons.add("Sanitization detected: " + sanitizer);
                    sanitizationFound = true;
                    break;
                }
            }
        }
        
        // Check for sensitive data patterns (increases confidence for certain rules)
        if (rule.ruleId.contains("A02") || rule.ruleId.contains("sensitive")) {
            String[] sensitivePatterns = {"password", "token", "key", "secret", "ssn", "credit", "api"};
            for (String pattern : sensitivePatterns) {
                if (sourceNode.name.toLowerCase().contains(pattern)) {
                    confidence += 0.2;
                    matchReasons.add("Sensitive data pattern detected: " + pattern);
                    break;
                }
            }
        }
        
        // Apply path complexity factor
        String complexityType = getPathComplexity(path);
        confidence *= confidenceFactors.getOrDefault(complexityType, 0.5);
        
        // Calculate risk score
        double severityWeight = severityWeights.get(rule.severity);
        double riskScore = severityWeight * confidence;
        
        // Only report if confidence is above threshold
        if (confidence > 0.5) {
            return new VulnerabilityFinding(
                rule.ruleId,
                rule.name,
                rule.owaspCategory,
                rule.severity,
                rule.description,
                path,
                confidence,
                riskScore,
                matchReasons,
                generateRemediation(rule)
            );
        }
        
        return null;
    }
    
    /**
     * Determine path complexity
     */
    private String getPathComplexity(TaintPath path) {
        int nodeCount = path.nodes.size();
        if (nodeCount == 2) {
            return "direct_flow";
        } else if (nodeCount == 3) {
            return "single_transformation";
        } else {
            return "multiple_transformations";
        }
    }
    
    /**
     * Generate remediation advice
     */
    private String generateRemediation(VulnerabilityRule rule) {
        switch (rule.ruleId) {
            case "OWASP-A03-002":
                return "Sanitize user input before logging. Use structured logging with parameterized messages. Consider excluding sensitive data from logs.";
            case "OWASP-A02-001":
                return "Encrypt or hash sensitive data before logging. Implement data classification and masking policies.";
            case "OWASP-A03-001":
                return "Use parameterized queries or prepared statements. Implement input validation and SQL injection prevention measures.";
            case "OWASP-A03-003":
                return "Validate and sanitize all user input. Use whitelisting for allowed commands. Consider safer alternatives to system commands.";
            case "OWASP-A01-002":
                return "Implement proper authorization checks. Validate user permissions before accessing objects. Use indirect object references.";
            default:
                return "Review the identified vulnerability and implement appropriate security controls.";
        }
    }
    
    /**
     * Generate comprehensive report
     */
    public JSONObject generateReport(List<VulnerabilityFinding> findings) {
        JSONObject report = new JSONObject();
        
        // Summary statistics
        Map<String, Integer> severityCounts = new HashMap<>();
        Map<String, Integer> categoryCounts = new HashMap<>();
        
        for (VulnerabilityFinding finding : findings) {
            severityCounts.merge(finding.severity, 1, Integer::sum);
            categoryCounts.merge(finding.owaspCategory, 1, Integer::sum);
        }
        
        JSONObject summary = new JSONObject();
        summary.put("totalFindings", findings.size());
        summary.put("severityBreakdown", new JSONObject(severityCounts));
        summary.put("owaspCategoryBreakdown", new JSONObject(categoryCounts));
        
        // Top risks
        findings.sort((a, b) -> Double.compare(b.riskScore, a.riskScore));
        
        JSONArray findingsArray = new JSONArray();
        for (VulnerabilityFinding finding : findings) {
            JSONObject findingJson = new JSONObject();
            findingJson.put("ruleId", finding.ruleId);
            findingJson.put("name", finding.name);
            findingJson.put("owaspCategory", finding.owaspCategory);
            findingJson.put("severity", finding.severity);
            findingJson.put("description", finding.description);
            findingJson.put("confidence", Math.round(finding.confidence * 100.0) / 100.0);
            findingJson.put("riskScore", Math.round(finding.riskScore * 100.0) / 100.0);
            findingJson.put("remediation", finding.remediation);
            findingJson.put("matchReasons", new JSONArray(finding.matchReasons));
            
            // Add taint path details
            JSONObject pathInfo = new JSONObject();
            pathInfo.put("sourceName", finding.taintPath.sourceName);
            pathInfo.put("sinkName", finding.taintPath.sinkName);
            pathInfo.put("pathLength", finding.taintPath.nodes.size());
            pathInfo.put("vulnerability", finding.taintPath.vulnerability);
            findingJson.put("taintPath", pathInfo);
            
            findingsArray.put(findingJson);
        }
        
        report.put("summary", summary);
        report.put("findings", findingsArray);
        report.put("timestamp", System.currentTimeMillis());
        report.put("analyzer", "OWASP Vulnerability Detector v1.0");
        
        return report;
    }
    
    /**
     * Print summary to console
     */
    public void printSummary(List<VulnerabilityFinding> findings) {
        System.out.println("\n🛡️  OWASP Vulnerability Analysis Results");
        System.out.println("=========================================");
        
        Map<String, Integer> severityCounts = new HashMap<>();
        for (VulnerabilityFinding finding : findings) {
            severityCounts.merge(finding.severity, 1, Integer::sum);
        }
        
        System.out.println("📊 Summary:");
        System.out.println("   Total Vulnerabilities: " + findings.size());
        System.out.println("   Critical: " + severityCounts.getOrDefault("CRITICAL", 0));
        System.out.println("   High: " + severityCounts.getOrDefault("HIGH", 0));
        System.out.println("   Medium: " + severityCounts.getOrDefault("MEDIUM", 0));
        System.out.println("   Low: " + severityCounts.getOrDefault("LOW", 0));
        
        System.out.println("\n🔍 Top Findings:");
        findings.sort((a, b) -> Double.compare(b.riskScore, a.riskScore));
        
        for (int i = 0; i < Math.min(5, findings.size()); i++) {
            VulnerabilityFinding finding = findings.get(i);
            System.out.printf("   %d. %s (%s) - Risk Score: %.2f\n", 
                i + 1, finding.name, finding.severity, finding.riskScore);
            System.out.printf("      Path: %s → %s\n", 
                finding.taintPath.sourceName, finding.taintPath.sinkName);
        }
        
        System.out.println("\n📝 Report saved to output file");
    }
    
    // Utility methods
    private static String readFile(String filename) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }
    
    private static void writeFile(String filename, String content) throws IOException {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(content);
        }
    }
    
    // Data classes
    static class VulnerabilityRule {
        String ruleId;
        String name;
        String owaspCategory;
        String severity;
        String description;
        List<String> sourceTypes;
        List<String> sinkNames;
        List<String> sinkTypes;
        List<String> sinkScopes;
        List<String> excludePatterns;
        
        public VulnerabilityRule(String ruleId, String name, String owaspCategory, String severity,
                               String description, List<String> sourceTypes, List<String> sinkNames,
                               List<String> sinkTypes, List<String> sinkScopes, List<String> excludePatterns) {
            this.ruleId = ruleId;
            this.name = name;
            this.owaspCategory = owaspCategory;
            this.severity = severity;
            this.description = description;
            this.sourceTypes = sourceTypes;
            this.sinkNames = sinkNames;
            this.sinkTypes = sinkTypes;
            this.sinkScopes = sinkScopes;
            this.excludePatterns = excludePatterns;
        }
    }
    
    static class TaintPath {
        int sourceId;
        int sinkId;
        String sourceName;
        String sinkName;
        String vulnerability;
        String severity;
        List<PathNode> nodes;
    }
    
    static class PathNode {
        String name;
        int id;
        String type;
        String scope;
    }
    
    static class VulnerabilityFinding {
        String ruleId;
        String name;
        String owaspCategory;
        String severity;
        String description;
        TaintPath taintPath;
        double confidence;
        double riskScore;
        List<String> matchReasons;
        String remediation;
        
        public VulnerabilityFinding(String ruleId, String name, String owaspCategory, String severity,
                                  String description, TaintPath taintPath, double confidence, double riskScore,
                                  List<String> matchReasons, String remediation) {
            this.ruleId = ruleId;
            this.name = name;
            this.owaspCategory = owaspCategory;
            this.severity = severity;
            this.description = description;
            this.taintPath = taintPath;
            this.confidence = confidence;
            this.riskScore = riskScore;
            this.matchReasons = matchReasons;
            this.remediation = remediation;
        }
    }
}