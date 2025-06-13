// api-gateway/src/main/java/com/example/api_gateway/service/ScanMetadataStore.java
package com.example.api_gateway.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ScanMetadataStore {
    private final Map<String, ScanMetadata> metadataStore = new ConcurrentHashMap<>();
    private final Map<String, String> reportStore = new ConcurrentHashMap<>();

    public static class ScanMetadata {
        private String scanId;
        private String sourceDir;
        private String rulesDir;
        private long startTime;
        private long endTime;
        private String status;
        private int filesProcessed;
        private int vulnerabilitiesFound;

        // Constructors, getters, and setters
        public ScanMetadata() {}

        public ScanMetadata(String scanId, String sourceDir, String rulesDir, long startTime, 
                           String status, int filesProcessed, int vulnerabilitiesFound) {
            this.scanId = scanId;
            this.sourceDir = sourceDir;
            this.rulesDir = rulesDir;
            this.startTime = startTime;
            this.status = status;
            this.filesProcessed = filesProcessed;
            this.vulnerabilitiesFound = vulnerabilitiesFound;
        }

        // Add all getters and setters
        public String getScanId() { return scanId; }
        public void setScanId(String scanId) { this.scanId = scanId; }
        public String getSourceDir() { return sourceDir; }
        public void setSourceDir(String sourceDir) { this.sourceDir = sourceDir; }
        public String getRulesDir() { return rulesDir; }
        public void setRulesDir(String rulesDir) { this.rulesDir = rulesDir; }
        public long getStartTime() { return startTime; }
        public void setStartTime(long startTime) { this.startTime = startTime; }
        public long getEndTime() { return endTime; }
        public void setEndTime(long endTime) { this.endTime = endTime; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public int getFilesProcessed() { return filesProcessed; }
        public void setFilesProcessed(int filesProcessed) { this.filesProcessed = filesProcessed; }
        public int getVulnerabilitiesFound() { return vulnerabilitiesFound; }
        public void setVulnerabilitiesFound(int vulnerabilitiesFound) { this.vulnerabilitiesFound = vulnerabilitiesFound; }
    }

    public void saveMetadata(String scanId, ScanMetadata metadata) {
        metadataStore.put(scanId, metadata);
    }

    public void saveReport(String scanId, String report) {
        reportStore.put(scanId, report);
    }

    public ScanMetadata getMetadata(String scanId) {
        return metadataStore.get(scanId);
    }

    public String getReport(String scanId) {
        return reportStore.get(scanId);
    }

    public Map<String, ScanMetadata> getAllMetadata() {
        return new ConcurrentHashMap<>(metadataStore);
    }

    public void updateStatus(String scanId, String status) {
        ScanMetadata metadata = metadataStore.get(scanId);
        if (metadata != null) {
            metadata.setStatus(status);
            if ("COMPLETED".equals(status) || "FAILED".equals(status)) {
                metadata.setEndTime(System.currentTimeMillis());
            }
        }
    }
}