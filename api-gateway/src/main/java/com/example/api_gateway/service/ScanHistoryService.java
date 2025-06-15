// ScanHistoryService.java
package com.example.api_gateway.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ScanHistoryService {
    private static final String DB_URL = "jdbc:sqlite:/home/arjun/Desktop/J-Sentinel/rule-engine/reports/data.db";

    public Mono<List<Map<String, Object>>> getAllScanHistory() {
        return Mono.fromCallable(() -> {
            List<Map<String, Object>> scans = new ArrayList<>();
            System.out.println("Attempting to connect to: " + DB_URL); // Add logging
            
            try (Connection conn = DriverManager.getConnection(DB_URL);
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT * FROM scans ORDER BY timestamp DESC")) {
                
                System.out.println("Connection successful, executing query"); // Add logging
                while (rs.next()) {
                    Map<String, Object> scan = new HashMap<>();
                    scan.put("scanId", rs.getString("scanId"));
                    scan.put("sourceDirectory", rs.getString("source_directory"));
                    scan.put("filesProcessed", rs.getInt("filesProcessed"));
                    scan.put("vulnerabilitiesFound", rs.getInt("vulnerabilitiesFound"));
                    scan.put("duration", rs.getInt("duration") + "s");
                    scan.put("timestamp", rs.getString("timestamp"));
                    scans.add(scan);
                }
            } catch (SQLException e) {
                System.err.println("Database error: " + e.getMessage());
                e.printStackTrace();
                throw e;
            }
            return scans;
        }).onErrorMap(e -> {
            System.err.println("Error in getAllScanHistory: " + e.getMessage());
            return new RuntimeException("Failed to retrieve scan history", e);
        });
    }

    public Mono<Map<String, Object>> getDirectoryHistory(String directory) {
        return Mono.fromCallable(() -> {
            try (Connection conn = DriverManager.getConnection(DB_URL);
                 PreparedStatement stmt = conn.prepareStatement(
                     "SELECT * FROM directory_history WHERE directory = ?")) {
                
                stmt.setString(1, directory);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        Map<String, Object> history = new HashMap<>();
                        history.put("directory", rs.getString("directory"));
                        history.put("firstScan", rs.getString("first_scan"));
                        history.put("lastScan", rs.getString("last_scan"));
                        history.put("scanCount", rs.getInt("scan_count"));
                        return history;
                    }
                }
            }
            return null;
        });
    }
}