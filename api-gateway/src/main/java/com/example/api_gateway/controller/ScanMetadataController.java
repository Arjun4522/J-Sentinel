package com.example.api_gateway.controller;

import com.example.api_gateway.service.ScanMetadataStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/scans")
@CrossOrigin // Optional: for frontend access
public class ScanMetadataController {

    private final ScanMetadataStore metadataStore;

    public ScanMetadataController(ScanMetadataStore metadataStore) {
        this.metadataStore = metadataStore;
    }

    @GetMapping
    public Mono<ResponseEntity<List<Map<String, Object>>>> getAllScans() {
        return Mono.just(ResponseEntity.ok(
            metadataStore.getAllMetadata().values().stream()
                .map(metadata -> {
                    Map<String, Object> data = new HashMap<>();
                    data.put("scanId", metadata.getScanId());
                    data.put("sourceDir", metadata.getSourceDir());
                    data.put("rulesDir", metadata.getRulesDir());
                    data.put("startTime", metadata.getStartTime());
                    data.put("endTime", metadata.getEndTime());
                    data.put("status", metadata.getStatus());
                    data.put("filesProcessed", metadata.getFilesProcessed());
                    data.put("vulnerabilitiesFound", metadata.getVulnerabilitiesFound());
                    data.put("duration", formatDuration(metadata.getStartTime(), metadata.getEndTime()));
                    return data;
                })
                .collect(Collectors.toList())
        ));
    }

    @GetMapping("/{scanId}/metadata")
    public Mono<ResponseEntity<Map<String, Object>>> getScanMetadata(@PathVariable String scanId) {
        ScanMetadataStore.ScanMetadata metadata = metadataStore.getMetadata(scanId);
        if (metadata == null) {
            return Mono.just(ResponseEntity.notFound().build());
        }

        Map<String, Object> data = new HashMap<>();
        data.put("scanId", metadata.getScanId());
        data.put("sourceDir", metadata.getSourceDir());
        data.put("rulesDir", metadata.getRulesDir());
        data.put("startTime", metadata.getStartTime());
        data.put("endTime", metadata.getEndTime());
        data.put("status", metadata.getStatus());
        data.put("filesProcessed", metadata.getFilesProcessed());
        data.put("vulnerabilitiesFound", metadata.getVulnerabilitiesFound());
        data.put("duration", formatDuration(metadata.getStartTime(), metadata.getEndTime()));

        return Mono.just(ResponseEntity.ok(data));
    }

    @GetMapping("/{scanId}/report")
    public Mono<ResponseEntity<String>> getScanReport(@PathVariable String scanId) {
        String report = metadataStore.getReport(scanId);
        if (report == null) {
            return Mono.just(ResponseEntity.notFound().build());
        }
        return Mono.just(ResponseEntity.ok(report));
    }

    private String formatDuration(long start, long end) {
        if (end > 0 && start > 0 && end > start) {
            long seconds = (end - start) / 1000;
            return seconds + "s";
        }
        return "N/A";
    }
}
