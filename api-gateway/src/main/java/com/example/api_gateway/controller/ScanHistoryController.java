// ScanHistoryController.java
package com.example.api_gateway.controller;

import com.example.api_gateway.service.ScanHistoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/history")
@CrossOrigin
public class ScanHistoryController {

    private final ScanHistoryService scanHistoryService;

    public ScanHistoryController(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    @GetMapping("/scans")
    public Mono<ResponseEntity<List<Map<String, Object>>>> getAllScanHistory() {
        return scanHistoryService.getAllScanHistory()
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.noContent().build());
    }

    @GetMapping("/directory/{directory}")
    public Mono<ResponseEntity<Map<String, Object>>> getDirectoryHistory(
            @PathVariable String directory) {
        return scanHistoryService.getDirectoryHistory(directory)
                .map(history -> history != null ? 
                    ResponseEntity.ok(history) : 
                    ResponseEntity.notFound().build());
    }
}