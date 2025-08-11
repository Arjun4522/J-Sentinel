package com.example.api_gateway.controller;

import com.example.api_gateway.service.TrackedVulnerabilityScanService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final TrackedVulnerabilityScanService scanService;

    public ScanController(TrackedVulnerabilityScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping
    public Mono<Map<String, Object>> triggerScan(@RequestBody Map<String, Object> config) {
        return scanService.triggerScan(config);
    }

    @DeleteMapping("/{scanId}")
    public Mono<ResponseEntity<Void>> deleteScan(@PathVariable String scanId) {
        return scanService.deleteScan(scanId)
                .then(Mono.defer(() -> Mono.just(ResponseEntity.noContent().<Void>build())))
                .onErrorResume(e -> Mono.just(
                    ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).<Void>build()
                ));
    }
}