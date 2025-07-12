package com.example.api_gateway.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.api_gateway.repository.ScanRepository;
import com.example.api_gateway.service.TrackedVulnerabilityScanService;

import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    @Autowired
    private TrackedVulnerabilityScanService scanService;

    @Autowired
    private ScanRepository scanRepository;

    @PostMapping
    public Mono<Map<String, Object>> triggerScan(@RequestBody Map<String, Object> config) {
        return scanService.triggerScan(config);
    }

    // 🆕 Delete scan by ID
    @DeleteMapping("/{scanId}")
    public void deleteScan(@PathVariable String scanId) {
        scanRepository.deleteById(scanId);
    }
}
