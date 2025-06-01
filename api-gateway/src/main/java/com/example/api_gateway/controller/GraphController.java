package com.example.api_gateway.controller;

import com.example.api_gateway.service.GraphStorageService;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
public class GraphController {

    private final GraphStorageService graphStorageService;

    public GraphController(GraphStorageService graphStorageService) {
        this.graphStorageService = graphStorageService;
    }

    @PostMapping("/scan")
    public Mono<ResponseEntity<String>> uploadGraph(@RequestBody String codeGraphJson) {
        try {
            JSONObject codeGraph = new JSONObject(codeGraphJson);
            String scanId = codeGraph.getString("scanId");
            graphStorageService.storeGraph(scanId, codeGraph);
            return Mono.just(ResponseEntity.ok("Code graph uploaded successfully for scanId: " + scanId));
        } catch (Exception e) {
            return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("Failed to upload code graph: " + e.getMessage()));
        }
    }

    @GetMapping("/graph")
    public Mono<ResponseEntity<String>> getGraph(@RequestParam String scanId) {
        JSONObject graph = graphStorageService.getGraph(scanId);
        if (graph == null) {
            return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("Code graph not found for scanId: " + scanId));
        }
        return Mono.just(ResponseEntity.ok(graph.toString()));
    }

    @GetMapping("/cfg")
    public Mono<ResponseEntity<String>> getCFG(@RequestParam String scanId) {
        JSONObject cfg = graphStorageService.getCFG(scanId);
        if (cfg == null) {
            return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("CFG not found for scanId: " + scanId));
        }
        return Mono.just(ResponseEntity.ok(cfg.toString()));
    }

    @GetMapping("/dfg")
    public Mono<ResponseEntity<String>> getDFG(@RequestParam String scanId) {
        JSONObject dfg = graphStorageService.getDFG(scanId);
        if (dfg == null) {
            return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("DFG not found for scanId: " + scanId));
        }
        return Mono.just(ResponseEntity.ok(dfg.toString()));
    }

    @GetMapping("/ast")
    public Mono<ResponseEntity<String>> getAST(@RequestParam String scanId) {
        JSONObject ast = graphStorageService.getAST(scanId);
        if (ast == null) {
            return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("AST not found for scanId: " + scanId));
        }
        return Mono.just(ResponseEntity.ok(ast.toString()));
    }
    @GetMapping("/health")
    public Mono<ResponseEntity<String>> health() {
        return Mono.just(ResponseEntity.ok("API Gateway is running"));
}
}