package com.example.api_gateway.controller;

import com.example.api_gateway.model.Project;
import com.example.api_gateway.service.ProjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/projects")
public class ProjectController {

    @Autowired
    private ProjectService projectService;

    @PostMapping("/create")
    public Map<String, String> createProject(@RequestBody Project project) {
        String projectId = projectService.createProject(project);
        return Map.of("projectId", projectId);
    }

    @GetMapping("/{projectId}")
    public Project getProject(@PathVariable String projectId) {
        return projectService.getProject(projectId);
    }

    @GetMapping("/{projectId}/scans")
    public List<String> getProjectScans(@PathVariable String projectId) {
        return projectService.getProjectScanIds(projectId);
    }

    @GetMapping
    public List<Project> getAllProjects() {
        return new ArrayList<>(projectService.getAllProjects());
}

}
