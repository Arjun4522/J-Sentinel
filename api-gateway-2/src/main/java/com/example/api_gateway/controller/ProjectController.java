package com.example.api_gateway.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.example.api_gateway.dto.ProjectDTO;
import com.example.api_gateway.model.Project;
import com.example.api_gateway.service.ProjectService;

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
        return projectService.getProjectById(projectId);
    }

    @GetMapping("/{projectId}/scans")
    public List<String> getProjectScans(@PathVariable String projectId) {
        return projectService.getProjectScanIds(projectId);
    }

    @PostMapping("/{projectId}/scan")
    public Map<String, String> createScan(@PathVariable String projectId) {
        String scanId = projectService.createScanForProject(projectId);
        return Map.of("scanId", scanId);
    }

    @GetMapping
    public List<ProjectDTO> getAllProjects() {
        return projectService.getAllProjectDTOs();
    }

    @DeleteMapping("/{projectId}")
    public void deleteProject(@PathVariable String projectId) {
        projectService.deleteProject(projectId);
    }

}