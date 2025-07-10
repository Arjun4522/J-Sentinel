package com.example.api_gateway.service;

import com.example.api_gateway.model.Project;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ProjectService {
    private final Map<String, Project> projectStore = new ConcurrentHashMap<>();
    private final Map<String, List<String>> projectScans = new ConcurrentHashMap<>();

    public String createProject(Project project) {
        String projectId = UUID.randomUUID().toString();
        project.setProjectId(projectId);
        project.setCreatedAt(System.currentTimeMillis());
        projectStore.put(projectId, project);
        return projectId;
    }

    public Project getProject(String projectId) {
        return projectStore.get(projectId);
    }

    public void addScanToProject(String projectId, String scanId) {
        projectScans.computeIfAbsent(projectId, k -> new ArrayList<>()).add(scanId);
    }

    public List<String> getProjectScanIds(String projectId) {
        return projectScans.getOrDefault(projectId, Collections.emptyList());
    }

    public Collection<Project> getAllProjects() {
    return projectStore.values();
    }

}
