package com.example.api_gateway.service;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.api_gateway.dto.ProjectDTO;
import com.example.api_gateway.model.Project;
import com.example.api_gateway.model.Scan;
import com.example.api_gateway.repository.ProjectRepository;
import com.example.api_gateway.repository.ScanRepository;

@Service
public class ProjectService {

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private ScanRepository scanRepository;

    public List<ProjectDTO> getAllProjectDTOs() {
        List<Project> projects = projectRepository.findAll();

        return projects.stream().map(project -> {
            List<String> scanIds = scanRepository.findByProject_ProjectId(project.getProjectId())
                    .stream()
                    .map(Scan::getScanId)
                    .toList();

            return new ProjectDTO(
                    project.getProjectId(),
                    project.getName(),
                    project.getCreatedAt(),
                    scanIds
            );
        }).toList();
    }

    public String createProject(Project project) {
        String projectId = UUID.randomUUID().toString();
        project.setProjectId(projectId);
        project.setCreatedAt(System.currentTimeMillis());
        projectRepository.save(project);
        return projectId;
    }

    public Project getProjectById(String projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found"));
    }

    public String createScanForProject(String projectId) {
        Project project = projectRepository.findById(projectId).orElseThrow();
        Scan scan = new Scan(project);
        scanRepository.save(scan);
        return scan.getScanId();
    }

    public List<String> getProjectScanIds(String projectId) {
        return scanRepository.findByProject_ProjectId(projectId)
                .stream()
                .map(Scan::getScanId)
                .toList();
    }
}
