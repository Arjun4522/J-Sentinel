package com.example.api_gateway.dto;

import java.util.List;

public class ProjectDTO {
    private String projectId;
    private String name;
    private long createdAt;
    private List<String> scanIds;
    private int scanCount;

    public ProjectDTO(String projectId, String name, long createdAt, List<String> scanIds, int scanCount) {
        this.projectId = projectId;
        this.name = name;
        this.createdAt = createdAt;
        this.scanIds = scanIds;
        this.scanCount = scanCount;
    }

    public String getProjectId() { return projectId; }
    public void setProjectId(String projectId) { this.projectId = projectId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public List<String> getScanIds() { return scanIds; }
    public void setScanIds(List<String> scanIds) { this.scanIds = scanIds; }
    public int getScanCount() { return scanCount; }
    public void setScanCount(int scanCount) { this.scanCount = scanCount; }
}