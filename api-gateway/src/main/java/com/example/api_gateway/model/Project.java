package com.example.api_gateway.model;

public class Project {
    private String projectId;
    private String name;
    private long createdAt;

    public Project() {
    }

    public Project(String projectId, String name, long createdAt) {
        this.projectId = projectId;
        this.name = name;
        this.createdAt = createdAt;
    }

    public String getProjectId() {
        return projectId;
    }

    public void setProjectId(String projectId) {
        this.projectId = projectId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }
}
