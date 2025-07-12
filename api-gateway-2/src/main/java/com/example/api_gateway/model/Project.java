package com.example.api_gateway.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "projects")
public class Project {
    @Id
    private String projectId;
    private String name;
    private long createdAt;
    private int scanCount;

    public String getProjectId() { return projectId; }
    public void setProjectId(String projectId) { this.projectId = projectId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public int getScanCount() { return scanCount; }
    public void setScanCount(int scanCount) { this.scanCount = scanCount; }
}