// src/main/java/com/example/api_gateway/dto/ProjectDTO.java
package com.example.api_gateway.dto;

import java.util.List;

public class ProjectDTO {
    public String projectId;
    public String name;
    public long createdAt;
    public List<String> scanIds;

    public ProjectDTO(String projectId, String name, long createdAt, List<String> scanIds) {
        this.projectId = projectId;
        this.name = name;
        this.createdAt = createdAt;
        this.scanIds = scanIds;
    }
}
