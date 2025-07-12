package com.example.api_gateway.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "scans")
public class Scan {
    @Id
    private String scanId;
    
    @ManyToOne
    private Project project;

    // Default constructor required by JPA
    public Scan() {
    }

    // Constructor with Project parameter
    public Scan(Project project) {
        this.project = project;
        this.scanId = java.util.UUID.randomUUID().toString();
    }

    // Getters and setters
    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }
    public Project getProject() { return project; }
    public void setProject(Project project) { this.project = project; }
}