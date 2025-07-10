package com.example.api_gateway.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.api_gateway.model.Scan;

public interface ScanRepository extends JpaRepository<Scan, String> {
    List<Scan> findByProject_ProjectId(String projectId);
}
