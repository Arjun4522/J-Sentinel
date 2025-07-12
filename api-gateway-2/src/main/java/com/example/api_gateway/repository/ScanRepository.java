package com.example.api_gateway.repository;

import com.example.api_gateway.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ScanRepository extends JpaRepository<Scan, String> {
    List<Scan> findByProject_ProjectId(String projectId);
    void deleteById(String scanId);

}

