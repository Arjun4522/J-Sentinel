package com.example.api_gateway.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.api_gateway.model.Project;

public interface ProjectRepository extends JpaRepository<Project, String> {
}
