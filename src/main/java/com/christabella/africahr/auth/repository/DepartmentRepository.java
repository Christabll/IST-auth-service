package com.christabella.africahr.auth.repository;

import com.christabella.africahr.auth.entity.Department;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DepartmentRepository extends JpaRepository<Department, String> {
    boolean existsByName(String name);
}
