package com.christabella.africahr.auth.repository;

import com.christabella.africahr.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
    List<User> findByRolesContainingIgnoreCase(String role);
}

