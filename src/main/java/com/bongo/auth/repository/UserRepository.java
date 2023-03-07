package com.bongo.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bongo.auth.entity.User;

public interface UserRepository extends JpaRepository<User, Long>  {
    Optional<User> findByLogin(String login);
}
