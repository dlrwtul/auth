package com.bongo.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bongo.auth.entity.Role;
import com.bongo.auth.utils.enums.ERole;

public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
	Boolean existsByName(ERole name);

}
