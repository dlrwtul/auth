package com.bongo.auth.controller;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.bongo.auth.dto.AuthenticationRequest;
import com.bongo.auth.dto.AuthenticationResponse;
import com.bongo.auth.entity.Role;
import com.bongo.auth.entity.User;
import com.bongo.auth.repository.RoleRepository;
import com.bongo.auth.repository.UserRepository;
import com.bongo.auth.service.JwtService;
import com.bongo.auth.service.JwtUserDetailService;
import com.bongo.auth.utils.enums.ERole;

import lombok.NoArgsConstructor;

@RestController
@RequestMapping(path = "/api/v1/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private JwtUserDetailService jwtUserDetailService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
	UserRepository userRepository;

    @Autowired
	RoleRepository roleRepository;

    @PostMapping("/login")
    public AuthenticationResponse authenticate(@RequestBody @Validated final AuthenticationRequest authenticationRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getLogin(), authenticationRequest.getPassword()));
        } catch (final BadCredentialsException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        final UserDetails userDetails = jwtUserDetailService.loadUserByUsername(authenticationRequest.getLogin());
        final AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setAccessToken(jwtService.generateToken(userDetails));
        return authenticationResponse;
    }

    @PostMapping("/user")
    public ResponseEntity<?> registerUser(@RequestBody @Validated final AuthenticationRequest authenticationRequest) {
        if (userRepository.existsByLogin(authenticationRequest.getLogin())) {
			return ResponseEntity
					.badRequest()
					.body(("Error: Email is already in use!"));
		}

        User user = new User(authenticationRequest.getLogin(), 
							 passwordEncoder.encode(authenticationRequest.getPassword()));

        Set<Role> roles = new HashSet<>();
        if (!roleRepository.existsByName(ERole.ROLE_USER)) {
            Role newRoleUser = new Role(ERole.ROLE_USER);
            roleRepository.save(newRoleUser);

        }
        Role role = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(role);
        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok().body(("User registered successfully!"));                   

    }

    @PostMapping("/admin")
    public ResponseEntity<?> registerAdmin(@RequestBody @Validated final AuthenticationRequest authenticationRequest) {
        if (userRepository.existsByLogin(authenticationRequest.getLogin())) {
			return ResponseEntity
					.badRequest()
					.body(("Error: Email is already in use!"));
		}

        User user = new User(authenticationRequest.getLogin(), 
							 passwordEncoder.encode(authenticationRequest.getPassword()));
        Set<Role> roles = new HashSet<>();
        if (!roleRepository.existsByName(ERole.ROLE_ADMIN)) {
            Role newRoleUser = new Role(ERole.ROLE_ADMIN);
            roleRepository.save(newRoleUser);

        }
        Role roleAdmin = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(roleAdmin);

        if (!roleRepository.existsByName(ERole.ROLE_USER)) {
            Role newRoleUser = new Role(ERole.ROLE_USER);
            roleRepository.save(newRoleUser);
        }
        Role roleUSer = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(roleUSer);
        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok().body(("User registered successfully!"));                   

    }

    @GetMapping("/bongo")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> bongo() {
        return ResponseEntity.ok().body(("Tested!"));    
    }
}
