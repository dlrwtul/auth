package com.bongo.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.bongo.auth.dto.AuthenticationRequest;
import com.bongo.auth.dto.AuthenticationResponse;
import com.bongo.auth.service.JwtService;
import com.bongo.auth.service.JwtUserDetailService;

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

    // public AuthController(AuthenticationManager authenticationManager,JwtService jwtService,JwtUserDetailService jwtUserDetailService) {
    //     this.authenticationManager = authenticationManager;
    //     this.jwtService = jwtService;
    //     this.jwtUserDetailService = jwtUserDetailService;
    // }

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
}
