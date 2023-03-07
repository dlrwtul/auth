package com.bongo.auth.service;

import com.bongo.auth.entity.JwtUserDetails;
import com.bongo.auth.entity.User;
import com.bongo.auth.repository.UserRepository;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;


    @Override
    public JwtUserDetails loadUserByUsername(final String username) {
        final User user = userRepository.findByLogin(username).orElseThrow(
                () -> new UsernameNotFoundException("User " + username + " not found"));
        return new JwtUserDetails(user.getId(), username, user.getPassword(), new ArrayList<>());
    }
}
