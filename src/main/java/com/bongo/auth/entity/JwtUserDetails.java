package com.bongo.auth.entity;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class JwtUserDetails extends User {

    public final Long id;

    public JwtUserDetails(final Long id, final String username, final String hash,
                          final Collection<? extends GrantedAuthority> authorities) {
        super(username, hash, authorities);
        this.id = id;
    }

}
