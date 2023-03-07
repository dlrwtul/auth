package com.bongo.auth.dto;

import lombok.Data;
import lombok.NonNull;

@Data
public class AuthenticationRequest {

    @NonNull
    private String login;

    @NonNull
    private String password;
}
