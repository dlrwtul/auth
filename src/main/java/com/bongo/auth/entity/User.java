package com.bongo.auth.entity;

import jakarta.annotation.Generated;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;

@Entity
@Data
@AllArgsConstructor
@Table( name = "users")
public class User {

    @GeneratedValue
    @Id
    private Long id;

    @Column(name = "login")
    @NonNull
    private String login;

    @Column(name = "password")
    @NonNull
    private String password;
}
