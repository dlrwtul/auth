package com.bongo.auth.entity;


import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table( name = "users" ,
uniqueConstraints = { 
    @UniqueConstraint(columnNames = "login"),
})
public class User {

    @GeneratedValue
    @Id
    private Long id;

    @Column(name = "login")
    @NotBlank
    private String login;

    @Column(name = "password")
    @NotBlank
    private String password;

    @ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(	name = "user_roles", 
				joinColumns = @JoinColumn(name = "user_id"), 
				inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new HashSet<>();

    public User(@NotBlank String login, @NotBlank String password) {
        this.login = login;
        this.password = password;
    }

}
