package com.example.demo.User;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

import com.example.demo.Security.AuthUser;

public class AppAuthUser extends org.springframework.security.core.userdetails.User implements AuthUser {
    //The Subject is the user ID
    private final String subject;

    //This is UserDetails OBJ + USER_ID(Subject)
    public AppAuthUser(String username, String password, Collection<? extends GrantedAuthority> authorities, String subject) {
        super(username, password, authorities);
        this.subject = subject;
    }

    @Override
    public String getUserId(){
        return subject;
    }
    

}
