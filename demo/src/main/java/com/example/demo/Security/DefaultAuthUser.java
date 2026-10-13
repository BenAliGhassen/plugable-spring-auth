package com.example.demo.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

public class DefaultAuthUser extends org.springframework.security.core.userdetails.User implements AuthUser {
//This class make any user entity work with our tokens logic it says what our token logic need
    private final String userId;

    //This is UserDetails OBJ + USER_ID
    public DefaultAuthUser(String username, String password, Collection<? extends GrantedAuthority> authorities, String userId) {
        super(username, password, authorities);
        this.userId = userId;
    }

    @Override
    public String getUserId(){
        return userId;
    }
    

}
