package com.example.demo.User;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

import com.example.demo.Security.AuthUser;

public class AppAuthUser extends org.springframework.security.core.userdetails.User implements AuthUser {
//This is the adapter it adapt any user entity to work with our tokens logic
    private final String userId;

    //This is UserDetails OBJ + USER_ID
    public AppAuthUser(String username, String password, Collection<? extends GrantedAuthority> authorities, String userId) {
        super(username, password, authorities);
        this.userId = userId;
    }

    @Override
    public String getUserId(){
        return userId;
    }
    

}
