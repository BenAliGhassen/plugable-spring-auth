package com.example.demo.Security;

import org.springframework.security.core.userdetails.UserDetailsService;
//ADAPTER THAT EXTEND USER DETAILS SERVICE AND ADD LoadUserById
public interface AuthUserService extends UserDetailsService {
    AuthUser loadUserById(String userId);

}
