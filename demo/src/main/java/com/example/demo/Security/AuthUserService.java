package com.example.demo.Security;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface AuthUserService extends UserDetailsService {
    AuthUser loadUserById(String subject);

}
