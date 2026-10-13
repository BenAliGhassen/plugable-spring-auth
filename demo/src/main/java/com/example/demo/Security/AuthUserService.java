package com.example.demo.Security;

import org.springframework.security.core.userdetails.UserDetailsService;
//ADAPTER THAT EXTEND USER DETAILS SERVICE AND ADD LoadUserById IT'S THE BRIDGE BETWEEN THE PROJECT AND TEMPLATE USED BY THE AppUserDetailsService.
public interface AuthUserService extends UserDetailsService {
    AuthUser loadUserById(String userId);

}
