package com.example.demo.Security;

import org.springframework.security.core.userdetails.UserDetails;

public interface AuthUser extends UserDetails {
    String getUserId();
}
