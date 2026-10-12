package com.example.demo.Security;

import org.springframework.security.core.userdetails.UserDetails;
//THIS IS AN ADAPTER IT EXTENDS USER DETAILS AND ADD A METHODE getUserID 
public interface AuthUser extends UserDetails {
    String getUserId();
}
