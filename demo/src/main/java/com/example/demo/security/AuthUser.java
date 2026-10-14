package com.example.demo.security;

import org.springframework.security.core.userdetails.UserDetails;
/*THIS INTERFACE EXTENDS USER DETAILS AND ADD A METHODE getUserID
WE USE IT BECAUSE WE NEED THE ID FROM USER DETAILS FOR REFRESH TOKEN
*/
public interface AuthUser extends UserDetails {
    String getUserId();
}
