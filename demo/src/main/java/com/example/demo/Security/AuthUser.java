package com.example.demo.Security;

import org.springframework.security.core.userdetails.UserDetails;
/*THIS IS AN ADAPTER IT EXTENDS USER DETAILS AND ADD A METHODE getUserID
WE USE IT BECAUSE WE NEED THE ID FROM USER DETAILS FOR REFRESH TOKEN
*/
public interface AuthUser extends UserDetails {
    String getUserId();
}
