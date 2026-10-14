package com.example.demo.security.refresh;

import java.util.List;
//This record is used when we rotate refresh token we return a record obj so we can use the email and roles to create a new access token
public record RefreshTokenRotation(String username, List<String> roles, String rawToken) {
}
