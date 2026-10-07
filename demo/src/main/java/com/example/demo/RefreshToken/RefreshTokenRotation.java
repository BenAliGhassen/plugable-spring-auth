package com.example.demo.RefreshToken;

import java.util.List;

public record RefreshTokenRotation(String userEmail, List<String> roles, String rawToken) {
}
