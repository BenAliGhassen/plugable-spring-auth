package com.example.demo.JWT;

import java.util.List;

public record TokenClaims(String subject, List<String> roles) {}
