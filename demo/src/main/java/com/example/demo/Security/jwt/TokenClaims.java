package com.example.demo.security.jwt;

import java.util.List;
//THIS RECORD WILL CONTAINS THE WT TOKEN CLAIMS USERNAME AND ROLES
public record TokenClaims(String username, List<String> roles) {}
