package com.example.demo.security.web;
import jakarta.validation.constraints.NotBlank;
//RECORD THAT HOLD THE LOGIN REQUEST
public record LoginRequest(
    @NotBlank String email, 
    @NotBlank String password) {

}
