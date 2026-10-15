package com.example.demo.security.web;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
//RECORD THAT HOLD THE LOGIN REQUEST
public record LoginRequest(
    @NotBlank @Size(max = 255) String username, 
    @NotBlank @Size(max = 72) String password) {

}
