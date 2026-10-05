package com.example.demo.RefreshToken;

public class InvalidToken extends RuntimeException {

    public InvalidToken(String message) {
        super(message);
    }
}
