package com.example.demo.RefreshToken;

//INVALID TOKEN EXCEPTION
public class InvalidToken extends RuntimeException {

    public InvalidToken(String message) {
        super(message);
    }
}
