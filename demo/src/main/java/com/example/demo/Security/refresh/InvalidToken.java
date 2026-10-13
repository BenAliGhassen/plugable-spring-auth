package com.example.demo.security.refresh;

//INVALID TOKEN EXCEPTION
public class InvalidToken extends RuntimeException {

    public InvalidToken(String message) {
        super(message);
    }
}
