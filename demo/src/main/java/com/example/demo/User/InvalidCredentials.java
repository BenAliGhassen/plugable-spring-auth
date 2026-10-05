package com.example.demo.User;

public class InvalidCredentials extends RuntimeException {

    public InvalidCredentials(String message) {
        super(message);
    }
}
