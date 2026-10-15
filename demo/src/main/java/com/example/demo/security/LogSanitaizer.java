package com.example.demo.security;

import org.springframework.stereotype.Component;

@Component 
public class LogSanitaizer {
    private LogSanitaizer(){}

    public String cleanString(String value){
        return value == null ? "null" : value;
    }
}
