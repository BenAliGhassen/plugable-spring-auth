package com.example.demo.security;


public final class LogSanitizer {
    private LogSanitizer(){}

    public static  String cleanString(String value){
        return value == null ? "null" : value.replaceAll("[\r\n]", "_");
    }
}
