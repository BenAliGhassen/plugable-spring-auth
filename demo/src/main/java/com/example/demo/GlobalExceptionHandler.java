package com.example.demo;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.MethodArgumentNotValidException;

import com.example.demo.RefreshToken.InvalidToken;
import com.example.demo.User.InvalidCredentials;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidToken.class)
    public ResponseEntity<Void> handleInvalidToken() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @ExceptionHandler(InvalidCredentials.class)
    public ResponseEntity<Void> handleInvalidCredentials() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, List<String>>> handleInvalidFields(MethodArgumentNotValidException exception) {
        Map<String, List<String>> errors = new LinkedHashMap<>();
        for (FieldError fieldError : exception.getBindingResult().getFieldErrors()) {
            errors.computeIfAbsent(fieldError.getField(), field -> new ArrayList<>())
                    .add(fieldError.getDefaultMessage() == null ? "Invalid value" : fieldError.getDefaultMessage());
        }

        return ResponseEntity.badRequest().body(errors);
    }
}
