package com.example.demo.Csrf;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;




@RestController
public class CsrfController {

    @GetMapping("/csrf")
    public ResponseEntity<Void> getCsrf(CsrfToken csrf) {
        csrf.getToken();
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/hello")
    public String Hello() {
        return "Hello";
    }
    
    

}
