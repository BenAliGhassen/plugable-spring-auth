package com.example.demo.Csrf;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;



//CSRF CONTROLLER IS USED TO CALL THE /csrf ENDPOINT TO GET A CSRF TOKEN
@RestController
public class CsrfController {

    @GetMapping("/csrf")
    public ResponseEntity<Void> getCsrf(CsrfToken csrf) {
        csrf.getToken();
        return ResponseEntity.noContent().build();
    }  
}
