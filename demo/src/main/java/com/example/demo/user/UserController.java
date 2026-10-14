package com.example.demo.user;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RestController;
import com.example.demo.user.records.UserRequest;
import com.example.demo.user.records.UserResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;



@RestController 
public class UserController {
    private final UserService userServ;

        public UserController(UserService userServ){
            this.userServ = userServ;
        }


        @PostMapping("/signup")
        public ResponseEntity<String> register(@Valid @RequestBody UserRequest user) {
            boolean result = userServ.createUser(user);

            if(result){
                return ResponseEntity.status(HttpStatus.CREATED).body("user created");
            }else{
                return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exist");
            }

            
        }


        @GetMapping("/me")
        public ResponseEntity<UserResponse> getMe(Authentication auth) {
            User user = userServ.getUser(auth.getName());
            return ResponseEntity.ok(new UserResponse(user.getName(), user.getEmail()));
        }

}
