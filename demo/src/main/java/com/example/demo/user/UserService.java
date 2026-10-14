package com.example.demo.user;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.demo.user.records.UserRequest;

@Service
public class UserService {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;


    public User getUser(String email){
        return userRepo.findByEmail(email.trim().toLowerCase()).orElseThrow(() -> new InvalidCredentials("Invalid email or password"));
    }

    public UserService(UserRepository userRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
    }

    public boolean createUser(UserRequest userReq) {
        String email = userReq.email().trim().toLowerCase();
        if (userRepo.findByEmail(email).isPresent()) {
            return false;
        }

        String hashedPassword = passwordEncoder.encode(userReq.password());
        User user = new User(userReq.name(), email, hashedPassword);
        userRepo.save(user);
        return true;
    }
}
