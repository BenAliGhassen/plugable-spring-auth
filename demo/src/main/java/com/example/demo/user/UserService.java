package com.example.demo.user;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.security.refresh.RefreshService;
import com.example.demo.user.records.UserRequest;

@Service
public class UserService {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final RefreshService refreshService;


    public User getUser(String email){
        return userRepo.findByEmail(email.trim().toLowerCase()).orElseThrow(() -> new InvalidCredentials("Invalid email or password"));
    }

    public UserService(UserRepository userRepo, PasswordEncoder passwordEncoder, RefreshService refreshService) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.refreshService = refreshService;
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

    public void logout(String raw) {
        refreshService.revoke(raw);
    }

    public void logoutAllAccounts(String raw){
        refreshService.revokeAll(raw);
    }
}
