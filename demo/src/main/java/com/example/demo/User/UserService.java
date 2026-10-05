package com.example.demo.User;

import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.demo.RefreshToken.RefreshService;
import com.example.demo.User.Records.LoginRequest;
import com.example.demo.User.Records.UserRequest;

@Service
public class UserService {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final RefreshService refreshService;

    public UserService(UserRepository userRepo, PasswordEncoder passwordEncoder, RefreshService refreshService) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.refreshService = refreshService;
    }

    public Boolean createUser(UserRequest userReq) {
        if (userRepo.findByEmail(userReq.email()).isPresent()) {
            return false;
        }

        String hashedPassword = passwordEncoder.encode(userReq.password());
        User user = new User(userReq.name(), userReq.email(), hashedPassword);
        userRepo.save(user);
        return true;
    }

    public User login(LoginRequest req) {
        User user = userRepo.findByEmail(req.email())
                .orElseThrow(() -> new InvalidCredentials("Invalid email or password"));

        if (!passwordEncoder.matches(req.password(), user.getPassword())) {
            throw new InvalidCredentials("Invalid email or password");
        }

        return user;
    }

    public void logout(String raw) {
        refreshService.revoke(raw);
    }
}
