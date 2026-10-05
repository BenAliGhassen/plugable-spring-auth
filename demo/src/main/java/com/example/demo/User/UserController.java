package com.example.demo.User;

import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.JWT.JwtService;
import com.example.demo.RefreshToken.InvalidToken;
import com.example.demo.RefreshToken.RefreshService;
import com.example.demo.RefreshToken.RefreshTokenRotation;
import com.example.demo.User.Records.LoginRequest;
import com.example.demo.User.Records.UserRequest;
import com.example.demo.User.Records.UserResponse;

import jakarta.validation.Valid;

@RestController 
public class UserController {
    private final UserService userServ;
    private final JwtService jwtService;
    private final RefreshService refreshService;

        public UserController(UserService userServ, JwtService jwtService, RefreshService refreshService){
            this.userServ = userServ;
            this.jwtService = jwtService;
            this.refreshService = refreshService;
        }


        @PostMapping("/auth/signup")
        public ResponseEntity<String> register(@Valid @RequestBody UserRequest user) {
            boolean result = userServ.createUser(user);

            if(result){
                return ResponseEntity.status(HttpStatus.CREATED).body("user created");
            }else{
                return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exist");
            }

            
        }


        @PostMapping("/auth/login")
        public ResponseEntity<UserResponse> login(@Valid @RequestBody LoginRequest req) {
            User user = userServ.login(req);
            String accessToken = jwtService.generateToken(user);
            String refreshToken = refreshService.generateRefreshToken(user);
            UserResponse userResponse = new UserResponse(user.getName(), user.getEmail());
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie(accessToken).toString(),
                            refreshTokenCookie(refreshToken).toString())
                    .body(userResponse);
        }

        @PostMapping("/auth/refresh")
        public ResponseEntity<UserResponse> refresh(@CookieValue(name = "refresh_token", required = false) String rawToken) {
            RefreshTokenRotation rotation = refreshService.rotateRefreshToken(rawToken);
                String accessToken = jwtService.generateToken(rotation.userEmail());
                UserResponse userResponse = new UserResponse(rotation.userName(), rotation.userEmail());

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie(accessToken).toString(),
                            refreshTokenCookie(rotation.rawToken()).toString())
                    .body(userResponse);
        }


        @PostMapping("/auth/logout")
        public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token", required = false) String rawToken) {
            if (rawToken != null && !rawToken.isBlank()) {
                try {
                    userServ.logout(rawToken);
                } catch (InvalidToken ignored) {
                    // Logout should still clear the cookies when the refresh token is already invalid.
                }
            }

            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, expiredAccessTokenCookie().toString(),
                            expiredRefreshTokenCookie().toString())
                    .build();
        }
        


        private ResponseCookie accessTokenCookie(String token) {
            return ResponseCookie.from("access_token", token)
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("Strict")
                    .path("/")
                    .maxAge(Duration.ofMinutes(15))
                    .build();
        }

        private ResponseCookie refreshTokenCookie(String token) {
            return ResponseCookie.from("refresh_token", token)
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("Strict")
                    .path("/auth")
                    .maxAge(RefreshService.REFRESH_TOKEN_TTL)
                    .build();
        }

        private ResponseCookie expiredAccessTokenCookie() {
            return ResponseCookie.from("access_token", "")
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("Strict")
                    .path("/")
                    .maxAge(Duration.ZERO)
                    .build();
        }

        private ResponseCookie expiredRefreshTokenCookie() {
            return ResponseCookie.from("refresh_token", "")
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("Strict")
                    .path("/auth")
                    .maxAge(Duration.ZERO)
                    .build();
        }
}
