package com.example.demo.security.web;
import java.time.Duration;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.demo.security.AuthProperties;
import com.example.demo.security.AuthUser;
import com.example.demo.security.AuthorityMapper;
import com.example.demo.security.jwt.JwtService;
import com.example.demo.security.login.LoginAttemptsService;
import com.example.demo.security.refresh.InvalidToken;
import com.example.demo.security.refresh.RefreshService;
import com.example.demo.security.refresh.RefreshTokenRotation;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;



@RequestMapping("/auth")
@RestController 
public class AuthController {
    private final JwtService jwtService;
    private final RefreshService refreshService;
    private final AuthenticationManager authManager;
    private final AuthProperties authProps;
    private final LoginAttemptsService loginAttemptsService;

        public AuthController(JwtService jwtService, RefreshService refreshService, AuthenticationManager authManager, AuthProperties authProps, LoginAttemptsService loginAttemptsService){
            this.jwtService = jwtService;
            this.refreshService = refreshService;
            this.authManager = authManager;
            this.authProps = authProps;
            this.loginAttemptsService = loginAttemptsService;
        }




        @PostMapping("/login")
        public ResponseEntity<Void> login(@Valid @RequestBody LoginRequest req, HttpServletRequest request){
            String ip = request.getRemoteAddr();
            if(loginAttemptsService.isBlocked(ip, req.username())){
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).header(HttpHeaders.RETRY_AFTER, String.valueOf(authProps.login().window().toSeconds())).build();
            }
           Authentication auth;
           try {
                auth = authManager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(req.username(),req.password()));
           } catch (AuthenticationException e) {
                loginAttemptsService.recordFailure(ip, req.username());
                throw e;
           }

            loginAttemptsService.recordSuccess(ip, req.username());
            String userId = ((AuthUser) auth.getPrincipal()).getUserId();
            List<String> roles = AuthorityMapper.toRoleNames(auth.getAuthorities());
            String accessToken = jwtService.generateToken(auth.getName(),roles);
            String refreshToken = refreshService.generateRefreshToken(userId);
            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie(accessToken, authProps.access().ttl()).toString(),
                            refreshTokenCookie(refreshToken, authProps.refresh().ttl()).toString()).build();
        }

        @PostMapping("/refresh")
        public ResponseEntity<Void> refresh(@CookieValue(name = AuthCookies.REFRESH_TOKEN, required = false) String rawToken) {
            RefreshTokenRotation rotation = refreshService.rotateRefreshToken(rawToken);
                String accessToken = jwtService.generateToken(rotation.username(), rotation.roles());

            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie(accessToken, authProps.access().ttl()).toString(),
                            refreshTokenCookie(rotation.rawToken(), authProps.refresh().ttl()).toString())
                    .build();
        }


        @PostMapping("/logout")
        public ResponseEntity<Void> logout(@CookieValue(name = AuthCookies.REFRESH_TOKEN, required = false) String rawToken) {
            if (rawToken != null && !rawToken.isBlank()) {
                try {
                    refreshService.revoke(rawToken);
                } catch (InvalidToken ignored) {
                    // Logout should still clear the cookies when the refresh token is already invalid.
                }
            }

            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie("", Duration.ZERO).toString(),
                            refreshTokenCookie("", Duration.ZERO).toString())
                    .build();
        }
        

        @PostMapping("/logout-all")
        public ResponseEntity<Void> logoutAll(@CookieValue(name = AuthCookies.REFRESH_TOKEN, required = false)String rawToken) {
            
             if (rawToken != null && !rawToken.isBlank()) {
                try {
                    refreshService.revokeAll(rawToken);
                } catch (InvalidToken ignored) {
                    // Logout should still clear the cookies when the refresh token is already invalid.
                }
            }


            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie("", Duration.ZERO).toString(),refreshTokenCookie("", Duration.ZERO).toString()).build();
        }
        




        


        private ResponseCookie accessTokenCookie(String value, Duration maxAge) {
            return ResponseCookie.from(AuthCookies.ACCESS_TOKEN, value)
                    .httpOnly(true)
                    .secure(authProps.cookie().secure())
                    .sameSite("Strict")
                    .path(AuthCookies.ACCESS_PATH)
                    .maxAge(maxAge)
                    .build();
        }

        private ResponseCookie refreshTokenCookie(String value, Duration maxAge) {
            return ResponseCookie.from(AuthCookies.REFRESH_TOKEN, value)
                    .httpOnly(true)
                    .secure(authProps.cookie().secure())
                    .sameSite("Strict")
                    .path(AuthCookies.REFRESH_PATH)
                    .maxAge(maxAge)
                    .build();
        }
}

