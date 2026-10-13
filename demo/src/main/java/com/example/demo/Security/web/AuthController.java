package com.example.demo.security.web;
import java.time.Duration;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.demo.security.AuthUser;
import com.example.demo.security.AuthorityMapper;
import com.example.demo.security.jwt.JwtService;
import com.example.demo.security.refresh.InvalidToken;
import com.example.demo.security.refresh.RefreshService;
import com.example.demo.security.refresh.RefreshTokenRotation;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;



@RequestMapping("/auth")
@RestController 
public class AuthController {
    private final JwtService jwtService;
    private final RefreshService refreshService;
    private final AuthenticationManager authManager;
    private final long accessTokenExpirationMinutes;
    private final boolean secureCookies;

        public AuthController(JwtService jwtService, RefreshService refreshService, AuthenticationManager authManager, @Value("15") long accessTokenExpirationMinutes, @Value("true") boolean secureCookies){
            this.jwtService = jwtService;
            this.refreshService = refreshService;
            this.authManager = authManager;
            this.accessTokenExpirationMinutes = accessTokenExpirationMinutes;
            this.secureCookies = secureCookies;
        }




        @PostMapping("/login")
        public ResponseEntity<Void> login(@Valid @RequestBody LoginRequest req) {
            Authentication auth = authManager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(req.email(),req.password()));
            String userId = ((AuthUser) auth.getPrincipal()).getUserId();
            List<String> roles = AuthorityMapper.toRoleNames(auth.getAuthorities());
            String accessToken = jwtService.generateToken(auth.getName(),roles);
            String refreshToken = refreshService.generateRefreshToken(userId);
            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie(accessToken, Duration.ofMinutes(accessTokenExpirationMinutes)).toString(),
                            refreshTokenCookie(refreshToken, RefreshService.REFRESH_TOKEN_TTL).toString()).build();
        }

        @PostMapping("/refresh")
        public ResponseEntity<Void> refresh(@CookieValue(name = AuthCookies.REFRESH_TOKEN, required = false) String rawToken) {
            RefreshTokenRotation rotation = refreshService.rotateRefreshToken(rawToken);
                String accessToken = jwtService.generateToken(rotation.userEmail(), rotation.roles());

            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie(accessToken, Duration.ofMinutes(accessTokenExpirationMinutes)).toString(),
                            refreshTokenCookie(rotation.rawToken(), RefreshService.REFRESH_TOKEN_TTL).toString())
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
                    .secure(secureCookies)
                    .sameSite("Strict")
                    .path(AuthCookies.ACCESS_PATH)
                    .maxAge(maxAge)
                    .build();
        }

        private ResponseCookie refreshTokenCookie(String value, Duration maxAge) {
            return ResponseCookie.from(AuthCookies.REFRESH_TOKEN, value)
                    .httpOnly(true)
                    .secure(secureCookies)
                    .sameSite("Strict")
                    .path(AuthCookies.REFRESH_PATH)
                    .maxAge(maxAge)
                    .build();
        }
}

