package com.example.demo.User;
import java.time.Duration;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.example.demo.JWT.JwtService;
import com.example.demo.RefreshToken.InvalidToken;
import com.example.demo.RefreshToken.RefreshService;
import com.example.demo.RefreshToken.RefreshTokenRotation;
import com.example.demo.Security.AuthUser;
import com.example.demo.Security.AuthorityMapper;
import com.example.demo.User.Records.LoginRequest;
import com.example.demo.User.Records.UserRequest;
import com.example.demo.User.Records.UserResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;



@RestController 
public class UserController {
    private final UserService userServ;
    private final JwtService jwtService;
    private final RefreshService refreshService;
    private final AuthenticationManager authManager;
    private final long accessTokenExpirationMinutes;
    private final boolean secureCookies;

        public UserController(UserService userServ, JwtService jwtService, RefreshService refreshService, AuthenticationManager authManager, @Value("${ACCESS_TOKEN_EXPIRATION_MINUTES:15}") long accessTokenExpirationMinutes, @Value("${COOKIE_SECURE:true}") boolean secureCookies){
            this.userServ = userServ;
            this.jwtService = jwtService;
            this.refreshService = refreshService;
            this.authManager = authManager;
            this.accessTokenExpirationMinutes = accessTokenExpirationMinutes;
            this.secureCookies = secureCookies;
        }



        @GetMapping("/me")
        public ResponseEntity<UserResponse> getMe(Authentication auth) {
            User user = userServ.getUser(auth.getName());
            return ResponseEntity.ok(new UserResponse(user.getName(), user.getEmail()));
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

        @PostMapping("/auth/refresh")
        public ResponseEntity<Void> refresh(@CookieValue(name = "refresh_token", required = false) String rawToken) {
            RefreshTokenRotation rotation = refreshService.rotateRefreshToken(rawToken);
                String accessToken = jwtService.generateToken(rotation.userEmail(), rotation.roles());

            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie(accessToken, Duration.ofMinutes(accessTokenExpirationMinutes)).toString(),
                            refreshTokenCookie(rotation.rawToken(), RefreshService.REFRESH_TOKEN_TTL).toString())
                    .build();
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
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie("", Duration.ZERO).toString(),
                            refreshTokenCookie("", Duration.ZERO).toString())
                    .build();
        }
        

        @PostMapping("/auth/logout-all")
        public ResponseEntity<Void> logoutAll(@CookieValue(name = "refresh_token", required = false)String rawToken) {
            
             if (rawToken != null && !rawToken.isBlank()) {
                try {
                    userServ.logoutAllAccounts(rawToken);
                } catch (InvalidToken ignored) {
                    // Logout should still clear the cookies when the refresh token is already invalid.
                }
            }


            return ResponseEntity.noContent()
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie("", Duration.ZERO).toString(),refreshTokenCookie("", Duration.ZERO).toString()).build();
        }
        




        


        private ResponseCookie accessTokenCookie(String value, Duration maxAge) {
            return ResponseCookie.from("access_token", value)
                    .httpOnly(true)
                    .secure(secureCookies)
                    .sameSite("Strict")
                    .path("/")
                    .maxAge(maxAge)
                    .build();
        }

        private ResponseCookie refreshTokenCookie(String value, Duration maxAge) {
            return ResponseCookie.from("refresh_token", value)
                    .httpOnly(true)
                    .secure(secureCookies)
                    .sameSite("Strict")
                    .path("/auth")
                    .maxAge(maxAge)
                    .build();
        }
}
