package com.example.demo.security.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;

import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.example.demo.security.AuthProperties;
import com.example.demo.security.DefaultAuthUser;
import com.example.demo.security.jwt.JwtService;
import com.example.demo.security.login.LoginAttemptsService;
import com.example.demo.security.refresh.InvalidToken;
import com.example.demo.security.refresh.RefreshService;
import com.example.demo.security.refresh.RefreshTokenRotation;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(AuthControllerTest.TestAuthPropertiesConfiguration.class)
class AuthControllerTest {

    private static final String CLIENT_IP = "192.0.2.10";
    private static final String USERNAME = "alice@example.com";
    private static final String PASSWORD = "correct-password";
    private static final String USER_ID = "user-123";
    private static final List<SimpleGrantedAuthority> AUTHORITIES = List.of(
            new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_ADMIN"));
    private static final List<String> ROLES = List.of("ROLE_USER", "ROLE_ADMIN");
    private static final String ACCESS_TOKEN = "access-token-value";
    private static final String REFRESH_TOKEN = "refresh-token-value";
    private static final String ROTATED_ACCESS_TOKEN = "rotated-access-token";
    private static final String ROTATED_REFRESH_TOKEN = "rotated-refresh-token";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private RefreshService refreshService;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private LoginAttemptsService loginAttemptsService;

    @BeforeEach
    void setUp() {
        when(jwtService.generateToken(USERNAME, ROLES)).thenReturn(ACCESS_TOKEN);
        when(refreshService.generateRefreshToken(USER_ID)).thenReturn(REFRESH_TOKEN);
    }

    @Test
    void loginSuccessSetsBothCookiesAndIssuesTokensForAuthenticatedPrincipal() throws Exception {
        Authentication authentication = authenticated(USERNAME, PASSWORD, USER_ID);
        when(loginAttemptsService.isBlocked(CLIENT_IP, USERNAME)).thenReturn(false);
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(authentication);

        MvcResult result = mockMvc.perform(loginRequest("""
                {"username":"alice@example.com","password":"correct-password"}
                """))
                .andExpect(status().isNoContent())
                
                .andReturn();

        assertTwoSetCookies(result);
        assertCookie(result, AuthCookies.ACCESS_TOKEN, ACCESS_TOKEN, AuthCookies.ACCESS_PATH, 900);
        assertCookie(result, AuthCookies.REFRESH_TOKEN, REFRESH_TOKEN, AuthCookies.REFRESH_PATH, 604800);
        verify(loginAttemptsService).recordSuccess(CLIENT_IP, USERNAME);
        verify(jwtService).generateToken(USERNAME, ROLES);
        verify(refreshService).generateRefreshToken(USER_ID);
    }

    @Test
    void loginWrongCredentialsReturnsUnauthorizedAndRecordsFailureWithoutIssuingTokens() throws Exception {
        when(loginAttemptsService.isBlocked(CLIENT_IP, USERNAME)).thenReturn(false);
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        MvcResult result = mockMvc.perform(loginRequest("""
                {"username":"alice@example.com","password":"wrong-password"}
                """))
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertThat(result.getResponse().getHeader(HttpHeaders.SET_COOKIE)).isNull();
        verify(loginAttemptsService).recordFailure(CLIENT_IP, USERNAME);
        verify(jwtService, never()).generateToken(any(String.class), any());
        verify(refreshService, never()).generateRefreshToken(any(String.class));
    }

    @Test
    void loginBlockedReturnsTooManyRequestsAndRetryAfterWithoutAuthenticating() throws Exception {
        when(loginAttemptsService.isBlocked(CLIENT_IP, USERNAME)).thenReturn(true);

        MvcResult result = mockMvc.perform(loginRequest("""
                {"username":"alice@example.com","password":"correct-password"}
                """))
                .andExpect(status().isTooManyRequests())
                .andReturn();

        assertThat(result.getResponse().getHeader(HttpHeaders.RETRY_AFTER)).isEqualTo("900");
        assertThat(result.getResponse().getHeader(HttpHeaders.SET_COOKIE)).isNull();
        verify(authenticationManager, never()).authenticate(any(Authentication.class));
        verify(loginAttemptsService, never()).recordFailure(CLIENT_IP, USERNAME);
        verify(jwtService, never()).generateToken(any(String.class), any());
        verify(refreshService, never()).generateRefreshToken(any(String.class));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidLoginBodies")
    void loginRejectsInvalidFieldsBeforeCheckingAttemptsOrAuthenticating(String description, String json)
            throws Exception {
        MvcResult result = mockMvc.perform(loginRequest(json))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        verify(loginAttemptsService, never()).isBlocked(any(String.class), any(String.class));
        verify(authenticationManager, never()).authenticate(any(Authentication.class));
    }

    private static Stream<Arguments> invalidLoginBodies() {
        return Stream.of(
                Arguments.of("blank username", """
                        {"username":" ","password":"correct-password"}
                        """),
                Arguments.of("blank password", """
                        {"username":"alice@example.com","password":" "}
                        """),
                Arguments.of("username longer than 255 characters", """
                        {"username":"%s","password":"correct-password"}
                        """.formatted("u".repeat(256))),
                Arguments.of("password longer than 72 characters", """
                        {"username":"alice@example.com","password":"%s"}
                        """.formatted("p".repeat(73))));
    }

    @Test
    void loginAcceptsUsernameOf255AndPasswordOf72Characters() throws Exception {
        String maxUsername = "u".repeat(255);
        String maxPassword = "p".repeat(72);
        Authentication authentication = authenticated(maxUsername, maxPassword, USER_ID);
        when(loginAttemptsService.isBlocked(CLIENT_IP, maxUsername)).thenReturn(false);
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(authentication);
        when(jwtService.generateToken(maxUsername, ROLES)).thenReturn(ACCESS_TOKEN);

        mockMvc.perform(loginRequest("""
                {"username":"%s","password":"%s"}
                """.formatted(maxUsername, maxPassword)))
                .andExpect(status().isNoContent());

        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(loginAttemptsService).recordSuccess(CLIENT_IP, maxUsername);
    }

    @Test
    void loginMalformedJsonReturnsBadRequest() throws Exception {
        mockMvc.perform(loginRequest("""
                {"username":"alice@example.com","password":
                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void refreshValidCookieRotatesTokenAndSetsBothReplacementCookies() throws Exception {
        when(refreshService.rotateRefreshToken(REFRESH_TOKEN))
                .thenReturn(new RefreshTokenRotation(USERNAME, ROLES, ROTATED_REFRESH_TOKEN));
        when(jwtService.generateToken(USERNAME, ROLES)).thenReturn(ROTATED_ACCESS_TOKEN);

        MvcResult result = mockMvc.perform(post("/auth/refresh")
                .cookie(new jakarta.servlet.http.Cookie(AuthCookies.REFRESH_TOKEN, REFRESH_TOKEN)))
                .andExpect(status().isNoContent())
                .andReturn();

        assertTwoSetCookies(result);
        assertCookie(result, AuthCookies.ACCESS_TOKEN, ROTATED_ACCESS_TOKEN, AuthCookies.ACCESS_PATH, 900);
        assertCookie(result, AuthCookies.REFRESH_TOKEN, ROTATED_REFRESH_TOKEN, AuthCookies.REFRESH_PATH, 604800);
        verify(refreshService).rotateRefreshToken(REFRESH_TOKEN);
        verify(jwtService).generateToken(USERNAME, ROLES);
    }

    @Test
    void refreshInvalidTokenReturnsUnauthorizedWithoutSetCookie() throws Exception {
        when(refreshService.rotateRefreshToken(REFRESH_TOKEN)).thenThrow(new InvalidToken("Invalid token"));

        MvcResult result = mockMvc.perform(post("/auth/refresh")
                .cookie(new jakarta.servlet.http.Cookie(AuthCookies.REFRESH_TOKEN, REFRESH_TOKEN)))
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertThat(result.getResponse().getHeader(HttpHeaders.SET_COOKIE)).isNull();
    }

    @Test
    void logoutWithCookieRevokesTokenAndClearsBothCookies() throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/logout")
                .cookie(new jakarta.servlet.http.Cookie(AuthCookies.REFRESH_TOKEN, REFRESH_TOKEN)))
                .andExpect(status().isNoContent())
                .andReturn();

        assertTwoSetCookies(result);
        assertCookie(result, AuthCookies.ACCESS_TOKEN, "", AuthCookies.ACCESS_PATH, 0);
        assertCookie(result, AuthCookies.REFRESH_TOKEN, "", AuthCookies.REFRESH_PATH, 0);
        verify(refreshService).revoke(REFRESH_TOKEN);
    }

    @Test
    void logoutInvalidTokenStillClearsBothCookies() throws Exception {
        org.mockito.Mockito.doThrow(new InvalidToken("Invalid token"))
                .when(refreshService).revoke(REFRESH_TOKEN);

        MvcResult result = mockMvc.perform(post("/auth/logout")
                .cookie(new jakarta.servlet.http.Cookie(AuthCookies.REFRESH_TOKEN, REFRESH_TOKEN)))
                .andExpect(status().isNoContent())
                .andReturn();

        assertTwoSetCookies(result);
        assertCookie(result, AuthCookies.ACCESS_TOKEN, "", AuthCookies.ACCESS_PATH, 0);
        assertCookie(result, AuthCookies.REFRESH_TOKEN, "", AuthCookies.REFRESH_PATH, 0);
    }

    @Test
    void logoutWithoutCookieDoesNotRevokeAndStillClearsBothCookies() throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/logout"))
                .andExpect(status().isNoContent())
                .andReturn();

        assertTwoSetCookies(result);
        assertCookie(result, AuthCookies.ACCESS_TOKEN, "", AuthCookies.ACCESS_PATH, 0);
        assertCookie(result, AuthCookies.REFRESH_TOKEN, "", AuthCookies.REFRESH_PATH, 0);
        verify(refreshService, never()).revoke(any(String.class));
    }

    @Test
    void logoutAllWithCookieRevokesAllAndClearsBothCookies() throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/logout-all")
                .cookie(new jakarta.servlet.http.Cookie(AuthCookies.REFRESH_TOKEN, REFRESH_TOKEN)))
                .andExpect(status().isNoContent())
                .andReturn();

        assertTwoSetCookies(result);
        assertCookie(result, AuthCookies.ACCESS_TOKEN, "", AuthCookies.ACCESS_PATH, 0);
        assertCookie(result, AuthCookies.REFRESH_TOKEN, "", AuthCookies.REFRESH_PATH, 0);
        verify(refreshService).revokeAll(REFRESH_TOKEN);
    }

    @Test
    void logoutAllInvalidTokenStillClearsBothCookies() throws Exception {
        org.mockito.Mockito.doThrow(new InvalidToken("Invalid token"))
                .when(refreshService).revokeAll(REFRESH_TOKEN);

        MvcResult result = mockMvc.perform(post("/auth/logout-all")
                .cookie(new jakarta.servlet.http.Cookie(AuthCookies.REFRESH_TOKEN, REFRESH_TOKEN)))
                .andExpect(status().isNoContent())
                .andReturn();

        assertTwoSetCookies(result);
        assertCookie(result, AuthCookies.ACCESS_TOKEN, "", AuthCookies.ACCESS_PATH, 0);
        assertCookie(result, AuthCookies.REFRESH_TOKEN, "", AuthCookies.REFRESH_PATH, 0);
    }

    @Test
    void logoutAllWithoutCookieDoesNotRevokeAndStillClearsBothCookies() throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/logout-all"))
                .andExpect(status().isNoContent())
                .andReturn();

        assertTwoSetCookies(result);
        assertCookie(result, AuthCookies.ACCESS_TOKEN, "", AuthCookies.ACCESS_PATH, 0);
        assertCookie(result, AuthCookies.REFRESH_TOKEN, "", AuthCookies.REFRESH_PATH, 0);
        verify(refreshService, never()).revokeAll(any(String.class));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder loginRequest(String json) {
        return post("/auth/login")
                .contentType("application/json")
                .content(json)
                .with(request -> {
                    request.setRemoteAddr(CLIENT_IP);
                    return request;
                });
    }

    private Authentication authenticated(String username, String password, String userId) {
        DefaultAuthUser principal = new DefaultAuthUser(username, password, AUTHORITIES, userId);
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, AUTHORITIES);
    }

    private static void assertTwoSetCookies(MvcResult result) {
        assertThat(result.getResponse().getHeaders(HttpHeaders.SET_COOKIE)).hasSize(2);
    }

    private static void assertCookie(MvcResult result, String name, String value, String path, int maxAgeSeconds) throws Exception {
                        cookie().value(name, value).match(result);
                        cookie().path(name, path).match(result);
                        cookie().maxAge(name, maxAgeSeconds).match(result);
                        cookie().httpOnly(name, true).match(result);
                        cookie().secure(name, true).match(result);
                        cookie().sameSite(name, "Strict").match(result);
                
    }

    @TestConfiguration
    static class TestAuthPropertiesConfiguration {

        @Bean
        AuthProperties authProperties() {
            return new AuthProperties(
                    new AuthProperties.Jwt("dGVzdC1zZWNyZXQ="),
                    new AuthProperties.Access(Duration.ofMinutes(15)),
                    new AuthProperties.Refresh(Duration.ofDays(3), Duration.ofDays(7)),
                    new AuthProperties.Cookie(true),
                    new AuthProperties.Cors(List.of("http://localhost:5173")),
                    new AuthProperties.Login(5, 20, Duration.ofMinutes(15)));
        }
    }
}
