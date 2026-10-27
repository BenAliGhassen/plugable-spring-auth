package com.example.demo.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.example.demo.TestContainerConfiguration;
import com.example.demo.security.refresh.RefreshRepository;
import com.example.demo.security.refresh.RefreshToken;
import com.example.demo.security.web.AuthCookies;
import com.example.demo.user.User;
import com.example.demo.user.UserRepository;

/*
 * Integration tests of the whole authentication flow: real Spring context, security filters ON,
 * real PostgreSQL (Testcontainers). Configuration comes from src/test/resources/application.properties.
 *
 * Rules for this class:
 * - NO @Transactional: the tests must observe real commits and rollbacks (noRollbackFor on reuse detection).
 * - NO .with(csrf()): it replaces the CSRF repository of the shared application context.
 *   Every POST uses the real flow: GET /csrf, then the XSRF-TOKEN cookie + X-XSRF-TOKEN header.
 * - Each test uses its own client IP: LoginAttemptsService is a singleton shared by all tests.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import({TestContainerConfiguration.class, TestEndpointsConfiguration.class})
class AuthenticationFlowIntegrationTest {

    private static final String USERNAME = "alice@example.com";
    private static final String PASSWORD = "correct-password";
    private static final String WRONG_PASSWORD = "incorrect-password";
    // Must match auth.cors.origins in src/test/resources/application.properties
    private static final String ALLOWED_ORIGIN = "http://localhost:5173";
    private static final String CSRF_COOKIE = "XSRF-TOKEN";
    private static final String CSRF_HEADER = "X-XSRF-TOKEN";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RefreshRepository refreshRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User user;

    @BeforeEach
    void setUp() {
        refreshRepository.deleteAll();
        userRepository.deleteAll();
        user = userRepository.save(new User("Alice", USERNAME, passwordEncoder.encode(PASSWORD)));
    }

    // ---------- CSRF ----------

    @Test
    void loginWithoutCsrfTokenIsForbiddenAndCreatesNoRefreshToken() throws Exception {
        mockMvc.perform(loginRequest("192.0.2.1", PASSWORD))
                .andExpect(status().isForbidden());

        assertThat(refreshRepository.findAll()).isEmpty();
    }

    @Test
    void csrfCookieAndHeaderAllowLogin() throws Exception {
        // Step 1: the frontend asks for a token; the server answers with the XSRF-TOKEN cookie
        MvcResult csrfResult = mockMvc.perform(get("/csrf"))
                .andExpect(status().isNoContent())
                .andReturn();
        String csrfToken = cookieValue(csrfResult, CSRF_COOKIE);

        // Step 2: the frontend sends the cookie back AND copies its value into the header (double submit)
        MvcResult loginResult = mockMvc.perform(loginRequest("192.0.2.2", PASSWORD)
                        .cookie(new Cookie(CSRF_COOKIE, csrfToken))
                        .header(CSRF_HEADER, csrfToken))
                .andExpect(status().isNoContent())
                .andReturn();

        assertThat(cookieValue(loginResult, AuthCookies.ACCESS_TOKEN)).isNotBlank();
        assertThat(cookieValue(loginResult, AuthCookies.REFRESH_TOKEN)).isNotBlank();
        assertThat(refreshRepository.findAll())
                .hasSize(1)
                .allSatisfy(token -> assertThat(token.getUserId()).isEqualTo(user.getId().toString()));
    }

    // ---------- Login ----------

    @Test
    void validCredentialsSetBothCookiesAndPersistOnlyHashedRefreshToken() throws Exception {
        MvcResult loginResult = mockMvc.perform(withRealCsrf(loginRequest("192.0.2.3", PASSWORD)))
                .andExpect(status().isNoContent())
                .andReturn();

        String accessToken = cookieValue(loginResult, AuthCookies.ACCESS_TOKEN);
        String refreshToken = cookieValue(loginResult, AuthCookies.REFRESH_TOKEN);
        List<RefreshToken> storedTokens = refreshRepository.findAll();
        assertThat(accessToken).isNotBlank();
        assertThat(refreshToken).isNotBlank();
        assertThat(storedTokens).hasSize(1);
        assertThat(storedTokens.get(0).getUserId()).isEqualTo(user.getId().toString());
        assertThat(storedTokens.get(0).getTokenHash()).isEqualTo(hash(refreshToken));
    }

    @Test
    void wrongPasswordReturnsUnauthorizedAndCreatesNoRefreshToken() throws Exception {
        mockMvc.perform(withRealCsrf(loginRequest("192.0.2.4", WRONG_PASSWORD)))
                .andExpect(status().isUnauthorized());

        assertThat(refreshRepository.findAll()).isEmpty();
    }

    @Test
    void repeatedWrongPasswordsBlockCorrectLoginFromSameIp() throws Exception {
        String clientIp = "192.0.2.5";

        for (int attempt = 0; attempt < 5; attempt++) {
            mockMvc.perform(withRealCsrf(loginRequest(clientIp, WRONG_PASSWORD)))
                    .andExpect(status().isUnauthorized());
        }

        MvcResult blockedResult = mockMvc.perform(withRealCsrf(loginRequest(clientIp, PASSWORD)))
                .andExpect(status().isTooManyRequests())
                .andReturn();

        assertThat(blockedResult.getResponse().getHeader(HttpHeaders.RETRY_AFTER)).isEqualTo("900");
        assertThat(refreshRepository.findAll()).isEmpty();
    }

    // ---------- Protected endpoint (deny by default) ----------

    @Test
    void protectedEndpointRejectsRequestsWithoutCookies() throws Exception {
        mockMvc.perform(get("/test/protected"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointAcceptsAccessCookieFromSuccessfulLogin() throws Exception {
        String accessToken = loginAndGetCookie("192.0.2.6", AuthCookies.ACCESS_TOKEN);

        mockMvc.perform(get("/test/protected")
                        .cookie(new Cookie(AuthCookies.ACCESS_TOKEN, accessToken)))
                .andExpect(status().isOk());
    }

    @Test
    void protectedEndpointRejectsAccessCookieWithTamperedSignature() throws Exception {
        String accessToken = loginAndGetCookie("192.0.2.7", AuthCookies.ACCESS_TOKEN);
        String tamperedToken = tamperSignature(accessToken);
        assertThat(tamperedToken).isNotEqualTo(accessToken);

        mockMvc.perform(get("/test/protected")
                        .cookie(new Cookie(AuthCookies.ACCESS_TOKEN, tamperedToken)))
                .andExpect(status().isUnauthorized());
    }

    // ---------- Refresh ----------

    @Test
    void refreshRotatesTokenAndPersistsReplacementInSameFamily() throws Exception {
        String oldRawToken = loginAndGetCookie("192.0.2.8", AuthCookies.REFRESH_TOKEN);
        String familyId = refreshRepository.findByTokenHash(hash(oldRawToken)).orElseThrow().getFamilyId();

        MvcResult refreshResult = mockMvc.perform(refreshRequest(oldRawToken))
                .andExpect(status().isNoContent())
                .andReturn();
        String rotatedRawToken = cookieValue(refreshResult, AuthCookies.REFRESH_TOKEN);

        RefreshToken oldToken = refreshRepository.findByTokenHash(hash(oldRawToken)).orElseThrow();
        RefreshToken newToken = refreshRepository.findByTokenHash(hash(rotatedRawToken)).orElseThrow();
        assertThat(refreshRepository.findAll()).hasSize(2);
        assertThat(oldToken.isRevoked()).isTrue();
        assertThat(newToken.isRevoked()).isFalse();
        assertThat(newToken.getFamilyId()).isEqualTo(familyId);
    }

    @Test
    void reusingOldRefreshTokenRevokesEveryTokenInItsFamily() throws Exception {
        String oldRawToken = loginAndGetCookie("192.0.2.9", AuthCookies.REFRESH_TOKEN);
        String familyId = refreshRepository.findByTokenHash(hash(oldRawToken)).orElseThrow().getFamilyId();

        MvcResult firstRefresh = mockMvc.perform(refreshRequest(oldRawToken))
                .andExpect(status().isNoContent())
                .andReturn();
        String latestRawToken = cookieValue(firstRefresh, AuthCookies.REFRESH_TOKEN);
        assertThat(refreshRepository.findByTokenHash(hash(latestRawToken)).orElseThrow().isRevoked()).isFalse();

        // Reuse of the OLD (already rotated) token = theft signal
        mockMvc.perform(refreshRequest(oldRawToken))
                .andExpect(status().isUnauthorized());

        // Read the database AFTER the 401: the family revoke must have been committed despite the exception
        List<RefreshToken> familyTokens = refreshRepository.findAll().stream()
                .filter(token -> token.getFamilyId().equals(familyId))
                .toList();
        assertThat(familyTokens)
                .hasSize(2)
                .allSatisfy(token -> assertThat(token.isRevoked()).isTrue());
    }

    // ---------- Logout ----------

    @Test
    void logoutClearsCookiesRevokesRefreshTokenAndPreventsRefresh() throws Exception {
        String rawToken = loginAndGetCookie("192.0.2.10", AuthCookies.REFRESH_TOKEN);

        MvcResult logoutResult = mockMvc.perform(withRealCsrf(post("/auth/logout")
                        .cookie(new Cookie(AuthCookies.REFRESH_TOKEN, rawToken))))
                .andExpect(status().isNoContent())
                .andReturn();

        assertClearedAuthCookies(logoutResult);
        assertThat(refreshRepository.findByTokenHash(hash(rawToken)).orElseThrow().isRevoked()).isTrue();

        mockMvc.perform(refreshRequest(rawToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutAllRevokesEveryRefreshFamilyForTheUser() throws Exception {
        String firstRawToken = loginAndGetCookie("192.0.2.11", AuthCookies.REFRESH_TOKEN);
        String secondRawToken = loginAndGetCookie("192.0.2.11", AuthCookies.REFRESH_TOKEN);
        RefreshToken first = refreshRepository.findByTokenHash(hash(firstRawToken)).orElseThrow();
        RefreshToken second = refreshRepository.findByTokenHash(hash(secondRawToken)).orElseThrow();
        assertThat(first.getFamilyId()).isNotEqualTo(second.getFamilyId());

        MvcResult logoutAllResult = mockMvc.perform(withRealCsrf(post("/auth/logout-all")
                        .cookie(new Cookie(AuthCookies.REFRESH_TOKEN, secondRawToken))))
                .andExpect(status().isNoContent())
                .andReturn();

        assertClearedAuthCookies(logoutAllResult);
        assertThat(refreshRepository.findAll())
                .hasSize(2)
                .allSatisfy(token -> {
                    assertThat(token.getUserId()).isEqualTo(user.getId().toString());
                    assertThat(token.isRevoked()).isTrue();
                });
    }

    // ---------- CORS ----------

    @Test
    void corsPreflightAllowsConfiguredOriginWithCredentials() throws Exception {
        MvcResult result = mockMvc.perform(options("/auth/login")
                        .header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isEqualTo(ALLOWED_ORIGIN);
        assertThat(result.getResponse().getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS)).isEqualTo("true");
    }

    @Test
    void corsPreflightRejectsUnconfiguredOrigin() throws Exception {
        MvcResult result = mockMvc.perform(options("/auth/login")
                        .header(HttpHeaders.ORIGIN, "https://evil.example")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isForbidden())
                .andReturn();

        assertThat(result.getResponse().getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isNull();
    }

    // ---------- Helpers ----------

    /** Login request with JSON body and a given client IP. Adds NO CSRF token. */
    private static MockHttpServletRequestBuilder loginRequest(String clientIp, String password) {
        return post("/auth/login")
                .contentType("application/json")
                .content("""
                        {"username":"%s","password":"%s"}
                        """.formatted(USERNAME, password))
                .with(request -> {
                    request.setRemoteAddr(clientIp);
                    return request;
                });
    }

    /** Real CSRF flow: GET /csrf for a fresh token, then send it as cookie AND header. */
    private MockHttpServletRequestBuilder withRealCsrf(MockHttpServletRequestBuilder request) throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/csrf"))
                .andExpect(status().isNoContent())
                .andReturn();
        String token = cookieValue(csrfResult, CSRF_COOKIE);
        return request
                .cookie(new Cookie(CSRF_COOKIE, token))
                .header(CSRF_HEADER, token);
    }

    private MockHttpServletRequestBuilder refreshRequest(String rawRefreshToken) throws Exception {
        return withRealCsrf(post("/auth/refresh")
                .cookie(new Cookie(AuthCookies.REFRESH_TOKEN, rawRefreshToken)));
    }

    /** Logs in successfully and returns the value of one of the auth cookies. */
    private String loginAndGetCookie(String clientIp, String cookieName) throws Exception {
        MvcResult loginResult = mockMvc.perform(withRealCsrf(loginRequest(clientIp, PASSWORD)))
                .andExpect(status().isNoContent())
                .andReturn();
        return cookieValue(loginResult, cookieName);
    }

    /** Reads a cookie from the response, whether it was written as a Set-Cookie header or as a Cookie object. */
    private static String cookieValue(MvcResult result, String cookieName) {
        Cookie cookie = result.getResponse().getCookie(cookieName);
        assertThat(cookie).as("response cookie %s", cookieName).isNotNull();
        return cookie.getValue();
    }

    private static void assertClearedAuthCookies(MvcResult result) {
        assertClearedCookie(result, AuthCookies.ACCESS_TOKEN, AuthCookies.ACCESS_PATH);
        assertClearedCookie(result, AuthCookies.REFRESH_TOKEN, AuthCookies.REFRESH_PATH);
    }

    /** A browser deletes a cookie only if name AND path match the original, so the path is checked exactly. */
    private static void assertClearedCookie(MvcResult result, String name, String expectedPath) {
        Cookie cookie = result.getResponse().getCookie(name);
        assertThat(cookie).as("cleared cookie %s", name).isNotNull();
        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge()).isZero();
        assertThat(cookie.getPath()).isEqualTo(expectedPath);
    }

    /*
     * Flips one bit of the FIRST signature byte. Changing the last Base64 character is not reliable:
     * that character carries 2 spare bits, so some changes decode to the exact same signature.
     */
    private static String tamperSignature(String jwt) {
        String[] parts = jwt.split("\\.");
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        signature[0] ^= 1;
        return parts[0] + "." + parts[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }

    private static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}