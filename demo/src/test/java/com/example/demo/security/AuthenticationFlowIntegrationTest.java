package com.example.demo.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.example.demo.TestContainerConfiguration;
import com.example.demo.security.refresh.RefreshRepository;
import com.example.demo.security.refresh.RefreshToken;
import com.example.demo.security.web.AuthCookies;
import com.example.demo.user.User;
import com.example.demo.user.UserRepository;

@SpringBootTest(properties = {
        "auth.jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "auth.cors.origins[0]=http://localhost:5173",
        "auth.cookie.secure=false"
})
@AutoConfigureMockMvc
@Import({TestContainerConfiguration.class, TestEndpointsConfiguration.class})
class AuthenticationFlowIntegrationTest {

    private static final String USERNAME = "alice@example.com";
    private static final String PASSWORD = "correct-password";
    private static final String WRONG_PASSWORD = "incorrect-password";
    private static final String ORIGIN = "http://localhost:5173";
    private static final String CSRF_COOKIE = "XSRF-TOKEN";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RefreshRepository refreshRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    private User user;

    @BeforeEach
    void setUp() {
        refreshRepository.deleteAll();
        userRepository.deleteAll();
        user = userRepository.save(new User("Alice", USERNAME, passwordEncoder.encode(PASSWORD)));
    }

    @Test
    void loginWithoutCsrfTokenIsForbiddenAndCreatesNoRefreshToken() throws Exception {
        mockMvc.perform(loginRequestWithoutCsrf("192.0.2.1", PASSWORD))
                .andExpect(status().isForbidden());

        assertThat(refreshRepository.findAll()).isEmpty();
    }

    @Test
    void csrfCookieAndHeaderAllowLogin() throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/csrf"))
                .andExpect(status().isNoContent())
                .andReturn();
        String csrfToken = cookieValue(csrfResult, CSRF_COOKIE);

        MvcResult loginResult = mockMvc.perform(loginRequest("192.0.2.2", PASSWORD, csrfToken))
                .andExpect(status().isNoContent())
                .andReturn();

        assertThat(cookieValue(loginResult, AuthCookies.ACCESS_TOKEN)).isNotBlank();
        assertThat(cookieValue(loginResult, AuthCookies.REFRESH_TOKEN)).isNotBlank();
        assertThat(refreshRepository.findAll())
                .hasSize(1)
                .allSatisfy(token -> assertThat(token.getUserId()).isEqualTo(user.getId().toString()));
    }

    @Test
    void validCredentialsSetBothCookiesAndPersistOnlyHashedRefreshToken() throws Exception {
        MvcResult loginResult = mockMvc.perform(loginRequest("192.0.2.3", PASSWORD))
                .andExpect(status().isNoContent())
                .andReturn();

        String accessToken = cookieValue(loginResult, AuthCookies.ACCESS_TOKEN);
        String refreshToken = cookieValue(loginResult, AuthCookies.REFRESH_TOKEN);
        List<RefreshToken> storedTokens = refreshRepository.findAll();
        assertThat(accessToken).isNotBlank();
        assertThat(refreshToken).isNotBlank();
        assertThat(storedTokens).hasSize(1);
        assertThat(storedTokens.get(0).getUserId()).isEqualTo(user.getId().toString());
        assertThat(storedTokens.get(0).getTokenHash()).isNotEqualTo(refreshToken);
    }

    @Test
    void wrongPasswordReturnsUnauthorizedAndCreatesNoRefreshToken() throws Exception {
        mockMvc.perform(loginRequest("192.0.2.4", WRONG_PASSWORD))
                .andExpect(status().isUnauthorized());

        assertThat(refreshRepository.findAll()).isEmpty();
    }

    @Test
    void repeatedWrongPasswordsBlockCorrectLoginFromSameIp() throws Exception {
        String clientIp = "192.0.2.5";

        for (int attempt = 0; attempt < 5; attempt++) {
            mockMvc.perform(loginRequest(clientIp, WRONG_PASSWORD))
                    .andExpect(status().isUnauthorized());
            assertThat(refreshRepository.findAll()).isEmpty();
        }

        MvcResult blockedResult = mockMvc.perform(loginRequest(clientIp, PASSWORD))
                .andExpect(status().isTooManyRequests())
                .andReturn();

        assertThat(blockedResult.getResponse().getHeader(HttpHeaders.RETRY_AFTER)).isEqualTo("900");
        assertThat(refreshRepository.findAll()).isEmpty();
    }

    @Test
    void protectedEndpointRejectsRequestsWithoutCookies() throws Exception {
        mockMvc.perform(get("/test/protected"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointAcceptsAccessCookieFromSuccessfulLogin() throws Exception {
        MvcResult loginResult = mockMvc.perform(loginRequest("192.0.2.6", PASSWORD))
                .andExpect(status().isNoContent())
                .andReturn();
        String accessToken = cookieValue(loginResult, AuthCookies.ACCESS_TOKEN);
        assertThat(refreshRepository.findAll()).hasSize(1);

        mockMvc.perform(get("/test/protected")
                .cookie(new Cookie(AuthCookies.ACCESS_TOKEN, accessToken)))
                .andExpect(status().isOk());
    }

    @Test
    void protectedEndpointRejectsModifiedAccessCookie() throws Exception {
        MvcResult loginResult = mockMvc.perform(loginRequest("192.0.2.7", PASSWORD))
                .andExpect(status().isNoContent())
                .andReturn();
        String accessToken = cookieValue(loginResult, AuthCookies.ACCESS_TOKEN);
        assertThat(refreshRepository.findAll()).hasSize(1);
        String modifiedToken = modifyLastCharacter(accessToken);

        mockMvc.perform(get("/test/protected")
                .cookie(new Cookie(AuthCookies.ACCESS_TOKEN, modifiedToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshRotatesTokenAndPersistsReplacementInSameFamily() throws Exception {
        MvcResult loginResult = mockMvc.perform(loginRequest("192.0.2.8", PASSWORD))
                .andExpect(status().isNoContent())
                .andReturn();
        String oldRawToken = cookieValue(loginResult, AuthCookies.REFRESH_TOKEN);
        RefreshToken oldToken = refreshRepository.findByTokenHash(hash(oldRawToken)).orElseThrow();

        MvcResult refreshResult = mockMvc.perform(refreshRequest(oldRawToken))
                .andExpect(status().isNoContent())
                .andReturn();

        String rotatedRawToken = cookieValue(refreshResult, AuthCookies.REFRESH_TOKEN);
        List<RefreshToken> storedTokens = refreshRepository.findAll();
        assertThat(storedTokens).hasSize(2);
        RefreshToken persistedOldToken = refreshRepository.findByTokenHash(hash(oldRawToken)).orElseThrow();
        RefreshToken newToken = refreshRepository.findByTokenHash(hash(rotatedRawToken)).orElseThrow();
        assertThat(persistedOldToken.isRevoked()).isTrue();
        assertThat(newToken.isRevoked()).isFalse();
        assertThat(newToken.getFamilyId()).isEqualTo(oldToken.getFamilyId());
        assertThat(newToken.getTokenHash()).isNotEqualTo(rotatedRawToken);
    }

    @Test
    void reusingOldRefreshTokenRevokesEveryTokenInItsFamily() throws Exception {
        MvcResult loginResult = mockMvc.perform(loginRequest("192.0.2.9", PASSWORD))
                .andExpect(status().isNoContent())
                .andReturn();
        String oldRawToken = cookieValue(loginResult, AuthCookies.REFRESH_TOKEN);
        RefreshToken oldToken = refreshRepository.findByTokenHash(hash(oldRawToken)).orElseThrow();

        MvcResult firstRefresh = mockMvc.perform(refreshRequest(oldRawToken))
                .andExpect(status().isNoContent())
                .andReturn();
        String latestRawToken = cookieValue(firstRefresh, AuthCookies.REFRESH_TOKEN);
        assertThat(refreshRepository.findAll()).hasSize(2);

        mockMvc.perform(refreshRequest(oldRawToken))
                .andExpect(status().isUnauthorized());

        List<RefreshToken> familyTokens = refreshRepository.findAll().stream()
                .filter(token -> token.getFamilyId().equals(oldToken.getFamilyId()))
                .toList();
        assertThat(familyTokens).hasSize(2).allSatisfy(token -> assertThat(token.isRevoked()).isTrue());
        assertThat(refreshRepository.findByTokenHash(hash(latestRawToken))).isPresent()
                .get()
                .extracting(RefreshToken::isRevoked)
                .isEqualTo(true);
    }

    @Test
    void logoutClearsCookiesRevokesRefreshTokenAndPreventsRefresh() throws Exception {
        MvcResult loginResult = mockMvc.perform(loginRequest("192.0.2.10", PASSWORD))
                .andExpect(status().isNoContent())
                .andReturn();
        String rawToken = cookieValue(loginResult, AuthCookies.REFRESH_TOKEN);
        assertThat(refreshRepository.findAll()).hasSize(1);

        MvcResult logoutResult = mockMvc.perform(csrfProtectedPost("/auth/logout")
                .cookie(new Cookie(AuthCookies.REFRESH_TOKEN, rawToken)))
                .andExpect(status().isNoContent())
                .andReturn();
        assertClearedAuthCookies(logoutResult);
        assertThat(refreshRepository.findByTokenHash(hash(rawToken)).orElseThrow().isRevoked()).isTrue();

        mockMvc.perform(refreshRequest(rawToken))
                .andExpect(status().isUnauthorized());

        assertThat(refreshRepository.findByTokenHash(hash(rawToken)).orElseThrow().isRevoked()).isTrue();
    }

    @Test
    void logoutAllRevokesEveryRefreshFamilyForTheUser() throws Exception {
        MvcResult firstLogin = mockMvc.perform(loginRequest("192.0.2.11", PASSWORD))
                .andExpect(status().isNoContent())
                .andReturn();
        String firstRawToken = cookieValue(firstLogin, AuthCookies.REFRESH_TOKEN);
        List<RefreshToken> afterFirstLogin = refreshRepository.findAll();
        assertThat(afterFirstLogin).hasSize(1);

        MvcResult secondLogin = mockMvc.perform(loginRequest("192.0.2.11", PASSWORD))
                .andExpect(status().isNoContent())
                .andReturn();
        String secondRawToken = cookieValue(secondLogin, AuthCookies.REFRESH_TOKEN);
        List<RefreshToken> afterSecondLogin = refreshRepository.findAll();
        assertThat(afterSecondLogin).hasSize(2);
        assertThat(afterSecondLogin.get(0).getFamilyId())
                .isNotEqualTo(afterSecondLogin.get(1).getFamilyId());

        MvcResult logoutAllResult = mockMvc.perform(csrfProtectedPost("/auth/logout-all")
                .cookie(new Cookie(AuthCookies.REFRESH_TOKEN, secondRawToken)))
                .andExpect(status().isNoContent())
                .andReturn();

        assertClearedAuthCookies(logoutAllResult);
        assertThat(refreshRepository.findByTokenHash(hash(firstRawToken)).orElseThrow().isRevoked()).isTrue();
        assertThat(refreshRepository.findByTokenHash(hash(secondRawToken)).orElseThrow().isRevoked()).isTrue();
        assertThat(refreshRepository.findAll())
                .hasSize(2)
                .allSatisfy(token -> assertThat(token.getUserId()).isEqualTo(user.getId().toString()));
    }

    @Test
    void corsPreflightAllowsConfiguredOriginWithCredentials() throws Exception {
        MvcResult result = mockMvc.perform(options("/auth/login")
                .header(HttpHeaders.ORIGIN, ORIGIN)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isEqualTo(ORIGIN);
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

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder loginRequest(
            String clientIp,
            String password) throws Exception {
        return loginRequest(clientIp, password, csrfToken());
    }

    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder loginRequestWithoutCsrf(
            String clientIp,
            String password) {
        return loginRequestBuilder(clientIp, password);
    }

    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder loginRequest(
            String clientIp,
            String password,
            String csrfToken) {
        return loginRequestBuilder(clientIp, password)
                .cookie(new Cookie(CSRF_COOKIE, csrfToken))
                .header("X-XSRF-TOKEN", csrfToken);
    }

    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder loginRequestBuilder(
            String clientIp,
            String password) {
        return post("/auth/login")
                .contentType("application/json")
                .content("""
                        {"username":"%s","password":"%s"}
                        """.formatted(USERNAME, password))
                .with(httpRequest -> {
                    httpRequest.setRemoteAddr(clientIp);
                    return httpRequest;
                });
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder refreshRequest(
            String rawToken) throws Exception {
        return csrfProtectedPost("/auth/refresh")
                .cookie(new Cookie(AuthCookies.REFRESH_TOKEN, rawToken));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder csrfProtectedPost(
            String path) throws Exception {
        String csrfToken = csrfToken();
        return post(path)
                .cookie(new Cookie(CSRF_COOKIE, csrfToken))
                .header("X-XSRF-TOKEN", csrfToken);
    }

    private String csrfToken() throws Exception {
        MvcResult result = mockMvc.perform(get("/csrf"))
                .andExpect(status().isNoContent())
                .andReturn();
        return cookieValue(result, CSRF_COOKIE);
    }

    private static String cookieValue(MvcResult result, String cookieName) {
        String prefix = cookieName + "=";
        String setCookie = result.getResponse().getHeaders(HttpHeaders.SET_COOKIE).stream()
                .filter(header -> header.startsWith(prefix))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing Set-Cookie for " + cookieName));
        int attributesStart = setCookie.indexOf(';');
        return setCookie.substring(prefix.length(), attributesStart < 0 ? setCookie.length() : attributesStart);
    }

    private static void assertClearedAuthCookies(MvcResult result) {
        List<String> setCookies = result.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        assertThat(setCookies).hasSize(2);
        assertClearedCookie(setCookies, AuthCookies.ACCESS_TOKEN, AuthCookies.ACCESS_PATH);
        assertClearedCookie(setCookies, AuthCookies.REFRESH_TOKEN, AuthCookies.REFRESH_PATH);
    }

    private static void assertClearedCookie(List<String> setCookies, String name, String expectedPath) {
        String setCookie = setCookies.stream()
                .filter(header -> header.startsWith(name + "="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing cleared cookie " + name));
        assertThat(setCookie).startsWith(name + "=");
        assertThat(setCookie).contains("Path=" + expectedPath, "Max-Age=0");
    }

    private static String modifyLastCharacter(String token) {
        char lastCharacter = token.charAt(token.length() - 1);
        char replacement = lastCharacter == 'A' ? 'B' : 'A';
        return token.substring(0, token.length() - 1) + replacement;
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
