package com.example.demo.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.example.demo.security.web.AuthCookies;

import io.jsonwebtoken.JwtException;

@ExtendWith(MockitoExtension.class)
class JwtFilterTest {

    private static final String ACCESS_TOKEN = "access-token-value";
    private static final String USERNAME = "alice@example.com";
    private static final List<String> ROLES = List.of("ROLE_USER", "ROLE_ADMIN");

    @Mock
    private JwtService jwtService;

    private JwtFilter jwtFilter;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        jwtFilter = new JwtFilter(jwtService);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validAccessTokenCookieAuthenticatesClaimsAndContinuesTheChain() throws Exception {
        when(jwtService.parseToken(ACCESS_TOKEN)).thenReturn(new TokenClaims(USERNAME, ROLES));
        MockHttpServletRequest request = requestWithCookies(new jakarta.servlet.http.Cookie(AuthCookies.ACCESS_TOKEN, ACCESS_TOKEN));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        jwtFilter.doFilter(request, response, chain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getName()).isEqualTo(USERNAME);
        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyElementsOf(ROLES);
        assertChainContinued(chain, request);
    }

    @Test
    void noCookiesLeavesContextEmptyAndContinuesTheChain() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        jwtFilter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(jwtService, never()).parseToken(org.mockito.ArgumentMatchers.anyString());
        assertChainContinued(chain, request);
    }

    @Test
    void otherCookiesLeaveContextEmptyAndContinueTheChain() throws Exception {
        MockHttpServletRequest request = requestWithCookies(new jakarta.servlet.http.Cookie(AuthCookies.REFRESH_TOKEN, "refresh-token-value"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        jwtFilter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(jwtService, never()).parseToken(org.mockito.ArgumentMatchers.anyString());
        assertChainContinued(chain, request);
    }

    @Test
    void blankAccessTokenCookieIsIgnoredAndLeavesContextEmpty() throws Exception {
        MockHttpServletRequest request = requestWithCookies(new jakarta.servlet.http.Cookie(AuthCookies.ACCESS_TOKEN, " \t "));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        jwtFilter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(jwtService, never()).parseToken(org.mockito.ArgumentMatchers.anyString());
        assertChainContinued(chain, request);
    }

    @Test
    void jwtExceptionLeavesContextEmptyAndContinuesTheChain() throws Exception {
        when(jwtService.parseToken(ACCESS_TOKEN)).thenThrow(new JwtException("expired"));
        MockHttpServletRequest request = requestWithCookies(new jakarta.servlet.http.Cookie(AuthCookies.ACCESS_TOKEN, ACCESS_TOKEN));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        jwtFilter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertChainContinued(chain, request);
    }

    @Test
    void blankUsernameClaimLeavesContextEmptyAndContinuesTheChain() throws Exception {
        when(jwtService.parseToken(ACCESS_TOKEN)).thenReturn(new TokenClaims(" \t ", ROLES));
        MockHttpServletRequest request = requestWithCookies(new jakarta.servlet.http.Cookie(AuthCookies.ACCESS_TOKEN, ACCESS_TOKEN));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        jwtFilter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertChainContinued(chain, request);
    }

    @Test
    void existingAuthenticationIsPreservedAndTokenIsNotParsed() throws Exception {
        Authentication existingAuthentication = UsernamePasswordAuthenticationToken.authenticated(
                "existing-user",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_EXISTING")));
        SecurityContextHolder.getContext().setAuthentication(existingAuthentication);
        MockHttpServletRequest request = requestWithCookies(new jakarta.servlet.http.Cookie(AuthCookies.ACCESS_TOKEN, ACCESS_TOKEN));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        jwtFilter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existingAuthentication);
        verify(jwtService, never()).parseToken(org.mockito.ArgumentMatchers.anyString());
        assertChainContinued(chain, request);
    }

    private static MockHttpServletRequest requestWithCookies(jakarta.servlet.http.Cookie... cookies) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(cookies);
        return request;
    }

    private static void assertChainContinued(MockFilterChain chain, MockHttpServletRequest request) {
        assertThat(chain.getRequest()).isSameAs(request);
    }
}
