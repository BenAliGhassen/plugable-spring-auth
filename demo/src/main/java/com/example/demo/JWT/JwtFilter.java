package com.example.demo.JWT;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.example.demo.Security.AuthorityMapper;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//THIS FILE IS JWT FILTER THIS FILTER IS THE FIRST IN OUR FILTER CHAIN IT CHECK IF THERE IS A JWT TOKEN IN THE REQUEST HEADER AND INITALIZE THE SECURITY CONTEXT WITH AN "UsernamePasswordAuthenticationToken" OBJ OR LET IT EMPTY
@Component
public class JwtFilter extends OncePerRequestFilter {

    private static final String ACCESS_TOKEN_COOKIE = "access_token";
    private final JwtService jwtService;

    public JwtFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //if the security context box is empty then find the access token
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = findAccessToken(request.getCookies());
            //if token found is not null parse it and create a UsernamePasswordAuthenticationToken obj fill it with the user name and role/roles then put it in the security context box
            if (token != null) {
                try {
                    TokenClaims claims = jwtService.parseToken(token);
                    String username = claims.username();
                    List<SimpleGrantedAuthority> authorities = AuthorityMapper.toAuthorities(claims.roles());
                    if (username != null && !username.isBlank()) {
                        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(username, null, authorities);
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                } catch (JwtException exception) {
                    SecurityContextHolder.clearContext();
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private String findAccessToken(Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (ACCESS_TOKEN_COOKIE.equals(cookie.getName()) && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }

        return null;
    }
}
