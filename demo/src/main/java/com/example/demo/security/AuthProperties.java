package com.example.demo.security;
import java.time.Duration;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
    @DefaultValue Jwt jwt,
    @DefaultValue Access access,
    @DefaultValue Refresh refresh,
    @DefaultValue Cookie cookie,
    @DefaultValue Cors cors,
    @DefaultValue Login login
) {

public AuthProperties {
    if(refresh.ttl().compareTo(access.ttl()) <= 0){
        throw new IllegalArgumentException("AUTH_REFRESH_TTL value must be greater than AUTH_ACCESS_TTL");
    }
}


public record Refresh(@DefaultValue("3d") Duration retention, @DefaultValue("7d") Duration ttl){
    public Refresh {
    if(retention == null || retention.isNegative() || retention.isZero()){
        throw new IllegalArgumentException("AUTH_REFRESH_RETENTION value must be filled with positive value");
    }

    if(ttl == null || ttl.isNegative() || ttl.isZero()){
        throw new IllegalArgumentException("AUTH_REFRESH_TTL value must be filled with positive value");
    }
    }
}

public record Jwt(String secret){
    public Jwt {
    if(secret == null || secret.isBlank()){
        throw new IllegalArgumentException("AUTH_JWT_SECRET is required");
    }
    }
    @Override 
    public String toString(){
        return "jwt[secret=*******]";
    }
}

public record Access(@DefaultValue("15m") Duration ttl){
    public Access {
    if(ttl == null || ttl.isNegative() || ttl.isZero()){
        throw new IllegalArgumentException("AUTH_ACCESS_TTL value must be filled with positive value");
    }
    }
}

public record Cookie(@DefaultValue("true") boolean secure){}

public record Cors(List<String> origins){
    private static final Pattern ORIGIN = Pattern.compile("https?://[a-z0-9.-]+(:[0-9]{1,5})?");
    public Cors {    
        if(origins == null || origins.isEmpty()){
            throw new IllegalArgumentException("AUTH_CORS_ORIGINS is required");
        }
        for(String origin:origins)
            validateOrigin(origin);
    }
    private static void validateOrigin(String origin){
        if(origin == null || !ORIGIN.matcher(origin).matches()){
            throw new IllegalArgumentException("AUTH_CORS_ORIGINS is invalid origin " + origin + ". Expected lowercase scheme://host[:port]");
        }
        
    }
}

public record Login(@DefaultValue("5") int maxFailure, @DefaultValue("20") int maxIpFailure, @DefaultValue("15m") Duration window) {
    public Login{
        if(maxFailure <= 0){
            throw new IllegalArgumentException("AUTH_LOGIN_MAXFAILURE must be greater than zero");
        }
        if(maxIpFailure <= 0){
            throw new IllegalArgumentException("AUTH_LOGIN_MAXIPFAILURE must be greater than zero");
        }
        if(maxFailure >= maxIpFailure){
            throw new IllegalArgumentException("AUTH_LOGIN_MAXIPFAILURE should be greater than AUTH_LOGIN_MAXFAILURE");
        }
        if(window == null || window.isNegative() || window.isZero()){
            throw new IllegalArgumentException("AUTH_LOGIN_WINDOW value must be filled with positive value");
        }
    }
}

    }
