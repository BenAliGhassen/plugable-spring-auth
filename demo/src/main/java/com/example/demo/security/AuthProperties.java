package com.example.demo.security;
import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
    @DefaultValue Jwt jwt,
    @DefaultValue Access access,
    @DefaultValue Refresh refresh,
    @DefaultValue Cookie cookie,
    @DefaultValue Cors cors) {

public AuthProperties {
    if(refresh.ttl().compareTo(access.ttl()) <= 0){
        throw new IllegalArgumentException("Retention ttl value must be greater than Access ttl");
    }
}


public record Refresh(@DefaultValue("3d") Duration retention, @DefaultValue("7d") Duration ttl){
    public Refresh {
    if(retention == null || retention.isNegative() || retention.isZero()){
        throw new IllegalArgumentException("Retention value must be filled with positive value");
    }

    if(ttl == null || ttl.isNegative() || ttl.isZero()){
        throw new IllegalArgumentException("Refresh TTL value must be filled with positive value");
    }
    }
}

public record Jwt(String secret){
    public Jwt {
    if(secret == null || secret.isBlank()){
        throw new IllegalArgumentException("Secret is required");
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
        throw new IllegalArgumentException("Access TTL value must be filled with positive value");
    }
    }
}

public record Cookie(@DefaultValue("true") boolean secure){}

public record Cors(List<String> origins){
    public Cors {
    if(origins == null || origins.isEmpty() || origins.contains("*")){
        throw new IllegalArgumentException("Origins is required and must be diffrent of '*' ");
    }
    }
}

    }
