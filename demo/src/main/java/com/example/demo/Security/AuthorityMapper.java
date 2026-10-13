package com.example.demo.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
//TWO OCCURING LOGIC ARE PUT HERE AND CALLED ELSEWHERE
public final class AuthorityMapper {
    private AuthorityMapper(){}

    public static List<String> toRoleNames(Collection<? extends GrantedAuthority> authorities){
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }

    public static List<SimpleGrantedAuthority> toAuthorities(Collection<String> roles){
        return roles.stream().map(SimpleGrantedAuthority::new).toList();
    }
}
