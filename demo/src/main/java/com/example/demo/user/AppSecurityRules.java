package com.example.demo.user;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import com.example.demo.security.ProjectSecurityRules;


//add your rules here the rules will be automaticlly injected in the filter chain
@Component 
public class AppSecurityRules implements ProjectSecurityRules {
    @Override
    public void configure(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry rules) {
                rules.requestMatchers(HttpMethod.POST, "/signup").permitAll();
    }

}
