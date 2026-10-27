package com.example.demo.security;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

@TestConfiguration(proxyBeanMethods = false)
class TestEndpointsConfiguration {

    @Bean
    ProjectSecurityRules testEndpointSecurityRules() {
        return rules -> rules.requestMatchers("/test/protected").authenticated();
    }

    @Bean
    RouterFunction<ServerResponse> testProtectedEndpoint() {
        return RouterFunctions.route()
                .GET("/test/protected", request -> ServerResponse.ok().body("authenticated"))
                .build();
    }
}
