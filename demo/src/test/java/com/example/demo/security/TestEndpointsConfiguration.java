package com.example.demo.security;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

/*
 * Test-only endpoint used by the integration tests to check the security chain.
 * It has NO security rule of its own on purpose: it must be protected by the template's
 * deny-by-default rule (anyRequest().authenticated()), which is what the tests verify.
 */
@TestConfiguration(proxyBeanMethods = false)
class TestEndpointsConfiguration {

    @Bean
    RouterFunction<ServerResponse> testProtectedEndpoint() {
        return RouterFunctions.route()
                .GET("/test/protected", request -> ServerResponse.ok().body("authenticated"))
                .build();
    }
}