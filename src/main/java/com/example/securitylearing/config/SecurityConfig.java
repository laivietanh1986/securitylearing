package com.example.securitylearing.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * No JWT / no session: /register and /login do their own credential check and
 * answer 200/401 directly, so the filter chain just needs to get out of the way.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Chosen from the real measurements in BENCHMARK.md (see "Chosen cost" section).
     */
    public static final int BCRYPT_COST = 12;

    public static final String BCRYPT_ID = "bcrypt";
    public static final String MD5_ID = "MD5";

    @Bean
    @SuppressWarnings("deprecation") // MessageDigestPasswordEncoder is deliberate: simulates a legacy system
    public PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put(BCRYPT_ID, new BCryptPasswordEncoder(BCRYPT_COST));
        encoders.put(MD5_ID, new MessageDigestPasswordEncoder("MD5"));
        return new DelegatingPasswordEncoder(BCRYPT_ID, encoders);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
