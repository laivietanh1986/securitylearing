package com.example.securitylearing.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.securitylearing.user.User;
import com.example.securitylearing.user.UserRepository;

/**
 * Simulates a legacy system that stored MD5 password hashes, so the app has real
 * {MD5}-prefixed rows to migrate to BCrypt on next successful login (see AuthService).
 */
@Component
@SuppressWarnings("deprecation")
public class LegacyUserSeeder implements CommandLineRunner {

    private final UserRepository userRepository;

    public LegacyUserSeeder(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) {
        if (userRepository.count() > 0) {
            return;
        }

        MessageDigestPasswordEncoder md5Encoder = new MessageDigestPasswordEncoder("MD5");
        seed("legacy1@example.com", "legacyPass123", md5Encoder);
        seed("legacy2@example.com", "oldSystemPw!", md5Encoder);
    }

    private void seed(String email, String rawPassword, MessageDigestPasswordEncoder md5Encoder) {
        String encoded = "{" + SecurityConfig.MD5_ID + "}" + md5Encoder.encode(rawPassword);
        userRepository.save(new User(email, encoded));
    }
}
