package com.example.securitylearing.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.securitylearing.user.User;
import com.example.securitylearing.user.UserRepository;

class AuthServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = new BCryptPasswordEncoder(4);
        authService = new AuthService(userRepository, passwordEncoder);
    }

    @Test
    void registerCreatesUserWhenEmailIsFree() {
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);

        AuthService.RegisterResult result = authService.register("new@example.com", "password123");

        assertThat(result).isEqualTo(AuthService.RegisterResult.CREATED);
    }

    @Test
    void registerRejectsDuplicateEmail() {
        when(userRepository.existsByEmail("taken@example.com")).thenReturn(true);

        AuthService.RegisterResult result = authService.register("taken@example.com", "password123");

        assertThat(result).isEqualTo(AuthService.RegisterResult.EMAIL_TAKEN);
    }

    @Test
    void loginSucceedsWithCorrectPassword() {
        User user = new User("user@example.com", passwordEncoder.encode("password123"));
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        AuthService.LoginResult result = authService.login("user@example.com", "password123");

        assertThat(result).isEqualTo(AuthService.LoginResult.OK);
    }

    @Test
    void loginFailsWithWrongPassword() {
        User user = new User("user@example.com", passwordEncoder.encode("password123"));
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        AuthService.LoginResult result = authService.login("user@example.com", "wrong-password");

        assertThat(result).isEqualTo(AuthService.LoginResult.INVALID_CREDENTIALS);
    }

    @Test
    void loginFailsWithUnknownEmail() {
        when(userRepository.findByEmail(any())).thenReturn(Optional.empty());

        AuthService.LoginResult result = authService.login("nobody@example.com", "whatever");

        assertThat(result).isEqualTo(AuthService.LoginResult.INVALID_CREDENTIALS);
    }
}
