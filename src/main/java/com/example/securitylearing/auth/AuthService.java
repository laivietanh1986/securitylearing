package com.example.securitylearing.auth;

import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.securitylearing.user.User;
import com.example.securitylearing.user.UserRepository;

@Service
public class AuthService {

    public enum RegisterResult {
        CREATED, EMAIL_TAKEN
    }

    public enum LoginResult {
        OK, INVALID_CREDENTIALS
    }

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Encoded once at construction with the exact same encoder used for real users, so
     * the "email not found" branch of {@link #login} pays the same hashing cost as the
     * "email found" branch instead of returning early. See TimingAttackTest.
     */
    private final String dummyHash;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.dummyHash = passwordEncoder.encode("dummy-password-for-constant-time-check");
    }

    public RegisterResult register(String email, String rawPassword) {
        if (userRepository.existsByEmail(email)) {
            return RegisterResult.EMAIL_TAKEN;
        }
        userRepository.save(new User(email, passwordEncoder.encode(rawPassword)));
        return RegisterResult.CREATED;
    }

    public LoginResult login(String email, String rawPassword) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            passwordEncoder.matches(rawPassword, dummyHash);
            return LoginResult.INVALID_CREDENTIALS;
        }

        User user = userOpt.get();
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            return LoginResult.INVALID_CREDENTIALS;
        }

        if (passwordEncoder.upgradeEncoding(user.getPasswordHash())) {
            user.setPasswordHash(passwordEncoder.encode(rawPassword));
            userRepository.save(user);
        }
        return LoginResult.OK;
    }
}
