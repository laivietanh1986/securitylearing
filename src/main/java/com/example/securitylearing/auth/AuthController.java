package com.example.securitylearing.auth;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.securitylearing.auth.dto.LoginRequest;
import com.example.securitylearing.auth.dto.RegisterRequest;

@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request) {
        AuthService.RegisterResult result = authService.register(request.getEmail(), request.getPassword());
        if (result == AuthService.RegisterResult.EMAIL_TAKEN) {
            return ResponseEntity.status(409).build();
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@Valid @RequestBody LoginRequest request) {
        AuthService.LoginResult result = authService.login(request.getEmail(), request.getPassword());
        if (result == AuthService.LoginResult.OK) {
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.status(401).build();
    }
}
