package com.example.securitylearing.api;

import com.example.securitylearing.entity.User;
import com.example.securitylearing.model.LoginRequest;
import com.example.securitylearing.model.RegisterRequest;
import com.example.securitylearing.repository.UserRepository;
import com.example.securitylearing.service.JwtService;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final UserDetailsService userDetailsService;
  private final JwtService jwtService;

  @PostMapping("/register")
  public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
    User user = User.builder()
        .username(req.getUsername())
        .password(passwordEncoder.encode(req.getPassword()))
        .roles("USER")
        .build();
    userRepository.save(user);
    return ResponseEntity.status(HttpStatus.CREATED).build();
  }

  @PostMapping("/login")
  public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));
    UserDetails userDetails = userDetailsService.loadUserByUsername(req.getUsername());
    String token = jwtService.generateToken(userDetails);
    return ResponseEntity.ok(Map.of("token", token));
  }
}
