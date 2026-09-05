package com.example.securitylearing.api;

import com.example.securitylearing.entity.RefreshToken;
import com.example.securitylearing.entity.User;
import com.example.securitylearing.model.LoginRequest;
import com.example.securitylearing.model.RegisterRequest;
import com.example.securitylearing.repository.RefreshTokenRepository;
import com.example.securitylearing.repository.UserRepository;
import com.example.securitylearing.service.JwtService;
import jakarta.validation.Valid;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
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
  private final RefreshTokenRepository refreshTokenRepository;
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
    String accessToken = jwtService.generateAccessToken(userDetails);
    String refreshToken = jwtService.generateRefreshToken(userDetails);

    refreshTokenRepository.save(RefreshToken.builder()
        .token(refreshToken)
        .username(userDetails.getUsername())
        .expiryDate(Instant.now().plus(7, ChronoUnit.DAYS))
        .revoked(false)
        .build());

    return ResponseEntity.ok(Map.of("accessToken", accessToken, "refreshToken", refreshToken));
  }
  @PostMapping("/refresh")
  public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
    String oldToken = body.get("refreshToken");

    RefreshToken stored = refreshTokenRepository.findByToken(oldToken)
        .orElseThrow(() -> new BadCredentialsException("Refresh token không hợp lệ"));

    if (stored.isRevoked() || stored.getExpiryDate().isBefore(Instant.now())) {
      throw new BadCredentialsException("Refresh token đã hết hạn hoặc bị thu hồi");
    }

    String username = jwtService.extractUsername(oldToken);
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

    // Rotation: thu hồi token cũ, phát hành cặp token mới
    stored.setRevoked(true);
    refreshTokenRepository.save(stored);

    String newAccessToken = jwtService.generateAccessToken(userDetails);
    String newRefreshToken = jwtService.generateRefreshToken(userDetails);
    refreshTokenRepository.save(RefreshToken.builder()
        .token(newRefreshToken).username(username)
        .expiryDate(Instant.now().plus(7, ChronoUnit.DAYS)).revoked(false).build());

    return ResponseEntity.ok(Map.of("accessToken", newAccessToken, "refreshToken", newRefreshToken));
  }
  @PostMapping("/logout")
  public ResponseEntity<?> logout(@RequestBody Map<String, String> body) {
    refreshTokenRepository.findByToken(body.get("refreshToken"))
        .ifPresent(rt -> { rt.setRevoked(true); refreshTokenRepository.save(rt); });
    return ResponseEntity.noContent().build();
  }
}
