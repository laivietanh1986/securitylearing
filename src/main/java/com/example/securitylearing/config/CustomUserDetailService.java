package com.example.securitylearing.config;

import com.example.securitylearing.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    com.example.securitylearing.entity.User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found "+username));
    return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
        .password(user.getPassword() != null ? user.getPassword() : "{noop}oauth2-external-user")
        .roles(user.getRoles())
        .build();

  }
}
