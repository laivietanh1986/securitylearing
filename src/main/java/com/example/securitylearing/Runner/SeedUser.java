package com.example.securitylearing.Runner;

import com.example.securitylearing.entity.User;
import com.example.securitylearing.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
@Configuration
public class SeedUser {
  @Bean
  CommandLineRunner seedUsers(UserRepository userRepository, PasswordEncoder passwordEncoder){
    return args -> {
      if(userRepository.count() ==0){
        userRepository.save(User.builder()
            .username("admin").password(passwordEncoder.encode("admin123")).roles("ADMIN").build());
        userRepository.save(User.builder()
            .username("user").password(passwordEncoder.encode("user123")).roles("USER").build());
      }
    };
  }

}
