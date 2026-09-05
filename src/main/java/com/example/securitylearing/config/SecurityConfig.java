package com.example.securitylearing.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
    http.authorizeHttpRequests(
        auth -> auth.requestMatchers("/hello").permitAll()
            .requestMatchers("/note/**").authenticated()
            .anyRequest().authenticated()
    )
        .exceptionHandling(ex-> ex
            .authenticationEntryPoint((request, response, authException) -> {
              response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
              response.setContentType("application/json");
              response.getWriter().write("{\"error\":\"Bạn chưa đăng nhập\"}");
            })
            .accessDeniedHandler((request, response, accessEx) -> {
              response.setStatus(HttpServletResponse.SC_FORBIDDEN);
              response.setContentType("application/json");
              response.getWriter().write("{\"error\":\"Bạn không đủ quyền\"}");
            })
        )
        .httpBasic(Customizer.withDefaults());
    return http.build();
  }
//  @Bean
//  public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder){
//    UserDetails admin = User.withUsername("admin")
//        .password(passwordEncoder.encode("admin123"))
//        .roles("ADMIN")
//        .build();
//    UserDetails user = User.withUsername("user")
//        .password(passwordEncoder.encode("user123"))
//        .roles("USER")
//        .build();
//    return new InMemoryUserDetailsManager(admin,user);
//  }
  @Bean
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }

}
