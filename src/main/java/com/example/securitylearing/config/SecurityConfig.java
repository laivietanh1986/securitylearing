package com.example.securitylearing.config;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http,JwtAuthenticationFilter jwtAuthFilter) throws Exception{
    http
        .csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
        .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
        auth -> auth.requestMatchers("/hello").permitAll()
            .requestMatchers("/auth/**").permitAll()
            .requestMatchers("/notes/**").authenticated()
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
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
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
