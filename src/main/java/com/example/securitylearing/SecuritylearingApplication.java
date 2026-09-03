package com.example.securitylearing;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

// UserDetailsServiceAutoConfiguration is excluded: this app never uses Spring
// Security's AuthenticationManager/UserDetailsService, /register and /login check
// credentials themselves via AuthService, so the default generated-password user is
// pure noise.
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class SecuritylearingApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuritylearingApplication.class, args);
	}

}
