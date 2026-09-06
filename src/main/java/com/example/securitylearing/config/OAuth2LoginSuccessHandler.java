package com.example.securitylearing.config;

import com.example.securitylearing.entity.User;
import com.example.securitylearing.repository.UserRepository;
import com.example.securitylearing.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

  private final JwtService jwtService;
  private final UserDetailsService userDetailsService; // chính là CustomUserDetailService
  private final UserRepository userRepository;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

    OAuth2User oAuth2User = oauthToken.getPrincipal();
    String provider = oauthToken.getAuthorizedClientRegistrationId(); // "github"
    String providerId = oAuth2User.getName();                         // GitHub numeric id
    User user = userRepository.findByProviderAndProviderId(provider, providerId)
        .orElseThrow(() -> new IllegalStateException("User not provisioned: " + provider + "/" + providerId));
    UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
    String accessToken = jwtService.generateAccessToken(userDetails);
    String refreshToken = jwtService.generateRefreshToken(userDetails);

    response.sendRedirect("/oauth2/success?token=" + accessToken + "&refresh=" + refreshToken);
  }
}
