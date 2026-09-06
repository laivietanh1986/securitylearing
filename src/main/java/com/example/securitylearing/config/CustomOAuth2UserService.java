package com.example.securitylearing.config;

import com.example.securitylearing.entity.User;
import com.example.securitylearing.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

  private final UserRepository userRepository;

  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    OAuth2User oAuth2User = super.loadUser(userRequest);

    String provider = userRequest.getClientRegistration().getRegistrationId(); // "google" hoặc "github"
    String providerId = oAuth2User.getName(); // Spring set = "sub" (Google) hoặc "id" (GitHub)
    String email = oAuth2User.getAttribute("email");

    User user = userRepository.findByProviderAndProviderId(provider, providerId)
        .orElseGet(() -> {
          User newUser = User.builder()
              .username(email != null ? email : provider + "_" + providerId)
              .provider(provider)
              .providerId(providerId)
              .roles("USER")
              .build();
          return userRepository.save(newUser);
        });

    return oAuth2User;
  }
}
