package com.example.securitylearing.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AuditLogFilter extends OncePerRequestFilter {

  private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    long start = System.currentTimeMillis();
    try {
      filterChain.doFilter(request, response);
    } finally {
      long durationMs = System.currentTimeMillis() - start;
      auditLog.info("ip={} method={} path={} status={} user={} durationMs={}",
          request.getRemoteAddr(),
          request.getMethod(),
          request.getRequestURI(),
          response.getStatus(),
          resolveUsername(),
          durationMs);
    }
  }

  private String resolveUsername() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      return "anonymous";
    }
    if (authentication.getPrincipal() instanceof Jwt jwt) {
      String preferredUsername = jwt.getClaimAsString("preferred_username");
      return preferredUsername != null ? preferredUsername : jwt.getSubject();
    }
    return authentication.getName();
  }
}
