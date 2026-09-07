package com.example.securitylearing.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

  private static final int CAPACITY = 20;
  private static final Duration REFILL_PERIOD = Duration.ofSeconds(10);

  private final ConcurrentHashMap<String, Bucket> bucketsByIp = new ConcurrentHashMap<>();

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String clientIp = request.getRemoteAddr();
    Bucket bucket = bucketsByIp.computeIfAbsent(clientIp, ip -> newBucket());

    if (!bucket.tryConsume(1)) {
      response.setStatus(429);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"Qua nhieu request, vui long thu lai sau\"}");
      return;
    }

    filterChain.doFilter(request, response);
  }

  private Bucket newBucket() {
    Bandwidth limit = Bandwidth.builder()
        .capacity(CAPACITY)
        .refillGreedy(CAPACITY, REFILL_PERIOD)
        .build();
    return Bucket.builder().addLimit(limit).build();
  }
}
