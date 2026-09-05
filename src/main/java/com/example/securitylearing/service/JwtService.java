package com.example.securitylearing.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
  @Value("${jwt.secret}")
  private String secretKey;
  public String generateToken(UserDetails userDetails){
    return Jwts.builder()
        .subject(userDetails.getUsername())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis()+1000*60*60))
        .signWith(getSigningKey())
        .compact();
  }
  private Claims parseClaims(String token) {
    return Jwts.parser().verifyWith(getSigningKey()).build()
        .parseSignedClaims(token).getPayload();
  }
  public String extractUsername(String token) {
    return parseClaims(token).getSubject();
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    String username = extractUsername(token);
    return username.equals(userDetails.getUsername()) && !isExpired(token);
  }

  private boolean isExpired(String token) {
    return parseClaims(token).getExpiration().before(new Date());
  }

  private SecretKey getSigningKey() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
  }

}
