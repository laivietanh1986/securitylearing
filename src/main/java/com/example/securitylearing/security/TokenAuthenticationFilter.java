package com.example.securitylearing.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Tự đọc header X-Token và tự set SecurityContextHolder — không dùng
 * AuthenticationManager/AuthenticationProvider nào cả, đây là filter thủ công.
 *
 * Quy ước giá trị token (chỉ để phục vụ demo trong bài học này):
 *  - thiếu header             -> để anonymous, authorization phía sau sẽ từ chối -> 401 (AuthenticationEntryPoint)
 *  - "hardcoded-secret"       -> authenticate với ROLE_USER -> truy cập được /hello
 *  - "throw"                  -> ném thẳng RuntimeException để quan sát nó KHÔNG bị @ControllerAdvice bắt
 *  - bất kỳ giá trị sai khác  -> authenticate với ROLE_GUEST (không đủ quyền) -> 403 (AccessDeniedHandler)
 */
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TokenAuthenticationFilter.class);

    private static final String HEADER_NAME = "X-Token";
    private static final String VALID_TOKEN = "hardcoded-secret";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader(HEADER_NAME);

        if (token == null) {
            log.debug("No X-Token header present, leaving request as anonymous");
            filterChain.doFilter(request, response);
            return;
        }

        if ("throw".equals(token)) {
            // Cố tình ném exception ngay trong filter, TRƯỚC khi DispatcherServlet
            // được gọi. @ControllerAdvice chỉ bắt exception xảy ra bên trong
            // DispatcherServlet.doDispatch() (tức là trong controller/handler),
            // nên exception này sẽ KHÔNG bao giờ tới GlobalExceptionHandler.
            log.warn("Deliberately throwing from the filter to demonstrate that @ControllerAdvice cannot catch it");
            throw new RuntimeException("Boom thrown directly from TokenAuthenticationFilter");
        }

        if (!VALID_TOKEN.equals(token)) {
            log.debug("Invalid X-Token value, authenticating as low-privilege guest");
            Authentication guestAuth = new UsernamePasswordAuthenticationToken(
                    "guest", null, List.of(new SimpleGrantedAuthority("ROLE_GUEST")));
            SecurityContextHolder.getContext().setAuthentication(guestAuth);
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("Valid X-Token, authenticating as api-client with ROLE_USER");
        Authentication auth = new UsernamePasswordAuthenticationToken(
                "api-client", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        filterChain.doFilter(request, response);
    }
}
