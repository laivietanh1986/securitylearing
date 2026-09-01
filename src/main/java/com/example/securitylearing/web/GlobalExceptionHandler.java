package com.example.securitylearing.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;
import java.util.Map;

/**
 * CHỈ bắt exception ném ra trong controller/handler method, tức là bên trong
 * DispatcherServlet.doDispatch(). Servlet filter (như TokenAuthenticationFilter)
 * chạy TRƯỚC DispatcherServlet trong filter chain, nên exception ném từ filter
 * (ví dụ X-Token: throw) sẽ đi thẳng ra ngoài container mà @ControllerAdvice
 * này không bao giờ thấy — hãy thử và quan sát response 500 mặc định của
 * Tomcat/Spring Boot thay vì body JSON do handler dưới đây tạo ra.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAny(Exception ex) {
        log.error("Handled by @ControllerAdvice: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "timestamp", Instant.now().toString(),
                "status", 500,
                "error", "Internal Server Error",
                "message", ex.getMessage()
        ));
    }
}
