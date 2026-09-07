# Bước 13 — CORS, CSRF và bảo mật API công khai

> Quy trình: giống bước 12, user yêu cầu Claude code trực tiếp ("code tiếp cho tôi") thay vì tự gõ. Code dưới đây do Claude viết, đã build thành công (`mvn clean compile` → BUILD SUCCESS).

## 1. Khái niệm

### Same-Origin Policy (SOP) và vấn đề CORS giải quyết

Trình duyệt mặc định chặn JS chạy trên origin A (`http://localhost:3000`) đọc response từ origin B (`http://localhost:8080`) — "origin" = scheme + host + port, khác 1 trong 3 là bị chặn. Đây là tính năng bảo mật cố ý: nếu không có SOP, 1 trang web độc hại bạn mở có thể âm thầm gọi API ngân hàng bạn đang đăng nhập và đọc được response.

**CORS (Cross-Origin Resource Sharing)** là cơ chế để server B chủ động khai báo "tôi cho phép origin A gọi tôi", qua các header response:
```
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
```

**Điểm quan trọng dễ hiểu sai:** CORS được thực thi **ở trình duyệt**, không phải server, và nó **chỉ chặn việc JS đọc response**, không phải lúc nào cũng chặn request được gửi đi:

- **Simple request** (GET, hoặc POST với `Content-Type: text/plain`/`form-urlencoded`, không header tùy chỉnh): trình duyệt **vẫn gửi request thật, server vẫn xử lý và tạo side-effect** (ví dụ ghi DB) **trước khi** CORS có cơ hội chặn gì. CORS chỉ chặn JS đọc lại response sau đó.
- **Preflighted request** (có header tùy chỉnh như `Authorization`, `Content-Type: application/json`, method `PUT`/`DELETE`): trình duyệt gửi `OPTIONS` hỏi trước. Nếu server không cho phép, trình duyệt **không gửi request thật luôn**.

**Hệ quả quan trọng:** vì CORS (với simple request) không chặn được việc request thực thi, nó **không** bảo vệ được khỏi CSRF — đây là lý do CORS và CSRF là 2 cơ chế tách biệt, không thay thế nhau (xem mục CSRF bên dưới).

### CSRF (Cross-Site Request Forgery)

Kẻ tấn công dụ bạn mở 1 trang độc hại, trang đó âm thầm gửi request (`<form>` tự submit, hoặc `<img src="http://bank.com/transfer?...">`) tới trang bạn **đã đăng nhập** (có session cookie). Trình duyệt **tự động đính kèm cookie** vào request đó bất kể request đến từ đâu → server tưởng đây là request hợp lệ từ chính bạn.

**Vì sao CSRF token cần thiết cho session-based app:** server yêu cầu mỗi request thay đổi dữ liệu phải kèm thêm 1 token ngẫu nhiên mà trang độc hại không biết được (do SOP chặn nó đọc DOM/response của trang thật).

**Vì sao app dùng Bearer token (JWT trong header `Authorization`) không cần CSRF:** trình duyệt không có cơ chế tự động đính kèm header tùy ý như nó làm với cookie. Trang độc hại muốn gửi đúng JWT của bạn phải tự đọc token đó bằng JS chạy trên origin của chính nó — bị chặn bởi SOP. Thêm nữa, vì `Authorization` header khiến mọi request ghi dữ liệu trở thành **preflighted request**, CORS ở đây thực sự chặn được request từ gốc nếu origin không được phép — khác hẳn trường hợp simple request/cookie ở trên.

**Tóm lại:** CORS + xác thực qua header (không phải cookie) tự nhiên loại bỏ nguy cơ CSRF cho REST API kiểu này → tắt CSRF là hợp lý, không phải bỏ qua bảo mật.

## 2. Gap thực tế đã phát hiện

Trước khi sửa, `SecurityConfig.java` **không có dòng `.csrf(...)` nào** → CSRF protection ở trạng thái mặc định BẬT (Spring tự thêm `CsrfFilter`). Vì app đã chuyển hẳn sang Bearer JWT (bước 12), không dùng session/cookie để xác thực, CSRF ở đây vô nghĩa nhưng vẫn đang chặn: mọi `POST /notes`, `DELETE /notes/{id}` gọi qua curl (không có CSRF token) sẽ nhận `403 Forbidden` từ `CsrfFilter` — khác với `AccessDeniedHandler` tự viết, dễ gây nhầm lẫn khi debug ("token đúng mà vẫn 403 là sao?").

## 3. Code — `SecurityConfig.java`

```java
package com.example.securitylearing.config;

import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter) throws Exception{
    http
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(
        auth -> auth.requestMatchers("/hello").permitAll()
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
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
        );
    return http.build();
  }

  @Bean
  public JwtAuthenticationConverter jwtAuthenticationConverter() {
    Converter<Jwt, Collection<GrantedAuthority>> realmRolesConverter = jwt -> {
      Map<String, Object> realmAccess = jwt.getClaim("realm_access");
      if (realmAccess == null) {
        return List.of();
      }
      @SuppressWarnings("unchecked")
      List<String> roles = (List<String>) realmAccess.get("roles");
      return roles.stream()
          .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
          .collect(Collectors.toList());
    };

    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(realmRolesConverter);
    return converter;
  }

  @Bean
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("http://localhost:3000"));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    config.setAllowCredentials(false);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

}
```

**Giải thích các lựa chọn cấu hình:**
- `setAllowedOrigins(List.of("http://localhost:3000"))` — domain giả định của frontend SPA; đổi thành domain thật khi có.
- `setAllowCredentials(false)` — chỉ cần `true` khi frontend gửi cookie/session kèm request (`fetch(url, {credentials: 'include'})`). App dùng JWT trong header `Authorization`, không phải cookie, nên không cần.
- **Pitfall cần nhớ:** `allowedOrigins("*")` không thể dùng chung với `allowCredentials(true)` — trình duyệt chặn, Spring cũng ném exception lúc khởi động nếu cấu hình sai kết hợp này. Chỉ dùng `"*"` khi API thực sự công khai, không có credential nào liên quan.
- `.csrf(csrf -> csrf.disable())` — an toàn để tắt vì đã phân tích ở mục 1: xác thực qua header (không phải cookie) tự nhiên loại bỏ nguy cơ CSRF.

## 4. Test bằng curl

**Test CORS preflight:**
```bash
curl -X OPTIONS http://localhost:8080/notes \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization,Content-Type" \
  -v
```
Kiểm tra response có header `Access-Control-Allow-Origin: http://localhost:3000` không.

**Test CSRF đã tắt (POST không cần token nữa):**
```bash
curl -X POST http://localhost:8080/notes \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"test","content":"noi dung"}'
```
Nếu trước đây bị 403 vô lý dù token đúng (do `CsrfFilter`), giờ phải qua được (còn lại chỉ phụ thuộc role/scope từ bước 12).

## 5. Câu hỏi tự kiểm tra

1. Vì sao nói "CORS được thực thi ở trình duyệt, không phải server"? Nếu dùng Postman/curl gọi API cross-origin (không phải trình duyệt), CORS có chặn gì không?
2. Với 1 request "simple" (không preflight), CORS có ngăn được request đó **thực thi** trên server không, hay chỉ ngăn JS đọc response? Điều này liên quan thế nào tới việc CORS không thể thay thế CSRF token?
3. Vì sao `Authorization` header (thay vì cookie) lại khiến app tự nhiên an toàn hơn trước CSRF?
4. Nếu 1 ngày nào đó app đổi sang lưu JWT trong cookie (thay vì để frontend tự gắn header `Authorization`), CSRF có cần bật lại không? Vì sao?
