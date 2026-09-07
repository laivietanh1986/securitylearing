# Bước 12 — OAuth2 Resource Server với Keycloak

> Lưu ý về quy trình: khác các bước trước (Claude chỉ giải thích, user tự code), ở bước này **user yêu cầu Claude code trực tiếp** (do cần dựng thêm hạ tầng Keycloak bên ngoài, phần code thuần Spring làm nhanh hơn để tập trung vào phần setup Keycloak). Phần code dưới đây do Claude viết và đã build thành công (`mvn clean compile` → BUILD SUCCESS), nhưng **chưa test end-to-end với Keycloak thật** (cần user tự dựng Docker + tạo realm/client/role/user, xem mục 4).

## 1. Khái niệm

### Authorization Server vs Resource Server

- **Authorization Server** = nơi xác thực user và **phát hành** token (Keycloak). Nó biết password, biết user, ký token bằng private key.
- **Resource Server** = app Spring Boot — không biết password của ai, chỉ biết **kiểm tra chữ ký** token để tin rằng "token này do Keycloak cấp, chưa hết hạn, chưa bị sửa".

Khác bước 8 (app tự làm cả 2 vai trò bằng JWT HS256 tự ký): giờ 2 vai trò tách hẳn ra 2 hệ thống — đúng mô hình các công ty lớn dùng (Auth0, Okta, Keycloak, nhiều backend service khác nhau chỉ là Resource Server dùng chung 1 Authorization Server).

**Quyết định kiến trúc đã chốt:** thay thế hoàn toàn cơ chế xác thực cũ (Basic Auth ở bước 3, dựa trên `CustomUserDetailService` đọc từ bảng `users`), không chạy song song 2 cơ chế.

### JWK (JSON Web Key) & issuer

- Keycloak ký token bằng **RS256** (khác HS256 tự ký ở bước 8). App cần public key tương ứng để verify chữ ký.
- Keycloak publish public key tại JWK endpoint: `/realms/{realm}/protocol/openid-connect/certs`.
- `issuer-uri` (`http://localhost:8081/realms/myrealm`) → Spring Boot tự gọi `/.well-known/openid-configuration`, tự tìm JWK endpoint, tự tải + cache + refresh public key khi Keycloak xoay key — không cần code thủ công phần này.
- App cũng tự kiểm tra claim `iss` trong token có khớp `issuer-uri` cấu hình không → chống token giả mạo từ nơi khác.

### Scope-based authorization vs Role-based

- Claim `scope` trong JWT Keycloak → Spring **tự động** map thành `GrantedAuthority` dạng `SCOPE_xxx`. Dùng được ngay `@PreAuthorize("hasAuthority('SCOPE_profile')")`.
- Nhưng **roles** của Keycloak nằm ở claim khác — `realm_access.roles` (dạng nested JSON: `{"realm_access": {"roles": ["ADMIN", "USER"]}}`). Spring **không tự map** claim này → phải viết `JwtAuthenticationConverter` tùy chỉnh (mục 3) nếu muốn tiếp tục dùng `hasRole('ADMIN')` như các bước trước.

## 2. Code đã thay đổi

### `pom.xml` — thêm dependency

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

### `application.yaml` — trỏ tới Authorization Server

```yaml
spring:
  application:
    name: securitylearing
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8081/realms/myrealm
```

### `SecurityConfig.java` — bỏ Basic Auth, chuyển sang validate JWT

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

@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter) throws Exception{
    http.authorizeHttpRequests(
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

}
```

**Điểm đáng chú ý trong code:**
- `.httpBasic(...)` bị xoá hoàn toàn — không còn cơ chế xác thực nào dựa trên `CustomUserDetailService`/bảng `users` nữa.
- `JwtAuthenticationConverter` khai làm **tham số của `securityFilterChain(...)`** (Spring tự autowire theo kiểu, giống cách các filter/service khác đã làm ở các bước trước) thay vì gọi trực tiếp `jwtAuthenticationConverter()` trong thân method — tránh gọi 2 lần (1 lần tạo bean thật, 1 lần gọi tay) tạo ra 2 instance khác nhau.
- Thêm tiền tố `"ROLE_"` thủ công trong `realmRolesConverter` để `@PreAuthorize("hasRole('ADMIN')")` ở `NoteController` (từ bước 6) tiếp tục chạy đúng mà không cần sửa gì ở đó.
- Tiện sửa luôn 1 lỗi nhỏ có sẵn từ trước: matcher `"/note/**"` (thiếu chữ "s") không khớp endpoint thật `/notes/**` — đổi thành `"/notes/**"`. Trước đây không lộ ra vì `.anyRequest().authenticated()` vẫn bắt buộc login, chỉ là matcher đó chưa từng có tác dụng.

## 3. Setup Keycloak (Docker) — phần user tự làm

```bash
docker run -p 8081:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:24.0 start-dev
```

Vào `http://localhost:8081` (admin console), đăng nhập `admin`/`admin`:

1. Tạo **Realm** mới: `myrealm` (phải khớp `issuer-uri` trong `application.yaml`).
2. Tạo **Client**: Client ID `securitylearing-api`. Bật **"Direct access grants"** để lấy token bằng curl (password grant) — không cần dựng frontend để test.
3. Tạo **Realm roles**: `ADMIN`, `USER` (Realm settings → Roles, không phải Client roles — vì code đọc claim `realm_access.roles`).
4. Tạo **User** thử (Users → Add user), set password (tab Credentials, tắt "Temporary" nếu không muốn bị bắt đổi password lần đầu), gán role ở tab Role mapping.

## 4. Test bằng curl

Lấy token trực tiếp từ Keycloak (Resource Owner Password Credentials grant — chỉ dùng để test, không dùng trong production thật vì client phải cầm password user):

```bash
curl -X POST http://localhost:8081/realms/myrealm/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=securitylearing-api" \
  -d "username=<user_test>" \
  -d "password=<password>"
```

Copy `access_token` từ response, gọi thử API:

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:8080/notes
```

Test role-based:
```bash
curl -X DELETE -H "Authorization: Bearer <access_token>" http://localhost:8080/notes/1
```
User có role `ADMIN` → 200/204. User chỉ có role `USER` → 403 `{"error":"Bạn không đủ quyền"}`.

## 5. Gap / dead code còn tồn đọng (đã ghi nhận, chưa xử lý)

- **`CustomUserDetailService`, entity `User`, `UserRepository`, `SeedUser` giờ là dead code.** Trước đây (bước 5) chúng được dùng để Basic Auth đọc user từ DB; giờ `.httpBasic(...)` đã bị xoá, không còn `AuthenticationProvider` nào gọi tới `CustomUserDetailService` nữa — Keycloak đã thay thế hoàn toàn vai trò "biết ai là ai, biết password". Các class này vẫn còn trong code, biên dịch được, nhưng không còn tác dụng bảo vệ API nào. Có 2 hướng xử lý sau này:
  - Xoá hẳn nếu xác định app không cần một bảng `users` nội bộ nữa (toàn bộ identity giao cho Keycloak).
  - Giữ lại nếu về sau muốn liên kết `Note.owner` với `preferred_username` từ Keycloak để làm lại ownership-based authorization (giống bước 10 ở nhánh `spring_security`) — khi đó bảng `users` có thể dùng để lưu thêm thông tin nghiệp vụ (không phải để xác thực) liên kết với `sub`/`preferred_username` của Keycloak.
- **Chưa test với Keycloak thật** — code build được nhưng hành vi thực tế (JWK có tải đúng không, role có map đúng không, format claim `realm_access` có đúng như giả định không) cần verify khi user dựng Docker xong.
- **`preferred_username` chưa được dùng ở đâu trong code hiện tại** vì nhánh này chưa có ownership-based authorization (bước 10 nằm ở nhánh `spring_security`, không có ở đây). Nếu sau này thêm lại ownership check, nhớ lấy username qua `((Jwt) authentication.getPrincipal()).getClaimAsString("preferred_username")`, KHÔNG dùng `authentication.getName()` (trả về `sub` — UUID nội bộ Keycloak, không đọc được).

## 6. Câu hỏi tự kiểm tra

1. Vì sao Resource Server không cần biết password của user, nhưng vẫn xác thực được ai đang gọi API?
2. `issuer-uri` giúp Spring tự động làm những gì? Nếu Keycloak đổi cổng (8081 → 9000) mà quên sửa `issuer-uri`, chuyện gì xảy ra khi gọi API?
3. Vì sao claim `scope` được Spring tự map thành quyền, còn claim `realm_access.roles` thì không? Sự khác biệt "scope" và "role" về mặt ý nghĩa là gì?
4. Nếu xoá `CustomUserDetailService`/`User`/`UserRepository` hoàn toàn, còn phần nào của app bị ảnh hưởng không? (Gợi ý: `PasswordEncoder` bean có còn cần thiết không nếu không còn ai gọi `passwordEncoder.encode(...)` nữa?)
