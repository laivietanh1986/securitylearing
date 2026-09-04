# Lộ trình học Spring Security (dễ → khó)

Dựa trên các dependency đã có trong `pom.xml` (Web, Data JPA, Validation, Security, H2, springdoc-openapi, Lombok).
Mỗi project nên làm trên một branch riêng hoặc tuần tự trên cùng project này, commit sau mỗi bước để dễ so sánh trước/sau.

## Cấp 1 — Nền tảng (Authentication cơ bản)

1. **Hello Security mặc định**
   - Chạy app với `spring-boot-starter-security` đã có sẵn, quan sát Spring Boot tự sinh user `user` + password ngẫu nhiên trong log.
   - Khái niệm: `UserDetailsService` mặc định, filter chain mặc định, vì sao mọi request đều bị chặn login.

2. **Cấu hình user trong `application.properties`**
   - Đặt `spring.security.user.name` / `password` cố định.
   - Khái niệm: cách Spring Boot autoconfigure `InMemoryUserDetailsManager`.

3. **Basic Auth cho REST API**
   - Viết `SecurityFilterChain` bean, cấu hình `httpBasic()`, cho phép `/hello` public, các endpoint khác cần login.
   - Khái niệm: `SecurityFilterChain`, `authorizeHttpRequests`, phân biệt public vs protected route.

4. **In-memory nhiều user với vai trò (roles)**
   - Tạo 2-3 user (ADMIN, USER) bằng `InMemoryUserDetailsManager` + `PasswordEncoder` (BCrypt).
   - Khái niệm: `PasswordEncoder`, roles/authorities, `hasRole()` vs `hasAuthority()`.

## Cấp 2 — Authorization & dữ liệu thật

5. **User trong database (JPA + H2)**
   - Tạo entity `User` (username, password, role), `UserRepository`, implement `UserDetailsService` đọc từ DB.
   - Khái niệm: custom `UserDetailsService`, `UserDetails` implementation, lưu password đã mã hoá.

6. **Phân quyền theo endpoint và theo method**
   - CRUD API (ví dụ quản lý "Product"/"Note"), phân quyền: ADMIN được xoá, USER chỉ được đọc/tạo.
   - Bật `@EnableMethodSecurity`, dùng `@PreAuthorize("hasRole('ADMIN')")` trên service/controller method.
   - Khái niệm: authorization ở tầng URL vs tầng method, `@PreAuthorize`/`@PostAuthorize`.

7. **Validation kết hợp Security**
   - Dùng `spring-boot-starter-validation` để validate request body (`@Valid`, `@NotBlank`...), xử lý lỗi qua `@ControllerAdvice`.
   - Khái niệm: tách lỗi validation (400) và lỗi authorization (401/403) đúng cách, `AccessDeniedHandler`, `AuthenticationEntryPoint`.

## Cấp 3 — Stateless & Token-based Auth

8. **Đăng ký + đăng nhập trả về JWT**
   - Thêm thư viện JWT (`jjwt` hoặc `nimbus-jose-jwt`), viết `/auth/register`, `/auth/login` trả token.
   - Tắt session (`SessionCreationPolicy.STATELESS`), viết `JwtAuthenticationFilter` để đọc token từ header `Authorization: Bearer ...`.
   - Khái niệm: stateless auth, `OncePerRequestFilter`, cách filter chain xử lý JWT, ký/verify token.

9. **Refresh token**
   - Thêm access token (thời gian sống ngắn) + refresh token (dài hơn), endpoint `/auth/refresh`.
   - Khái niệm: vòng đời token, revoke/blacklist token, lưu refresh token trong DB.

10. **Phân quyền chi tiết dựa trên dữ liệu (ownership)**
    - Ví dụ: user chỉ được sửa/xoá "Note" do chính mình tạo.
    - Khái niệm: `@PreAuthorize` với SpEL truy cập tham số method, authorization dựa trên dữ liệu chứ không chỉ role.

## Cấp 4 — Tích hợp nâng cao

11. **OAuth2 Login (Google/GitHub)**
    - Thêm `spring-boot-starter-oauth2-client`, cấu hình login qua Google/GitHub.
    - Khái niệm: OAuth2 Authorization Code flow, `OAuth2User`, ánh xạ user OAuth vào user nội bộ.

12. **Resource Server bảo vệ bằng JWT (OAuth2 Resource Server)**
    - Dùng `spring-boot-starter-oauth2-resource-server`, xác thực JWT phát hành từ một Authorization Server (Keycloak).
    - Khái niệm: JWK, issuer, scope-based authorization, tách Authorization Server và Resource Server.

13. **CORS, CSRF và bảo mật API công khai**
    - Cấu hình CORS đúng cho frontend SPA gọi API; hiểu khi nào cần bật/tắt CSRF (session-based vs token-based).
    - Khái niệm: `CorsConfigurationSource`, CSRF token, khác biệt bảo mật giữa web app truyền thống và REST API.

14. **Rate limiting, audit log, và bảo vệ chống brute-force**
    - Giới hạn số lần đăng nhập sai, ghi log truy cập/authorization qua `AuditorAware` hoặc filter riêng.
    - Khái niệm: bảo mật thực chiến ngoài phạm vi Spring Security core (rate limit, logging, account lockout).

## Cấp 5 — Kiến trúc & kiểm thử

15. **Multi-module / Microservices với Security dùng chung**
    - Tách Auth Service riêng phát hành JWT, các service khác chỉ verify token (Resource Server).
    - Khái niệm: chia sẻ secret/JWK giữa các service, service-to-service auth.

16. **Viết test cho Security**
    - Dùng `spring-security-test` (`@WithMockUser`, `SecurityMockMvcRequestPostProcessors`) để test các endpoint có/không có quyền.
    - Khái niệm: test authentication/authorization mà không cần gọi thật hệ thống login.

---

### Cách dùng file này
- Làm tuần tự từng mục, mỗi mục nên có commit riêng để so sánh diff trước/sau khi thêm tính năng.
- Sau mỗi cấp, thử tự đặt câu hỏi: "Nếu bỏ dòng cấu hình X thì điều gì xảy ra?" để hiểu rõ cơ chế thay vì chỉ copy code.
