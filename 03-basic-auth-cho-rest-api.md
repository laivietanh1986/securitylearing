# Bước 3 — Basic Auth cho REST API

Ở bước 1–2, filter chain đang dùng là loại "mặc định" tự sinh ra (`SpringBootWebSecurityConfiguration`), chặn **mọi** request kể cả `/hello`. Bước 3 tự viết tường minh một bean `SecurityFilterChain`, thay thế hoàn toàn cấu hình mặc định đó và tự quyết định route nào public/protected.

## 1. Cấu hình đã thêm

`src/main/java/com/example/securitylearing/config/SecurityConfig.java`:

```java
@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
        auth -> auth.requestMatchers("/hello").permitAll()
            .anyRequest().authenticated()
    )
        .httpBasic(Customizer.withDefaults());
    return http.build();
  }
}
```

## 2. Khái niệm cần nắm

1. **`SecurityFilterChain` là gì:** một chuỗi các `Filter` servlet (không phải interceptor MVC) được `FilterChainProxy` gọi trước khi request chạm tới `DispatcherServlet`. Khi tự khai báo bean này, `@ConditionalOnMissingBean` khiến Spring Boot **tắt hẳn** filter chain mặc định — từ giờ chịu trách nhiệm 100% cho việc "mở"/"khoá" route.

2. **`authorizeHttpRequests` — thứ tự rule quan trọng:** các `requestMatchers(...)` được đánh giá **theo thứ tự khai báo**, rule đầu tiên khớp sẽ thắng. Vì vậy `permitAll()` cho `/hello` phải đứng **trước** `anyRequest().authenticated()` — nếu đảo ngược thứ tự, `anyRequest()` sẽ khớp trước và `/hello` vẫn bị chặn.

3. **`httpBasic()`:** bật cơ chế Basic Authentication — client gửi header `Authorization: Basic base64(username:password)` trên mỗi request. Khác với `formLogin()` (redirect sang trang `/login`, dùng session), Basic Auth là stateless-friendly hơn, phù hợp gọi bằng curl/Postman cho REST API — không có khái niệm "trang login".

4. **Vì sao không cần khai `formLogin()`:** nếu không tự thêm `.formLogin(...)`, nó sẽ không tự bật (khác với filter chain mặc định vốn bật cả hai). Chỉ Basic Auth là đủ để test REST API bằng curl/Postman.

## 3. Cách kiểm tra

```bash
curl -i http://localhost:8080/hello
# → 200 OK, không cần đăng nhập

curl -i -u admin:admin123 http://localhost:8080/actuator   # hoặc bất kỳ route nào khác
# → không có -u thì 401 Unauthorized kèm header WWW-Authenticate: Basic
```

Vì project hiện chỉ có đúng route `/hello`, có thể gọi một path bất kỳ không tồn tại (ví dụ `/foo`) để quan sát **401** thay vì 404 — minh chứng filter chain chặn request **trước** khi nó kịp tới `DispatcherServlet` (nơi lẽ ra sẽ trả 404 vì không có handler khớp).

## 4. Câu hỏi tự kiểm tra

Nếu đổi `requestMatchers("/hello").permitAll()` xuống **sau** `anyRequest().authenticated()`, điều gì xảy ra?

→ `/hello` vẫn bị 401, vì `anyRequest()` đã khớp và "thắng" trước rule permitAll — minh hoạ rõ cơ chế "first match wins" của `authorizeHttpRequests`.

---

*Gợi ý bước tiếp theo:* Bước 4 — tạo 2-3 user (ADMIN, USER) bằng `InMemoryUserDetailsManager` + `PasswordEncoder` (BCrypt), thay cho cấu hình 1-user tĩnh ở `application.yaml`.
