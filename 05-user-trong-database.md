# Bước 5 — User trong database (JPA + H2)

`InMemoryUserDetailsManager` (bước 4) chỉ tồn tại trong RAM, mất hết khi restart app, và không thể tự thêm/sửa/xoá user lúc runtime. Bước 5 chuyển nguồn user sang database thật (H2), qua đó viết `UserDetailsService` tuỳ biến đầu tiên — nền tảng cho mọi hệ thống auth thực tế sau này.

## 1. Các thành phần đã thêm

- `entity/User.java` — entity JPA: `id`, `username` (unique), `password` (đã mã hoá), `roles`.
- `repository/UserRepository.java` — `JpaRepository<User, Long>` + `findByUsername(String)`.
- `config/CustomUserDetailService.java` — implement `UserDetailsService`, đọc từ `UserRepository`, map sang `UserDetails` qua builder có sẵn.
- `Runner/SeedUser.java` — `CommandLineRunner` seed 2 user (`admin`/`ADMIN`, `user`/`USER`) vào DB nếu bảng đang rỗng.
- `SecurityConfig` — comment out bean `userDetailsService()` in-memory cũ (không được có 2 bean `UserDetailsService` cùng lúc), giữ lại `passwordEncoder()`.

## 2. Khái niệm cần nắm

1. **`UserDetailsService` là một "cổng cắm" (SPI), không phải class cụ thể:** `AuthenticationManager` không biết và không quan tâm user đến từ đâu — nó chỉ gọi `loadUserByUsername(username)` và nhận về `UserDetails`. Bước 4 cắm `InMemoryUserDetailsManager` vào cổng đó, bước 5 cắm `CustomUserDetailService` (đọc DB) — logic filter chain, Basic Auth ở `SecurityConfig` không cần đổi gì cả. Đây chính là điểm mạnh của kiến trúc theo interface.

2. **`UserDetails` là gì:** interface đại diện cho "một user dưới góc nhìn của Spring Security" — chỉ cần `getUsername()`, `getPassword()`, `getAuthorities()`, cùng 4 cờ trạng thái tài khoản. Entity `User` (JPA) không implement `UserDetails` trực tiếp — thay vào đó `loadUserByUsername` **map** entity sang builder `org.springframework.security.core.userdetails.User` có sẵn. Cách khác (thường gặp ở dự án lớn hơn) là cho chính entity `User` implement `UserDetails` luôn, tự viết 4 method boolean — tránh phải map qua lại, nhưng trộn lẫn domain model với security model.

3. **Vì sao seed bằng `CommandLineRunner` mà không hardcode trong `data.sql`:** để password được mã hoá qua đúng `PasswordEncoder` đang dùng trong app, thay vì phải tự tính sẵn chuỗi bcrypt rồi dán cứng vào SQL.

4. **Lưu password đã mã hoá:** cột `password` trong bảng `users` luôn chứa chuỗi bcrypt (bắt đầu bằng `$2a$...`), không bao giờ là plaintext. `loadUserByUsername` trả nguyên chuỗi đã hash này cho Spring Security — việc so khớp lúc login dùng `passwordEncoder.matches(rawPassword, storedHash)` diễn ra ở tầng dưới (`DaoAuthenticationProvider`), không cần tự gọi.

## 3. Bug thực tế đã gặp: vào `localhost:8080`, nhập login xong vẫn 401

**Nguyên nhân:** `SeedUser` thiếu annotation stereotype:

```java
public class SeedUser {          // ← thiếu @Configuration (hoặc @Component)
  @Bean
  CommandLineRunner seedUsers(...) { ... }
}
```

`@Bean` chỉ được Spring xử lý khi **class chứa nó** đã được đăng ký làm bean (qua `@Configuration`, `@Component`, hoặc tương đương). Dù `SeedUser` nằm trong package `com.example.securitylearing.Runner` (đúng phạm vi component-scan của `@SpringBootApplication`), component-scan chỉ "nhặt" các class có annotation stereotype. Không có annotation → class bị bỏ qua hoàn toàn → `seedUsers()` không bao giờ chạy → bảng `users` trong H2 luôn rỗng.

**Chuỗi sự kiện dẫn tới 401:**

1. Vào `localhost:8080` → không route nào match `/` → `anyRequest().authenticated()` áp dụng → trình duyệt bật popup Basic Auth.
2. Nhập `admin`/`admin123` → `CustomUserDetailService.loadUserByUsername("admin")` gọi `userRepository.findByUsername("admin")`.
3. DB rỗng → `UsernameNotFoundException` → Spring Security trả **401**, trình duyệt bật lại popup login (tưởng như "bấm login mà vẫn 401" lặp lại).

**Cách sửa:**

```java
@Configuration
public class SeedUser {
  @Bean
  CommandLineRunner seedUsers(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    ...
  }
}
```

**Lưu ý sau khi sửa:** vào `/` sau khi login thành công vẫn sẽ trả **404** (không phải lỗi) — vì project chỉ có route `/hello`, không có gì map ở `/`. Đó là hành vi đúng, không phải bug.

## 4. Cách kiểm tra

- Bật H2 console (`spring.h2.console.enabled: true` trong `application.yaml`) để xem bảng `users` có đúng 2 dòng sau khi khởi động lại app, cột `password` là chuỗi hash dài ~60 ký tự.
- `curl -i -u admin:admin123 http://localhost:8080/hello` vẫn phải trả 200 như bước 4 — chứng tỏ đổi nguồn dữ liệu (in-memory → DB) không phá vỡ hành vi authentication.
- Restart app: vì `CommandLineRunner` kiểm tra `count() == 0`, seed chỉ chạy 1 lần — user vẫn còn sau restart (khác hẳn in-memory bước 4, nơi mọi thứ mất sạch khi restart).

## 5. Câu hỏi tự kiểm tra

Nếu quên gọi `.roles(user.getRoles())` mà gán thẳng `.authorities(user.getRoles())`, và cột `roles` trong DB lưu giá trị `"ADMIN"` (không prefix) — kết quả cuối có khác gì so với dùng `.roles("ADMIN")` không?

→ Có khác: `.roles("ADMIN")` tự thêm `ROLE_` → ra authority `ROLE_ADMIN`; `.authorities("ADMIN")` giữ nguyên → ra `ADMIN`. Nếu route đang bảo vệ bằng `hasRole("ADMIN")` (ngầm định tìm `ROLE_ADMIN`), dùng nhầm `.authorities()` sẽ khiến admin bị 403 — lặp lại đúng lỗi đã nêu ở bước 4, vì đây là chỗ rất dễ nhầm khi map dữ liệu từ DB.

---

*Gợi ý bước tiếp theo:* Bước 6 — CRUD API (ví dụ "Product"/"Note"), phân quyền ADMIN được xoá còn USER chỉ đọc/tạo. Bật `@EnableMethodSecurity`, dùng `@PreAuthorize("hasRole('ADMIN')")` trên service/controller method.
