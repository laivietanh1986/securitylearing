# Bước 4 — In-memory nhiều user với vai trò (roles)

`spring.security.user.*` chỉ cho phép khai báo **đúng 1 user**, và khi có bean `SecurityFilterChain` riêng nhưng chưa có `UserDetailsService` riêng, Spring Boot vẫn dùng auto-config cũ dựa trên `application.yaml`. Bước 4 tự viết bean `UserDetailsService` trả về nhiều user, với role khác nhau — đây cũng là bước khiến cấu hình `spring.security.user.*` ở `application.yaml` **bị vô hiệu hoàn toàn** (đúng như câu tự-kiểm-tra ở bước 2).

## 1. Cấu hình cần thêm

Thêm vào `SecurityConfig` (hoặc tách bean riêng):

```java
@Bean
public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    UserDetails admin = User.withUsername("admin")
        .password(passwordEncoder.encode("admin123"))
        .roles("ADMIN")
        .build();

    UserDetails user = User.withUsername("user")
        .password(passwordEncoder.encode("user123"))
        .roles("USER")
        .build();

    return new InMemoryUserDetailsManager(admin, user);
}

@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

## 2. Khái niệm cần nắm

1. **`PasswordEncoder` là gì và vì sao phải có:** interface với 2 method chính — `encode(rawPassword)` để hash lúc tạo user, `matches(rawPassword, encodedPassword)` để so khớp lúc login. `BCryptPasswordEncoder` dùng thuật toán bcrypt — có salt ngẫu nhiên tự động nên **cùng 1 password gốc sẽ ra hash khác nhau mỗi lần encode**, và cố tình chậm (tunable cost factor) để chống brute-force. Khác biệt lớn so với bước 2, nơi password được lưu dạng `{noop}` (plaintext, không hash) — chỉ chấp nhận cho học tập.

2. **`roles()` vs `authorities()`:** `User.builder().roles("ADMIN")` là **shortcut** — tự động thêm prefix `ROLE_` và lưu thành authority `ROLE_ADMIN`. Nếu dùng `.authorities("ADMIN")` (không qua `roles()`), authority sẽ là `ADMIN` — **không có** prefix `ROLE_`. Lỗi rất hay gặp: gọi nhầm `roles("ROLE_ADMIN")` sẽ tạo ra authority `ROLE_ROLE_ADMIN` (double prefix), khiến `hasRole("ADMIN")` không bao giờ khớp.

3. **`hasRole()` vs `hasAuthority()`** (dùng ở bước sau, trong `authorizeHttpRequests` hoặc `@PreAuthorize`):
   - `hasRole("ADMIN")` — Spring **tự động thêm** prefix `ROLE_` khi so khớp, tức là tìm authority `ROLE_ADMIN`.
   - `hasAuthority("ROLE_ADMIN")` — so khớp **chính xác** chuỗi, không tự thêm prefix gì cả.
   - Hai cách viết trên tương đương nhau **chỉ khi** user được tạo qua `roles(...)` (có prefix `ROLE_` tự động). Roles dùng cho phân quyền dạng "vai trò" (ADMIN/USER), còn authorities linh hoạt hơn, thường dùng cho quyền hạt mịn hơn (ví dụ `PRODUCT_DELETE`) không theo khuôn mẫu `ROLE_*`.

4. **Vì sao bean `UserDetailsService` không xung đột với `application.yaml`:** vì auto-config gốc có `@ConditionalOnMissingBean(UserDetailsService.class)` — một khi tự khai `@Bean UserDetailsService`, Spring Boot bỏ qua hoàn toàn `spring.security.user.*`. Có thể xoá đoạn đó khỏi `application.yaml` (không còn tác dụng) hoặc để lại làm ghi chú lịch sử — không ảnh hưởng runtime.

## 3. Cách kiểm tra

```bash
curl -i -u admin:admin123 http://localhost:8080/hello
curl -i -u user:user123 http://localhost:8080/hello
curl -i -u admin:wrongpass http://localhost:8080/hello   # → 401
```

Vì `/hello` đang `permitAll()`, cả 3 lệnh trên đều trả 200 (không cần login) — để thực sự thấy khác biệt role, cần một route protected phân biệt ADMIN/USER (sẽ làm rõ ở bước 6 khi phân quyền theo endpoint/method).

## 4. Câu hỏi tự kiểm tra

Nếu tạo user bằng `.authorities("ADMIN")` thay vì `.roles("ADMIN")`, rồi dùng `.requestMatchers("/admin").hasRole("ADMIN")` để bảo vệ route — điều gì xảy ra khi user đó gọi `/admin`?

→ Vẫn bị 403, vì `hasRole("ADMIN")` tìm authority `ROLE_ADMIN`, nhưng user chỉ có authority `ADMIN` (không prefix) — hai chuỗi này không khớp nhau.

---

*Gợi ý bước tiếp theo:* Bước 5 — chuyển user từ in-memory sang database (JPA + H2): tạo entity `User`, `UserRepository`, custom `UserDetailsService` đọc từ DB.