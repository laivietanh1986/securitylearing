# Bước 2 — Cấu hình user trong `application.yaml`

Ở bước 1, Spring Boot tự sinh ra một user tên `user` với password ngẫu nhiên, in ra log mỗi lần khởi động — bất tiện vì password đổi liên tục. Bước 2 cố định lại username/password bằng cấu hình, không cần viết code Java nào cả.

## 1. Cấu hình đã thêm

Trong [application.yaml](src/main/resources/application.yaml):

```yaml
spring:
  security:
    user:
      name: admin
      password: admin123
```

(Tương đương `spring.security.user.name` / `spring.security.user.password` ở dạng `application.properties` mà roadmap nhắc tới.)

## 2. Cơ chế đứng sau nó — `UserDetailsServiceAutoConfiguration`

1. Khi có `spring-boot-starter-security` trên classpath **và** không có bean `UserDetailsService`/`AuthenticationManager` nào do bạn tự khai báo, Spring Boot kích hoạt `UserDetailsServiceAutoConfiguration`.
2. Auto-config này đọc các thuộc tính `spring.security.user.*` (bind vào class `SecurityProperties.User`) — gồm `name`, `password`, `roles`.
3. Nó tạo ra một bean `InMemoryUserDetailsManager` chứa đúng 1 user với thông tin đó. `InMemoryUserDetailsManager` implement interface `UserDetailsService` — nhiệm vụ duy nhất của interface này là: nhận vào username, trả về `UserDetails` (chứa password đã mã hoá + authorities) để `AuthenticationManager` so khớp lúc login.
4. Nếu **không** đặt `password`, Spring Boot tự sinh password ngẫu nhiên và in log — đó chính là hành vi mặc định ở bước 1. Đặt `password` cố định là cách tắt hành vi sinh ngẫu nhiên đó.
5. Password gõ ở dạng plaintext trong file cấu hình, nhưng lúc runtime Spring Boot tự bọc nó bằng prefix `{noop}` nếu không tự mã hoá — nghĩa là dùng `NoOpPasswordEncoder` (không hash). Chỉ chấp nhận được cho môi trường học/dev, không dùng cho production.

## 3. Lưu ý về cấu hình hiện tại

- Không có `roles`, nên user `admin` chỉ nhận role mặc định `ROLE_USER` (Spring Boot không tự suy role `ADMIN` từ tên user). Cần biết trước để không bất ngờ khi sau này thử `hasRole("ADMIN")` mà bị 403.
- Password plaintext trong file cấu hình chỉ chấp nhận được ở dev/local, không nên commit password thật lên repo public.

## 4. Câu hỏi tự kiểm tra

Nếu khai báo thêm một `@Bean UserDetailsService` của riêng mình (dù rỗng), điều gì xảy ra với cấu hình `spring.security.user.*`?

→ Auto-config này sẽ **tắt hẳn** (có điều kiện `@ConditionalOnMissingBean`), tức là các thuộc tính username/password trong yaml sẽ bị bỏ qua hoàn toàn — đây chính là nền cho bước 5 (user từ database) sau này.

---

*Gợi ý bước tiếp theo:* chạy app, gọi `GET /hello` — vẫn bị chặn (401/redirect login) vì bước 3 (`SecurityFilterChain` phân biệt public/protected) chưa làm. Login bằng `admin`/`admin123` qua form login mặc định để xác nhận cấu hình có tác dụng.
