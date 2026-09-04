# Bước 1 — Hello Security mặc định

Ở trạng thái hiện tại, project chỉ có `spring-boot-starter-security` trong classpath, chưa có class `SecurityConfig` nào, và cũng chưa có `application.properties`. Đây chính xác là trạng thái "mặc định" mà bước 1 muốn quan sát. Dưới đây là những gì xảy ra và lý do.

## 1. Autoconfiguration được kích hoạt vì có Security trong classpath

`SecurityAutoConfiguration` của Spring Boot phát hiện có `spring-security-web` + `spring-security-config`, và vì không tìm thấy bean `UserDetailsService` hay bean `SecurityFilterChain` nào do bạn tự định nghĩa, nó sẽ tự động cấu hình các giá trị mặc định thông qua `UserDetailsServiceAutoConfiguration` và `SpringBootWebSecurityConfiguration`.

## 2. `UserDetailsService` mặc định → một user trong bộ nhớ

Spring Boot tạo một `InMemoryUserDetailsManager` với đúng một user:

- username: `user`
- password: một UUID ngẫu nhiên, được sinh một lần khi khởi động và in ra console, ví dụ:

  ```
  Using generated security password: 8e557245-73e2-4286-969a-ff57fe326336
  ```

  Đây là cơ chế tiện lợi để một app mới tinh không bao giờ vô tình bị mở toang — bạn bị "ép" phải nhận ra rằng security đang hoạt động. Nếu restart app, bạn sẽ nhận được một password ngẫu nhiên **mới** (không có gì được lưu lại).

## 3. Filter chain mặc định → mọi request đều cần đăng nhập

`SpringBootWebSecurityConfiguration` đăng ký một `SecurityFilterChain` mặc định, tương đương với việc cấu hình `authorizeHttpRequests(a -> a.anyRequest().authenticated())` cộng với `formLogin()` và `httpBasic()` được bật sẵn.

Đó là lý do vì sao `/hello` — dù `WelcomeController` không hề nhắc gì đến security — vẫn bị chặn lại: filter chain nằm chắn phía trước **mọi** request ở tầng servlet, trước khi request đó kịp đến được controller của bạn.

- Nếu gọi `/hello` bằng trình duyệt, bạn sẽ bị redirect đến trang login mặc định (`/login`).
- Nếu gọi bằng curl, bạn sẽ nhận `401 Unauthorized` kèm header `WWW-Authenticate` (thách thức Basic Auth), vì curl không tự động follow redirect theo kiểu session như trình duyệt.

## 4. Vì sao "mọi request đều bị chặn" lại là mặc định có chủ đích

Triết lý của Spring Security là secure-by-default: chỉ cần thêm dependency thôi cũng không bao giờ được để lộ endpoint ra ngoài một cách vô tình. Bạn phải chủ động "mở" (opt out) từng phần thay vì phải chủ động "khoá" (opt in) từng phần — đây chính xác là điều bước 3 trong roadmap (tạo bean `SecurityFilterChain`, dùng `authorizeHttpRequests`) sẽ hướng dẫn bạn làm một cách tường minh.

---

*Gợi ý bước tiếp theo:* chạy thử app để xem password ngẫu nhiên xuất hiện trong log, rồi thử gọi `/hello` cả có lẫn không có thông tin đăng nhập.
