# Bước 8 — Đăng ký + đăng nhập trả về JWT (stateless auth)

Từ bước 1–7, mọi request tự chứng minh danh tính qua header `Authorization: Basic ...` (Basic Auth), Spring Security tự re-authenticate **lại từ đầu** ở mỗi request (đọc username/password, gọi lại `UserDetailsService` + `PasswordEncoder`). Bước 8 đổi hẳn cơ chế: client login **một lần** để lấy token, sau đó mọi request mang theo token đó — server không lưu session, không nhớ ai vừa login, chỉ **verify chữ ký** của token là đủ để biết ai đang gọi.

## 1. Các thành phần đã thêm

- `pom.xml` — 3 dependency `jjwt-api` / `jjwt-impl` / `jjwt-jackson` (0.12.5).
- `service/JwtService.java` — ký (`generateToken`) và verify (`extractUsername`, `isTokenValid`) token bằng HMAC-SHA256, secret lấy từ `application.yaml` qua `@Value("${jwt.secret}")`.
- `config/JwtAuthenticationFilter.java` (`extends OncePerRequestFilter`) — đọc header `Authorization: Bearer ...`, verify token, set `Authentication` vào `SecurityContextHolder` nếu hợp lệ.
- `model/RegisterRequest.java`, `model/LoginRequest.java` — DTO cho request body.
- `api/AuthController.java` — `POST /auth/register` (tạo user mới), `POST /auth/login` (xác thực qua `AuthenticationManager`, trả JWT).
- `SecurityConfig` — thêm `csrf().disable()`, `sessionCreationPolicy(STATELESS)`, `/auth/**` permitAll, đăng ký `JwtAuthenticationFilter` bằng `addFilterBefore(..., UsernamePasswordAuthenticationFilter.class)`, thêm bean `AuthenticationManager`.
- `GlobalExceptionHandler` — thêm handler cho `BadCredentialsException` (401), tách riêng khỏi handler validation (400).

## 2. Khái niệm cần nắm

1. **Stateless auth nghĩa là gì cụ thể:** server không lưu bất kỳ thông tin phiên nào giữa các request (`SessionCreationPolicy.STATELESS` — Spring Security sẽ **không bao giờ** tạo `HttpSession`, kể cả khi code cố gắng). Mọi thông tin cần để xác thực (username, roles, thời hạn) đều nằm **trong chính token**, được client gửi lại ở mỗi request. Hệ quả: có thể scale ngang nhiều instance server mà không cần sticky session hay session replication — bất kỳ instance nào cũng verify được token miễn có cùng secret key.

2. **`OncePerRequestFilter` là gì và vì sao dùng nó thay vì `Filter` thường:** một request HTTP có thể đi qua filter chain **nhiều lần trong cùng 1 request** nếu có forward/include nội bộ trong servlet container (ví dụ khi có error page forward, hay `RequestDispatcher.forward()`). `OncePerRequestFilter` đảm bảo `doFilterInternal()` chỉ chạy **đúng 1 lần** mỗi request gốc, tránh việc parse/verify token lặp lại nhiều lần lãng phí hoặc gây side-effect (như set `Authentication` nhiều lần).

3. **Vị trí filter trong chain quyết định mọi thứ — `addFilterBefore`:** `JwtAuthenticationFilter` phải chạy **trước** `UsernamePasswordAuthenticationFilter` (filter xử lý form login mặc định), vì `authorizeHttpRequests` (nằm sâu hơn trong chain) cần đọc `SecurityContextHolder.getContext().getAuthentication()` đã được set **trước khi** nó kiểm tra quyền.

4. **Luôn gọi `filterChain.doFilter(...)` vô điều kiện — kể cả khi không có token:** nếu `return` sớm mà quên gọi `filterChain.doFilter()` khi thiếu header `Authorization`, request sẽ bị "treo" (không bao giờ tới được `DispatcherServlet`). Không có token không có nghĩa là filter phải chặn — nó chỉ đơn giản là **không set `Authentication`**, để tầng `authorizeHttpRequests` phía sau tự quyết định route đó có cần login hay không (đây cũng chính là lý do `/auth/login` phải `permitAll()` — request gọi login sẽ không có token, nhưng vẫn phải được filter chain "cho qua" để chạm tới controller).

5. **Ký/verify token — HMAC đối xứng:** `signWith(secretKey)` dùng thuật toán HS256, secret key là **một chuỗi bí mật duy nhất** dùng để cả ký lẫn verify (symmetric). Ai có secret key này đều ký được token giả mạo hợp lệ — vì vậy secret phải đủ dài (≥256 bit), lưu trong config (không commit lên git ở dự án thật), và **không bao giờ** để lộ ra client. Đối lập là RS256 (asymmetric, dùng cặp private/public key) — sẽ gặp ở bước 12 khi làm Resource Server verify token phát hành từ Authorization Server khác.

6. **`AuthenticationManager.authenticate(...)` ở `/auth/login` tái sử dụng toàn bộ hạ tầng cũ:** không cần viết logic so khớp password thủ công — `authenticate()` tự động delegate tới `DaoAuthenticationProvider`, dùng lại đúng `CustomUserDetailService` (bước 5) + `PasswordEncoder` (bước 4). Nó **không trả về boolean** — đúng thì trả `Authentication`, sai thì **ném exception** (`BadCredentialsException`), code phía sau (`generateToken`) sẽ không chạy tới. `DaoAuthenticationProvider` mặc định bắt cả `UsernameNotFoundException` và ném lại thành `BadCredentialsException`, để response giống hệt nhau dù "sai password" hay "user không tồn tại" — chống username enumeration attack.

7. **Vì sao tắt CSRF (`csrf.disable()`):** CSRF protection tồn tại để chống browser tự động gửi kèm session cookie trong request giả mạo từ site khác. Với JWT, không có cookie nào được tự động đính kèm — client phải **chủ động** gắn header `Authorization: Bearer ...`. CSRF không còn ý nghĩa bảo vệ ở đây (đào sâu hơn ở bước 13, cùng CORS).

## 3. Các bug thực tế đã gặp khi implement

**Bug 1 — sai cú pháp placeholder trong `JwtService`:**
```java
@Value("$(jwt.secret)")   // ❌ ngoặc tròn
```
Phải là `@Value("${jwt.secret}")` (ngoặc nhọn). Với cú pháp sai, Spring coi đây là literal string, không resolve property — `Decoders.BASE64.decode("$(jwt.secret)")` ném `IllegalArgumentException: Illegal base64 character` ngay lần đầu gọi login.

**Bug 2 — property path sai trong `application.yaml` (phát sinh khi sửa bug 1):**
```yaml
spring:
  application:
    name: securitylearing
  jwt:                     # ❌ lồng trong "spring:" → property thực tế là spring.jwt.secret
    secret: ...
```
Phải đưa `jwt:` ra ngoài, ngang hàng với `spring:`:
```yaml
spring:
  application:
    name: securitylearing

jwt:
  secret: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

**Bug 3 — thiếu `return` sau `filterChain.doFilter()` trong nhánh không có token:**
```java
if (authHeader == null || !authHeader.startsWith("Bearer ")) {
    filterChain.doFilter(request, response);
    // ❌ thiếu return — code chạy tiếp xuống authHeader.substring(7) → NullPointerException
}
String token = authHeader.substring(7);
```
Sửa bằng cách thêm `return;` ngay sau dòng `filterChain.doFilter(...)` trong nhánh if.

**Bug 4 — `/auth/**` không được `permitAll()`, tạo vòng lặp con-gà-quả-trứng:**
```java
auth.requestMatchers("/hello").permitAll()
    .requestMatchers("/note/**").authenticated()  // cũng sai path, đúng phải là "/notes/**"
    .anyRequest().authenticated()                 // /auth/login rơi vào đây → phải login mới gọi được login
```
Sửa: thêm `.requestMatchers("/auth/**").permitAll()`, và sửa path `/note/**` → `/notes/**` cho khớp `@RequestMapping("/notes")`.

**Bug 5 — thiếu `sessionCreationPolicy(STATELESS)` và `csrf().disable()`:** thiếu STATELESS khiến Spring vẫn tự tạo `HttpSession` song song với JWT (không đúng tinh thần stateless). Thiếu tắt CSRF nghiêm trọng hơn: mặc định Spring Security bật CSRF cho mọi POST/PUT/DELETE, kể cả stateless — `/auth/register`/`/auth/login` (POST) có thể bị chặn 403 CSRF trước khi tới controller, độc lập với `authorizeHttpRequests`.

**Bug 6 — `GlobalExceptionHandler` gộp 2 exception khác nhánh kế thừa vào 1 method:**
```java
@ExceptionHandler({MethodArgumentNotValidException.class, BadCredentialsException.class})
public Map<String,String> handleValidation(MethodArgumentNotValidException exception){
    ...exception.getBindingResult()...   // BadCredentialsException không có method này
}
```
Khi `BadCredentialsException` xảy ra, kiểu tham số khai báo không khớp kiểu exception thực tế → lỗi runtime khi resolve handler. Sửa bằng cách tách 2 method riêng, và đổi status của `BadCredentialsException` thành 401 (không phải 400 — đây là lỗi authentication, không phải validation).

## 4. Cách kiểm tra

```bash
curl -i -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" -d '{"username":"alice","password":"alice123"}'

curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" -d '{"username":"alice","password":"alice123"}'
# → {"token": "eyJhbGciOi..."}

curl -i http://localhost:8080/notes -H "Authorization: Bearer eyJhbGciOi..."   # → 200
curl -i http://localhost:8080/notes                                            # → 401, không có token
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" -d '{"username":"alice","password":"wrongpass"}'  # → 401
```

## 5. Câu hỏi tự kiểm tra

Nếu quên đặt `.sessionCreationPolicy(SessionCreationPolicy.STATELESS)`, hệ thống JWT có còn hoạt động đúng không?

→ Về cơ bản vẫn chạy được (`JwtAuthenticationFilter` vẫn set `Authentication` mỗi request từ token), nhưng Spring Security sẽ tự tạo `HttpSession` để lưu `SecurityContext` sau khi authenticate — nghĩa là có cả 2 cơ chế chạy song song (session + token) một cách lãng phí, không còn "stateless" đúng nghĩa.

---

*Gợi ý bước tiếp theo:* Bước 9 — Refresh token: thêm access token (thời gian sống ngắn) + refresh token (dài hơn), endpoint `/auth/refresh`, lưu refresh token trong DB để có thể revoke/blacklist.
