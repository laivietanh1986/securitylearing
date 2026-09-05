# Bước 7 — Validation kết hợp Security

Phân biệt rạch ròi 3 loại lỗi khác nhau xảy ra ở 3 tầng khác nhau của cùng một request — lỗi dữ liệu đầu vào (400), lỗi chưa đăng nhập (401), lỗi đã đăng nhập nhưng không đủ quyền (403) — và trả về response nhất quán cho cả 3, dù cơ chế xử lý bên dưới hoàn toàn khác nhau.

## 1. Cách làm

**Thêm validation constraint vào entity/DTO:**

```java
@Entity
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Note {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "title không được để trống")
    private String title;

    @NotBlank(message = "content không được để trống")
    private String content;
}
```

**Bật validation ở controller bằng `@Valid`:**

```java
@PostMapping
public Note create(@Valid @RequestBody Note note) {
    return noteRepository.save(note);
}
```

**Bắt lỗi validation qua `@RestControllerAdvice`:**

```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors()
            .forEach(err -> errors.put(err.getField(), err.getDefaultMessage()));
        return errors;
    }
}
```

**Tuỳ biến response cho 401/403 — khai báo trong `SecurityConfig`:**

```java
.exceptionHandling(ex -> ex
    .authenticationEntryPoint((request, response, authEx) -> {
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
```

## 2. Khái niệm cần nắm

1. **3 loại lỗi nằm ở 3 tầng hoàn toàn khác nhau trong pipeline của một request:**
   - **`AuthenticationException` (401)** — ném ra ở tầng filter chain, **trước** khi request chạm tới `DispatcherServlet`. Với Basic Auth, `BasicAuthenticationFilter` kiểm tra header `Authorization` — nếu thiếu/sai, exception này bay thẳng ra ngoài, **không bao giờ tới được** `@ControllerAdvice`, vì controller chưa hề được gọi.
   - **`AccessDeniedException` (403)** — ném ra ở tầng AOP proxy khi `@PreAuthorize` đánh giá `false`, xảy ra **trong lúc** `DispatcherServlet` đang gọi controller method (proxy chặn trước khi method thật chạy). Vì nằm "sâu" hơn 401, nó **có thể** bị `@ExceptionHandler` trong `@ControllerAdvice` bắt được nếu khai báo handler cho nó.
   - **`MethodArgumentNotValidException` (400)** — ném ra khi `@Valid` fail, xảy ra ngay trong `DispatcherServlet` lúc resolve argument cho controller method, trước khi body method chạy. Luôn nằm trong tầm bắt của `@ControllerAdvice`.

2. **`ExceptionTranslationFilter` — "người phiên dịch" đứng giữa filter chain và MVC:** đây là filter của Spring Security, bọc quanh toàn bộ phần còn lại của chain (bao gồm cả `DispatcherServlet`). Nó bắt `AuthenticationException`/`AccessDeniedException` **bay ra khỏi** toàn bộ quá trình xử lý MVC (tức là không bị `@ControllerAdvice` xử lý trước), rồi quyết định gọi `AuthenticationEntryPoint` (cho 401) hay `AccessDeniedHandler` (cho 403). Đây chính xác là lý do tuỳ biến 401/403 ở `SecurityConfig` chứ không phải ở `@ControllerAdvice` — vì filter này đứng **ngoài** phạm vi mà `@ControllerAdvice` với tới.

3. **Bẫy hay gặp — `@ControllerAdvice` "cướp" mất `AccessDeniedException`:** nếu lỡ khai báo `@ExceptionHandler(AccessDeniedException.class)` trong `@ControllerAdvice`, Spring MVC's exception resolver sẽ xử lý nó **trước khi** nó kịp bay ra tới `ExceptionTranslationFilter` — khi đó `accessDeniedHandler()` cấu hình ở `SecurityConfig` sẽ **không bao giờ được gọi** cho lỗi 403 phát sinh từ `@PreAuthorize`. Quy tắc an toàn: chỉ dùng **một** cơ chế cho mỗi loại lỗi — validation (400) và lỗi nghiệp vụ đi qua `@ControllerAdvice`; authentication/authorization (401/403) đi qua `AuthenticationEntryPoint`/`AccessDeniedHandler`, không khai trùng cả hai.

4. **Vì sao không thể "gộp chung" 401 vào `@ControllerAdvice` như 400/403:** vì bản chất 401 xảy ra **trước khi có Authentication object** trong `SecurityContext` — request còn chưa được coi là hợp lệ để vào tới tầng ứng dụng. `@ControllerAdvice` sống trong thế giới của `DispatcherServlet`/Spring MVC, còn `AuthenticationEntryPoint` sống ở tầng servlet filter, thấp hơn và sớm hơn — đây là ranh giới kiến trúc cứng, không phải giới hạn kỹ thuật có thể lách qua.

## 3. Cách kiểm tra

```bash
# 400 — validation fail (thiếu title)
curl -i -u user:user123 -X POST http://localhost:8080/notes \
  -H "Content-Type: application/json" -d '{"content":"b"}'

# 401 — không gửi -u, chưa đăng nhập
curl -i -X GET http://localhost:8080/notes

# 403 — user thường cố xoá
curl -i -u user:user123 -X DELETE http://localhost:8080/notes/1
```

Mỗi lệnh phải trả đúng status code tương ứng, và body JSON phải theo đúng format định nghĩa ở từng handler (khác nhau giữa 400 vs 401/403 là chấp nhận được, miễn nội bộ mỗi loại nhất quán).

## 4. Câu hỏi tự kiểm tra

Nếu khai `@ExceptionHandler(AccessDeniedException.class)` trong `@ControllerAdvice` **và** vẫn cấu hình `accessDeniedHandler()` riêng trong `SecurityConfig`, cái nào sẽ thắng khi `@PreAuthorize` fail?

→ `@ControllerAdvice` thắng — vì `AccessDeniedException` bị bắt ngay trong `DispatcherServlet` (tầng gần controller hơn), không bao giờ kịp bay ra tới `ExceptionTranslationFilter` để `accessDeniedHandler()` có cơ hội chạy.

---

*Gợi ý bước tiếp theo:* Bước 8 — Đăng ký + đăng nhập trả về JWT, chuyển sang stateless auth (`SessionCreationPolicy.STATELESS`), viết `JwtAuthenticationFilter`.
