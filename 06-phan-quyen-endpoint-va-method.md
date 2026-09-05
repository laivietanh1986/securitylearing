# Bước 6 — Phân quyền theo endpoint và theo method (CRUD "Note")

Dựng một API CRUD thật (`Note`), rồi phân quyền theo **2 tầng khác nhau** — tầng URL (trong `SecurityFilterChain`) và tầng method (`@PreAuthorize` trên controller/service) — để thấy rõ khác biệt và khi nào dùng cái nào.

## 1. Các thành phần đã thêm

- `entity/Note.java` — entity JPA: `id`, `title`, `content`.
- `repository/NoteRepository.java` — `JpaRepository<Note, Long>`.
- `api/NoteController.java` — CRUD cơ bản: `GET /notes`, `POST /notes`, `DELETE /notes/{id}`.
- `config/MethodSecurityConfig.java` — `@EnableMethodSecurity`, bật cơ chế đọc `@PreAuthorize`/`@PostAuthorize`.
- `DELETE /notes/{id}` được bảo vệ bằng `@PreAuthorize("hasRole('ADMIN')")` ngay trên method controller.
- Tầng URL (`SecurityConfig`) chỉ yêu cầu `/notes/**` phải đăng nhập (`authenticated()`), chưa phân biệt role — phân biệt role nằm ở tầng method.

## 2. Khái niệm cần nắm

1. **Authorization tầng URL vs tầng method — hai lớp phòng thủ khác nhau, không thay thế nhau:**
   - **Tầng URL** (`authorizeHttpRequests`) hoạt động ở filter chain, **trước khi** request chạm tới bất kỳ code Java nào của bạn (controller/service). Nó chỉ biết HTTP method + path — không biết gì về nghiệp vụ bên trong.
   - **Tầng method** (`@PreAuthorize`) hoạt động **sau khi** request đã vào tới bên trong ứng dụng, ngay trước khi method thực thi, dựa trên AOP proxy. Nó có thể kiểm tra logic phức tạp hơn nhiều (tham số method, kết quả trả về — xem `@PostAuthorize`).
   - Tầng URL chỉ đảm bảo "`/notes/**` phải login" (chặn người chưa đăng nhập từ xa nhất có thể — tối ưu hiệu năng, fail sớm). Tầng method mới thực sự phân biệt ADMIN/USER cho từng thao tác cụ thể (`DELETE` cần ADMIN).

2. **Vì sao không dùng `hasRole('ADMIN')` luôn ở tầng URL cho `DELETE /notes/**`:** hoàn toàn có thể làm được (`.requestMatchers(HttpMethod.DELETE, "/notes/**").hasRole("ADMIN")`), nhiều dự án làm vậy cho các rule đơn giản. Nhưng `@PreAuthorize` mạnh hơn khi rule phức tạp hơn URL/method thuần tuý — ví dụ bước 10 sau này ("user chỉ sửa Note do chính mình tạo") **không thể** biểu diễn được ở tầng URL, vì tầng URL không biết `id` trong path thuộc về ai — phải xuống tầng method, đọc tham số qua SpEL.

3. **`@EnableMethodSecurity` là điều kiện bắt buộc:** nếu không bật, mọi `@PreAuthorize`/`@PostAuthorize` bị **âm thầm bỏ qua** — không có lỗi biên dịch, không có exception lúc chạy, method vẫn thực thi bình thường như không có gì. Đây là lỗi rất hay gặp: tưởng đã chặn quyền nhưng thực ra chưa bật cơ chế đọc annotation.

4. **`@PreAuthorize` vs `@PostAuthorize`:**
   - `@PreAuthorize("...")` — kiểm tra **trước khi** method chạy. Dùng SpEL, có thể truy cập tham số method qua tên (`#id`), ví dụ `@PreAuthorize("#id == authentication.principal.id")`.
   - `@PostAuthorize("...")` — kiểm tra **sau khi** method đã chạy xong, dựa trên `returnObject`. Ví dụ `@PostAuthorize("returnObject.owner == authentication.name")` — cần thiết khi điều kiện phân quyền phụ thuộc vào dữ liệu chỉ có sau khi query DB (không biết trước khi gọi).
   - Cả hai đều throw `AccessDeniedException` nếu biểu thức trả `false` → Spring Security tự trả về **403 Forbidden**.

5. **Cơ chế đứng sau `@PreAuthorize` — AOP proxy:** Spring bọc bean của bạn (`NoteController`) bằng một dynamic proxy. Khi method có `@PreAuthorize` được gọi, proxy chặn lại, đánh giá biểu thức SpEL trước, chỉ cho method thật chạy nếu pass. Hệ quả quan trọng: `@PreAuthorize` **chỉ có tác dụng khi gọi qua bean được Spring quản lý** (ví dụ từ ngoài vào qua HTTP) — nếu tự gọi `this.delete(id)` từ bên trong cùng class, nó **bỏ qua proxy**, tức bỏ qua luôn kiểm tra quyền (self-invocation problem, kinh điển trong Spring AOP).

## 3. Cách kiểm tra

```bash
curl -i -u user:user123 -X GET http://localhost:8080/notes        # → 200
curl -i -u user:user123 -X POST http://localhost:8080/notes -d '{"title":"a","content":"b"}' -H "Content-Type: application/json"  # → 200
curl -i -u user:user123 -X DELETE http://localhost:8080/notes/1   # → 403 (USER không có quyền)
curl -i -u admin:admin123 -X DELETE http://localhost:8080/notes/1 # → 200
```

> Lưu ý: `@DeleteMapping` cần đúng path variable dạng `"/{id}"` (không phải `"/id"`) để `@PathVariable Long id` bind đúng — nếu thiếu ngoặc nhọn, app sẽ lỗi ngay lúc khởi động (`IllegalStateException: missing URI template variable`).

## 4. Câu hỏi tự kiểm tra

Nếu quên annotation `@EnableMethodSecurity` nhưng vẫn có `@PreAuthorize("hasRole('ADMIN')")` trên method `delete`, user thường (`USER`) gọi `DELETE /notes/1` sẽ nhận response gì?

→ **200 OK**, note bị xoá bình thường — vì `@PreAuthorize` bị bỏ qua hoàn toàn khi thiếu `@EnableMethodSecurity`, không có bất kỳ cảnh báo nào lúc build/chạy. Đây là lý do luôn phải test thủ công bằng cURL/Postman với user thường, không chỉ tin vào việc "đã viết annotation".

---

*Gợi ý bước tiếp theo:* Bước 7 — Validation kết hợp Security: dùng `spring-boot-starter-validation` (`@Valid`, `@NotBlank`), xử lý lỗi qua `@ControllerAdvice`, phân biệt lỗi 400 (validation) với 401/403 (authentication/authorization).
