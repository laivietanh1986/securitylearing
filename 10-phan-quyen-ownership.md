# Bước 10 — Phân quyền chi tiết dựa trên dữ liệu (ownership)

`@PreAuthorize("hasRole('ADMIN')")` (bước 6) chỉ trả lời được câu hỏi "user này có vai trò gì?" — hoàn toàn không biết gì về **dữ liệu cụ thể** đang được thao tác. Bước 10 mở rộng sang bài toán khác hẳn: "user này có phải chủ của **đúng note** đang bị sửa/xoá không?" — câu trả lời phụ thuộc vào **nội dung một dòng trong DB**, không thể suy ra chỉ từ role.

## 1. Các thành phần đã thêm

- `entity/Note.java` — thêm field `owner` (username người tạo).
- `api/NoteController.create()` — gán `note.setOwner(authentication.getName())` **sau khi** bind request body, ghi đè bất kỳ `owner` nào client cố gửi lên.
- `config/NoteSecurity.java` — bean `@Component("noteSecurity")`, method `isOwner(Long noteId, String username)` tự query DB để trả lời "id này có phải của user này không?".
- `api/NoteController.update()` / `delete()` — dùng `@PreAuthorize` gọi vào bean trên qua SpEL.

```java
@Component("noteSecurity")
@RequiredArgsConstructor
public class NoteSecurity {
    private final NoteRepository noteRepository;

    public boolean isOwner(Long noteId, String username) {
        return noteRepository.findById(noteId)
            .map(note -> note.getOwner().equals(username))
            .orElse(false);
    }
}
```

```java
@PutMapping("/{id}")
@PreAuthorize("@noteSecurity.isOwner(#id, authentication.name)")
public Note update(@PathVariable Long id, @Valid @RequestBody Note req) {
    Note note = noteRepository.findById(id)
        .orElseThrow(() -> new NoSuchElementException("Note không tồn tại"));
    note.setTitle(req.getTitle());
    note.setContent(req.getContent());
    return noteRepository.save(note);
}

@DeleteMapping("/{id}")
@PreAuthorize("hasRole('ADMIN') or @noteSecurity.isOwner(#id, authentication.name)")
public void delete(@PathVariable Long id) {
    noteRepository.deleteById(id);
}
```

## 2. Khái niệm cần nắm

1. **Vì sao không thể viết `@PreAuthorize("#note.owner == authentication.name")` trực tiếp mà phải qua bean riêng:** `@PreAuthorize` được đánh giá **trước khi** method body chạy — tại thời điểm đó, note **chưa được load từ DB**, chỉ có sẵn: tham số method (`#id`), object `authentication`, và các bean khác trong context (gọi qua `@tenBean.method(...)`). SpEL hoàn toàn không "nhìn thấy" biến local bên trong method (như biến `note` tự query trong `update()`) vì nó chưa tồn tại ở thời điểm kiểm tra. Đây chính là lý do cần một bean riêng (`NoteSecurity`) — tự làm 1 query DB độc lập để trả lời câu hỏi ownership **trước khi** method thật được phép chạy.

2. **`authentication.name` trong SpEL lấy từ đâu:** biểu thức `@PreAuthorize` chạy trên root object là `SecurityExpressionRoot`, có sẵn property `authentication` — trỏ tới `Authentication` object hiện tại trong `SecurityContextHolder` (chính là cái `JwtAuthenticationFilter` set vào ở bước 8). `authentication.name` gọi `getName()` — với principal là `UserDetails`, giá trị trả về chính là `username`. `authentication` luôn có sẵn trong SpEL bất kể method controller có khai `Authentication` làm tham số hay không.

3. **Vì sao ownership check phải nằm ở `@PreAuthorize`, không phải `@PostAuthorize`:** `@PostAuthorize` chỉ hợp lý cho thao tác **đọc** (kiểm tra sau khi đã có `returnObject`, chấp nhận được vì không có tác dụng phụ). Với `DELETE`/`PUT` — thao tác **có tác dụng phụ** — kiểm tra "sau khi" là quá muộn: dữ liệu đã bị xoá/sửa xong rồi mới biết là không đủ quyền, không thể "hoàn tác". Bắt buộc phải chặn **trước khi** method chạy.

4. **Kết hợp role-based + ownership-based bằng `or`:** `hasRole('ADMIN') or @noteSecurity.isOwner(...)` — ADMIN được bỏ qua hoàn toàn kiểm tra ownership, user thường chỉ pass nếu đúng chủ sở hữu. Đây là ví dụ rõ nhất cho thấy authorization không còn thuần tuý dựa trên "vai trò tĩnh" nữa, mà là kết hợp role + dữ liệu động.

5. **Binding tham số `#id`:** Spring Security đọc tên tham số method qua reflection để khớp với `#id` trong SpEL. Spring Boot Maven plugin mặc định bật cờ compiler `-parameters` nên việc này tự hoạt động; nếu gặp lỗi `Name for argument of type [...] not specified`, cần gắn thêm `@P("id")` trước tham số.

## 3. Q&A mở rộng: đánh đổi hiệu năng — double query

**Timeline thực tế khi gọi `PUT /notes/1`:**

```
1. AOP proxy chặn NoteController.update() lại
2. Đánh giá @PreAuthorize → gọi noteSecurity.isOwner(1, "alice")
   → SQL #1: SELECT * FROM note WHERE id=1
3. Proxy cho phép method thật chạy
4. Bên trong update(): noteRepository.findById(1)
   → SQL #2: SELECT * FROM note WHERE id=1 (giống hệt SQL #1)
5. save() → SQL #3: UPDATE note SET ...
```

**Nhưng thực tế có thể KHÔNG phải 2 lần query SQL thật** — tuỳ `spring.jpa.open-in-view`. Hibernate có first-level cache trong phạm vi 1 Session; Spring Boot mặc định bật `open-in-view=true` (một Session dùng chung cho cả HTTP request), nên SQL #2 rất có thể chỉ là cache hit, không đụng DB. Nếu tắt OSIV (nhiều team tắt vì nó dễ che giấu N+1 query và giữ connection mở lâu), 2 lệnh `findById` chạy trong Session riêng biệt → chi phí 2 query thật sự xảy ra.

**2 cách chủ động tránh double-query, không phụ thuộc OSIV:**

*Cách 1 — bỏ `@PreAuthorize`, tự kiểm tra thủ công, tái sử dụng entity đã load:*
```java
@PutMapping("/{id}")
public Note update(@PathVariable Long id, @Valid @RequestBody Note req, Authentication authentication) {
    Note note = noteRepository.findById(id)
        .orElseThrow(() -> new NoSuchElementException("Note không tồn tại"));

    boolean isAdmin = authentication.getAuthorities().stream()
        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    if (!isAdmin && !note.getOwner().equals(authentication.getName())) {
        throw new AccessDeniedException("Bạn không phải chủ note này");
    }
    note.setTitle(req.getTitle());
    note.setContent(req.getContent());
    return noteRepository.save(note);   // chỉ 1 lần SELECT
}
```

*Cách 2 — gộp điều kiện ownership vào query, để DB tự lọc:*
```java
public interface NoteRepository extends JpaRepository<Note, Long> {
    Optional<Note> findByIdAndOwner(Long id, String owner);
}
```
Lợi ích phụ: nếu note tồn tại nhưng không phải của bạn, response giống hệt "note không tồn tại" — che giấu thông tin tốt hơn. Nhược điểm: ADMIN cần bypass filter owner nên phải rẽ nhánh logic riêng.

**Đánh đổi tổng thể:**

| | `@PreAuthorize` + bean riêng | Kiểm tra thủ công |
|---|---|---|
| Số query | 2 (hoặc 1 nếu OSIV cache hit) | Luôn đúng 1 |
| Dễ đọc / audit | Rule nằm ngay trên signature | Ẩn trong thân method |
| Rủi ro quên áp dụng | Thấp — khai báo tường minh | Cao hơn — dễ sót ở endpoint mới |
| Tái sử dụng | Cao — dùng lại ở nhiều nơi | Phải tự tách helper |

Với quy mô project học tập, giữ `@PreAuthorize` + bean riêng là hợp lý — chỉ chuyển sang cách thủ công khi đo được đây thực sự là bottleneck.

## 4. Review khi implement — 2 điểm cần biết (không chặn chạy)

**1. `PUT /notes/{id}` với id không tồn tại → trả 403, không phải 404:** vì `isOwner()` trả `false` khi note không tồn tại (`orElse(false)`), `@PreAuthorize` chặn ngay từ đầu — dòng `throw new NoSuchElementException(...)` trong `update()` gần như không bao giờ chạy tới (chỉ xảy ra khi note bị xoá đúng lúc giữa lượt check quyền và lúc method thật chạy — race condition hiếm gặp). Có mặt tốt về bảo mật (không tiết lộ note có tồn tại hay không cho người không sở hữu), nhưng dễ gây hiểu lầm khi debug.

**2. `deleteById(id)` ném exception chưa được bắt nếu id không tồn tại:** `SimpleJpaRepository.deleteById` ném `EmptyResultDataAccessException` nếu không tìm thấy entity. Trường hợp chạm tới: ADMIN gọi `DELETE /notes/{id}` với id không tồn tại (`hasRole('ADMIN')` pass ngay, không cần qua `isOwner()`). `GlobalExceptionHandler` hiện chỉ bắt `MethodArgumentNotValidException` và `BadCredentialsException` → rơi về 500 mặc định thay vì 404. Nên bổ sung:

```java
@ExceptionHandler(NoSuchElementException.class)
@ResponseStatus(HttpStatus.NOT_FOUND)
public Map<String,String> handleNotFound(NoSuchElementException ex) {
    return Map.of("error", ex.getMessage());
}
```

(Có thể đổi `delete()` dùng `findById().orElseThrow(NoSuchElementException::new)` rồi `noteRepository.delete(note)` thay vì `deleteById`, để cả 2 trường hợp cùng chung 1 loại exception.)

## 5. Cách kiểm tra

```bash
# alice tạo note
curl -X POST http://localhost:8080/notes -H "Authorization: Bearer <alice-token>" \
  -H "Content-Type: application/json" -d '{"title":"a","content":"b"}'
# → {"id": 1, "owner": "alice", ...}

# alice sửa note của chính mình → 200
curl -X PUT http://localhost:8080/notes/1 -H "Authorization: Bearer <alice-token>" \
  -H "Content-Type: application/json" -d '{"title":"a2","content":"b2"}'

# bob (user khác) cố sửa note của alice → 403
curl -i -X PUT http://localhost:8080/notes/1 -H "Authorization: Bearer <bob-token>" \
  -H "Content-Type: application/json" -d '{"title":"hack","content":"hack"}'

# admin xoá note của alice dù không phải chủ → 200 (vì hasRole('ADMIN') pass trước)
curl -i -X DELETE http://localhost:8080/notes/1 -H "Authorization: Bearer <admin-token>"
```

## 6. Câu hỏi tự kiểm tra

Nếu quên gán `note.setOwner(authentication.getName())` ở `create()`, và để client tự gửi `owner` trong request body (`@RequestBody Note note` nhận nguyên object, không lọc field) — điều gì có thể xảy ra?

→ **Lỗ hổng bảo mật nghiêm trọng:** client có thể tự khai `"owner": "admin"` trong JSON gửi lên, note sẽ được lưu với `owner = "admin"` dù người tạo thực sự là ai — vô hiệu hoá hoàn toàn cơ chế ownership check. Đây là lý do `owner` luôn phải được server tự gán từ `Authentication`, không bao giờ tin giá trị client gửi lên qua request body — nguyên tắc chung: field liên quan tới authorization/ownership không bao giờ nên là input trực tiếp từ client.

---

*Gợi ý bước tiếp theo:* Cấp 4 — Bước 11: OAuth2 Login (Google/GitHub), thêm `spring-boot-starter-oauth2-client`, tìm hiểu OAuth2 Authorization Code flow.
