# Context handoff — Spring Security learning project

File này tóm tắt trạng thái hiện tại của project để tiếp tục ở session mới (Claude không còn nhớ lịch sử hội thoại trước, chỉ đọc được file này + code + các file `0X-*.md`).

## ⚠️ Có 2 branch khác nhau — đọc kỹ trước khi làm gì

- **`spring_security`** — branch cũ, đã hoàn thành tuần tự bước 1→11 (Basic Auth → DB user → CRUD/roles → validation → **JWT tự viết** (bước 8) → refresh token (bước 9) → ownership (bước 10) → OAuth2 Login GitHub (bước 11)). Có đủ code + file `01-*.md` đến `11-*.md`.
- **`Keycloak`** — branch hiện tại (`git branch --show-current`), **đã checkout về trạng thái trước bước 8** (HEAD = commit `2c18b53`, chỉ có code bước 1–7: Basic Auth, in-memory roles, DB user, CRUD+roles, validation — KHÔNG có JWT/refresh/ownership/OAuth2 của bước 8-11). Lý do: chuẩn bị làm **bước 12 — Keycloak Resource Server**, và đã quyết định **thay thế hoàn toàn** JWT tự viết bằng JWT do Keycloak phát hành thay vì giữ song song (xem mục "Bước tiếp theo" bên dưới) — nên checkout về mốc sạch trước khi có JWT tự viết, tránh code thừa/gây rối.

**Khi bắt đầu session mới, luôn chạy `git branch --show-current` và `git log --oneline -3` trước để biết đang ở branch nào** — đừng giả định dựa vào file `0X-*.md` có trong thư mục hay không (file `.md` export theo bước có thể tồn tại trên 1 branch nhưng code tương ứng lại nằm ở branch kia sau khi checkout).

## Bối cảnh & cách làm việc đã thiết lập

- Đây là project học Spring Security theo [LEARNING-ROADMAP.md](LEARNING-ROADMAP.md) (16 bước, cấp 1 → cấp 5), làm tuần tự trên cùng 1 project, commit sau mỗi bước.
- **Quy trình đã lặp lại xuyên suốt cho mỗi bước:**
  1. User chọn 1 mục trong `LEARNING-ROADMAP.md`, yêu cầu "tiếp tục phần N".
  2. Assistant (Claude) **chỉ giải thích khái niệm + đưa code mẫu**, KHÔNG tự sửa code — user tự gõ code theo hướng dẫn (đây là lựa chọn tường minh của user ngay từ bước 2: "Chỉ giải thích khái niệm", không phải "tự làm hộ").
  3. User tự viết code xong, gõ "review" → Claude đọc code thật (qua `git status`/`Read`), chỉ ra bug cụ thể kèm dòng code, không chỉ nói chung chung.
  4. Thường có vài vòng review qua lại cho tới khi hết bug.
  5. User gõ "export" / "export ra file md" → Claude tạo file `0X-ten-buoc.md` ở thư mục gốc, gộp: giải thích khái niệm + code mẫu + bug thực tế đã gặp/sửa + câu hỏi tự kiểm tra + cách test bằng curl.
  6. Naming convention file export: `0<số bước>-<slug-tieng-viet-khong-dau>.md`, ví dụ `08-dang-ky-dang-nhap-jwt.md`.
- User code chủ yếu bằng tiếng Việt trong biến/comment đôi khi không dấu, indent 2-space (khác 4-space ở `WelcomeController.java` gốc — không cần sửa, chỉ là style cũ).
- User hay hỏi sâu thêm về khái niệm sau khi đọc giải thích (ví dụ: "sao hàm login không thấy kiểm tra gì", "refresh token để dài có sợ DoS không") — nên trả lời kỹ, có ví dụ cụ thể, rồi hỏi có cần export/update file không.
- Khi có Q&A mở rộng sau khi đã export file bước đó, cần **update lại file `0X-*.md`** (thêm mục mới), không tạo file riêng.
- Khi 1 bước có quyết định kiến trúc quan trọng ảnh hưởng code cũ (ví dụ: bước 12 thay thế hẳn JWT tự viết thay vì chạy song song), **hỏi user chọn hướng trước khi giải thích chi tiết**, đừng tự quyết.

## Tiến độ trên branch `Keycloak` (branch hiện tại)

| Bước | Chủ đề | File giải thích |
|---|---|---|
| 1 | Hello Security mặc định | [01-hello-security-mac-dinh.md](01-hello-security-mac-dinh.md) |
| 2 | User cố định trong `application.yaml` | [02-cau-hinh-user-co-dinh.md](02-cau-hinh-user-co-dinh.md) |
| 3 | Basic Auth + `SecurityFilterChain` | [03-basic-auth-cho-rest-api.md](03-basic-auth-cho-rest-api.md) |
| 4 | In-memory nhiều user + roles + BCrypt | [04-in-memory-nhieu-user-voi-roles.md](04-in-memory-nhieu-user-voi-roles.md) |
| 5 | User trong DB (JPA + H2), `CustomUserDetailService` | [05-user-trong-database.md](05-user-trong-database.md) |
| 6 | CRUD Note, `@EnableMethodSecurity` + `@PreAuthorize` role-based | [06-phan-quyen-endpoint-va-method.md](06-phan-quyen-endpoint-va-method.md) |
| 7 | Validation (`@Valid`) + `@ControllerAdvice` + `AuthenticationEntryPoint`/`AccessDeniedHandler` | [07-validation-ket-hop-security.md](07-validation-ket-hop-security.md) |

Bước 8-11 (JWT, refresh token, ownership, OAuth2 GitHub) **không có trên branch này** — xem branch `spring_security` nếu cần tham khảo lại code/giải thích các bước đó.

| 12 | OAuth2 Resource Server với Keycloak — validate JWT do Keycloak phát hành, thay thế hoàn toàn Basic Auth/`CustomUserDetailService` | [12-oauth2-resource-server-keycloak.md](12-oauth2-resource-server-keycloak.md) |

### Trạng thái bước 12: đã code xong, CHƯA test với Keycloak thật, CHƯA commit

**Khác quy trình mọi bước trước (ngoại lệ đáng chú ý):** ở bước này **user yêu cầu Claude code trực tiếp** (gõ "bạn hãy code hộ tôi") thay vì tự gõ code — lý do là cần tập trung công sức vào phần dựng hạ tầng Keycloak (Docker, admin console) hơn là gõ lại code Spring. Claude đã sửa `pom.xml`, `application.yaml`, `SecurityConfig.java` và build thành công (`mvn clean compile` → BUILD SUCCESS), nhưng **chưa chạy thử với Keycloak thật** vì việc dựng Docker + tạo realm/client/role/user qua admin console web là thao tác trên máy user, Claude không tự làm được. Đây là ngoại lệ một lần cho bước 12 do có nhiều setup hạ tầng — **không mặc định áp dụng cho các bước sau**, quay lại quy trình "chỉ giải thích, user tự code" trừ khi user yêu cầu lại.

**Việc còn lại (user tự làm, không phải code):**
1. Chạy Keycloak qua Docker (`quay.io/keycloak/keycloak:24.0 start-dev`, cổng 8081).
2. Tạo realm `myrealm`, client `securitylearing-api` (bật Direct access grants), realm roles `ADMIN`/`USER`, 1 user test.
3. Lấy token bằng curl (`POST /realms/myrealm/protocol/openid-connect/token`, grant_type=password), gọi thử `/notes` và `DELETE /notes/{id}` (cần role ADMIN) để xác nhận role mapping hoạt động đúng.
4. Báo lại kết quả — nếu có lỗi, gõ "review" như quy trình cũ.

**Gap/dead code đã ghi nhận (chi tiết ở [12-oauth2-resource-server-keycloak.md](12-oauth2-resource-server-keycloak.md) mục 5):**
- `CustomUserDetailService`, entity `User`, `UserRepository`, `SeedUser` giờ không còn được dùng để xác thực (Keycloak đã thay thế hoàn toàn) — vẫn còn trong code, biên dịch được, nhưng là dead code. Chưa xoá vì đó là quyết định dọn dẹp riêng, chưa được user yêu cầu.
- Nếu sau này làm lại ownership-based authorization (như bước 10 ở nhánh `spring_security`), nhớ dùng claim `preferred_username` từ `Jwt` principal để lấy username thật, KHÔNG dùng `authentication.getName()` (trả về `sub` — UUID nội bộ Keycloak).

## Trạng thái codebase hiện tại (branch `Keycloak`)

HEAD = commit `2c18b53` ("Implement user authentication and authorization with JPA and H2 database; add CRUD API for notes with role-based access control"). Working tree sạch, chỉ có `CONTEXT-HANDOFF.md` untracked.

```
api/
  WelcomeController.java     — GET /hello (permitAll)
  NoteController.java        — CRUD /notes, role-based @PreAuthorize
config/
  SecurityConfig.java        — SecurityFilterChain: Basic Auth, csrf disabled, exceptionHandling
  MethodSecurityConfig.java  — @EnableMethodSecurity
  CustomUserDetailService.java — UserDetailsService đọc từ DB
entity/
  User.java                  — username, password (bcrypt), roles (String, không prefix ROLE_)
  Note.java                  — title, content, owner (username)
repository/
  UserRepository, NoteRepository — JpaRepository
exception/
  GlobalExceptionHandler.java — @RestControllerAdvice: MethodArgumentNotValidException→400
Runner/
  SeedUser.java               — @Configuration, CommandLineRunner seed admin/user vào H2 lúc start
```

Chưa có: `AuthController`, `JwtService`, `JwtAuthenticationFilter`, `RefreshToken`, `NoteSecurity`, `CustomOAuth2UserService`, `OAuth2LoginSuccessHandler`, model `LoginRequest`/`RegisterRequest` — tất cả thuộc bước 8-11, chỉ có trên branch `spring_security`.

`pom.xml`: Spring Boot 3.2.1, Java 17. Dependencies: web, data-jpa, validation, security, h2 (runtime), springdoc-openapi 2.3.0, lombok. **Chưa có** `jjwt-*` hay `spring-boot-starter-oauth2-*` (sẽ thêm `oauth2-resource-server` khi làm bước 12).

## Cách bắt đầu session mới

1. Chạy `git branch --show-current` + `git log --oneline -3` để xác nhận đang ở branch nào — đọc đúng phần tương ứng ở file này.
2. Nếu đang ở branch `Keycloak` và user muốn tiếp tục: đó là bước 12, nội dung đã giải thích đầy đủ ở trên, chỉ cần review code khi user viết xong.
3. Đọc code thật (`Read`/`git status`) trước khi review hoặc trả lời câu hỏi về hành vi hiện tại — đừng suy đoán từ các file `0X-*.md` vì code có thể đã thay đổi hoặc thuộc branch khác kể từ lúc export.
