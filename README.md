# Security Learning

Project học Spring Security từ cơ bản đến nâng cao, đi tuần tự theo [LEARNING-ROADMAP.md](LEARNING-ROADMAP.md) (16 bước, cấp 1 → cấp 5), commit sau mỗi bước để dễ so sánh trước/sau.

## Trạng thái branch `master` (branch này)

Đây là điểm khởi đầu của project — mới có:
- `GET /hello` ([WelcomeController.java](src/main/java/com/example/securitylearing/api/WelcomeController.java)) không có bảo vệ gì đặc biệt.
- `spring-boot-starter-security` đã thêm vào `pom.xml` nhưng **chưa cấu hình gì** — chạy app sẽ thấy Spring Boot tự sinh 1 user `user` kèm password ngẫu nhiên trong log (đúng bước 1 của roadmap).
- File giải thích bước 1: [01-hello-security-mac-dinh.md](01-hello-security-mac-dinh.md).

> Các bước tiếp theo (2 → 16) được làm trên các branch riêng, **không nằm trên `master`**:
> - `spring_security` — làm tuần tự bước 1 → 11 (Basic Auth → DB user → CRUD/roles → validation → JWT tự viết → refresh token → ownership → OAuth2 Login GitHub).
> - `Keycloak` — checkout lại từ mốc bước 7, làm tiếp bước 12 → 14 (OAuth2 Resource Server với Keycloak, CORS/CSRF, rate limiting + audit log), thay JWT tự viết bằng JWT do Keycloak phát hành.
>
> Xem đúng branch tương ứng nếu cần tham khảo code/giải thích các bước đó.

## Công nghệ

- Java 17, Spring Boot 3.2.1
- `spring-boot-starter-web`, `spring-boot-starter-data-jpa`, `spring-boot-starter-validation`, `spring-boot-starter-security`
- H2 (runtime), `springdoc-openapi-starter-webmvc-ui` (Swagger UI), Lombok

## Chạy project

```bash
./mvnw spring-boot:run
```

Mặc định chạy ở `http://localhost:8080`. Vì `spring-boot-starter-security` đã có sẵn nên mọi request (trừ khi cấu hình khác) sẽ yêu cầu Basic Auth với user `user` + password in ra trong log khi khởi động app.

Swagger UI: `http://localhost:8080/swagger-ui.html`

## Tài liệu

- [LEARNING-ROADMAP.md](LEARNING-ROADMAP.md) — lộ trình đầy đủ 16 bước.
- `0X-*.md` ở từng branch — giải thích khái niệm + code mẫu + bug thực tế đã gặp cho từng bước, export sau khi hoàn thành.
