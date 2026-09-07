# Bước 15 — Multi-module / Microservices với Security dùng chung (ý tưởng, chưa code)

> Trạng thái: mới dừng ở **thảo luận ý tưởng/kiến trúc**, CHƯA chọn hướng cụ thể, CHƯA viết code. File này ghi lại các phương án đã bàn để dùng làm điểm bắt đầu khi quay lại bước này. Khi đã chốt hướng và code xong, cần **update lại file này** (thêm mục Code/Test/Gap) thay vì tạo file mới, theo đúng quy ước đã dùng ở các bước trước.

## 1. Điều chỉnh phạm vi so với roadmap gốc — vì sao

Roadmap gốc mô tả bước này là "tách Auth Service riêng phát hành JWT, các service khác chỉ verify token". Nhưng trên branch `Keycloak`, từ bước 12, **Keycloak đã đóng đúng vai trò Auth Service riêng đó rồi** — app Spring Boot hiện tại chỉ là Resource Server. Vì vậy trọng tâm bước 15 không phải "tự viết 1 Auth Service", mà là:

- Nhân rộng mô hình Resource Server ra **nhiều service Spring Boot** cùng verify JWT từ 1 Keycloak.
- Xử lý bài toán **service gọi service** (không có user đứng sau) — thứ chưa gặp ở các bước trước.
- Cân nhắc thêm 1 **API Gateway** đứng trước các service.

## 2. Các lựa chọn kiến trúc đã bàn

### 2.1 Cách tổ chức code: multi-module Maven vs 2 project độc lập

Dự kiến tách project hiện tại (Notes) thành 2 service nhỏ để minh hoạ, ví dụ `notes-service` (giữ CRUD Notes hiện có) và 1 service phụ nhỏ (ví dụ `stats-service`) để `notes-service` gọi sang.

| Cách | Mô tả | Đánh giá |
|---|---|---|
| **Maven multi-module** | 1 repo, 1 parent `pom.xml`, nhiều module con | Đúng nghĩa đen "multi-module" trong roadmap; học thêm cách quản lý dependency/version dùng chung; có thể tách thêm 1 module `security-common` chứa `SecurityConfig`/`JwtAuthenticationConverter` để 2 service cùng phụ thuộc — đúng tinh thần "security dùng chung" |
| **2 project Spring Boot độc lập hoàn toàn** | 2 thư mục/2 process riêng, không chung parent pom | Gần với microservices thật hơn (mỗi service build/deploy độc lập); đơn giản hơn, không cần học Maven module |

*(chưa chốt — cần chọn trước khi bắt đầu code)*

### 2.2 "Chia sẻ JWK" giữa các service — thực ra không cần chia sẻ thủ công

Vì Keycloak ký JWT bằng **RS256 (asymmetric)**, mỗi service chỉ cần khai `issuer-uri` trỏ về Keycloak — Spring Security tự fetch JWK Set (public key) qua endpoint `/.well-known/...` của Keycloak, không có gì phải "chia sẻ" thủ công giữa các service. Khác hẳn JWT tự viết ở bước 8 (HS256 — nếu làm nhiều service dùng JWT tự ký kiểu đó thì đúng là phải chia sẻ *secret*, và lộ secret ở 1 service là lộ luôn khả năng giả JWT cho toàn bộ hệ thống).

Điểm cần thêm khi có nhiều Resource Server dùng chung 1 Keycloak: nên validate thêm claim **`aud` (audience)** để đảm bảo 1 token phát hành cho service A không bị dùng gọi nhầm/lạm dụng sang service B — cần cấu hình audience mapper phía Keycloak.

### 2.3 API Gateway đứng trước 2 service — 2 mô hình

**Mô hình A — Gateway verify JWT, service phía sau tin tưởng gateway**
- Gateway là Resource Server duy nhất; verify JWT xong mới route xuống `notes-service`/`stats-service`. Service phía sau không tự verify nữa, tin tưởng mọi request đều đã qua gateway (cần network policy đảm bảo service không bị gọi thẳng, bỏ qua gateway).
- Cách service phía sau biết "ai gọi": gateway forward lại claim qua header (`X-User-Id`, `X-Roles`) sau khi verify.
- Rủi ro kiến trúc cần lưu ý: nếu network không isolate đúng, gọi thẳng vào service bỏ qua gateway sẽ mất bảo vệ hoàn toàn.

**Mô hình B — Gateway chỉ routing, mỗi service tự verify JWT (giữ nguyên cơ chế đang có từ bước 12)**
- Gateway không biết gì về JWT, chỉ route theo path (`/notes/**` → notes-service, `/stats/**` → stats-service). Mỗi service vẫn tự làm Resource Server độc lập — mô hình **zero-trust/defense-in-depth**, dù bị gọi thẳng bỏ qua gateway thì service vẫn tự bảo vệ được.
- Gateway lúc này có giá trị ở việc tập trung **rate limiting** và **audit log** — đúng phần đang tự viết riêng lẻ ở từng service từ bước 14 (`RateLimitingFilter`, `AuditLogFilter`), có thể chuyển lên gateway làm 1 lần thay vì lặp lại.
- Phù hợp hơn nếu muốn **giữ nguyên** bài học audience/issuer-uri đã làm ở bước 12, không phá kiến trúc cũ.

Công cụ nếu làm thật: **Spring Cloud Gateway** — nhưng chạy trên WebFlux (reactive), khác hẳn Servlet stack đang dùng, nên tăng thêm độ khó khi chọn hướng này.

*(chưa chốt — cần chọn mô hình A hay B, hoặc bỏ qua gateway ở bước này, trước khi code)*

### 2.4 Service-to-service auth: token relay vs Client Credentials Grant

**Token relay**: notes-service nhận request có Bearer token của user X → forward **nguyên token đó** khi gọi `stats-service`. Đơn giản, nhưng:
- Chỉ dùng được khi đang xử lý 1 request có sẵn user token — nếu notes-service chạy job nền (`@Scheduled`) không gắn với request nào thì không có token để relay.
- Token vốn phát hành cho "user gọi notes-service" — nếu stats-service kiểm tra `aud` chặt, có thể từ chối.

**Client Credentials Grant** — grant type OAuth2 dành cho machine-to-machine, không có user đứng sau:

Cấu hình phía Keycloak:
1. Tạo client mới, ví dụ `notes-service-client` (khác client `securitylearing-api` dùng cho user login).
2. Bật **Client authentication = ON** → client có `client_secret` riêng (confidential client).
3. Bật **Service accounts roles = ON** → Keycloak tự tạo 1 "service account user" (`service-account-notes-service-client`).
4. Gán role riêng cho service account này, ví dụ `ROLE_SERVICE` — **tách biệt** với `ADMIN`/`USER` của người dùng thật.

Flow lúc chạy:
```
notes-service                          Keycloak                    stats-service
     |  POST /token                       |                              |
     |  grant_type=client_credentials      |                              |
     |  client_id=notes-service-client     |                              |
     |  client_secret=xxxx                 |                              |
     |------------------------------------>|                              |
     |  <-- access_token (JWT, sub=service-account-...) --                |
     |                                     |                              |
     |  GET /internal/stats  Authorization: Bearer <token>                |
     |-------------------------------------------------------------------->|
     |                    stats-service verify JWT y hệt cách verify user token
     |                    (cùng issuer-uri), nhưng thấy role=SERVICE thay vì USER/ADMIN
```

Ví dụ curl minh hoạ lấy token (chạy thử tay, không phải code project):
```bash
curl -X POST http://localhost:8081/realms/myrealm/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=notes-service-client" \
  -d "client_secret=xxxxx"
```

Điểm hay: stats-service verify JWT bằng **đúng cơ chế Resource Server sẵn có** (issuer-uri, JWK) — không cần code thêm gì để "nhận biết" đây là service gọi, chỉ cần phân quyền theo role:
```java
@PreAuthorize("hasRole('SERVICE')")   // endpoint nội bộ, chỉ service khác được gọi
@GetMapping("/internal/stats")
```
So với endpoint public cho user thật dùng `hasRole('USER')` — 1 user có token hợp lệ vẫn không gọi được endpoint nội bộ vì token của họ không có role `SERVICE`.

Về code phía notes-service (khi đóng vai trò client gọi đi): dùng `spring-security-oauth2-client`, khai 1 registration kiểu `client_credentials` (client-id/secret/token-uri trỏ Keycloak) trong `application.yml`, dùng `OAuth2AuthorizedClientManager` để tự động lấy token — Spring tự lo **cache token và xin lại khi hết hạn**, không cần tự viết cache tay.

Lưu ý bảo mật: `client_secret` là bí mật cần bảo vệ như password — không hardcode/commit. Nên tạo role riêng cho service account thay vì tái dùng role của user thật (least privilege, dễ audit "ai gọi": user hay service).

Mở rộng nâng cao (chưa cần cho bài học cơ bản): nếu cần vừa biết "service nào gọi" vừa biết "gọi thay cho user nào", có kỹ thuật **Token Exchange (RFC 8693)** mà Keycloak hỗ trợ.

## 3. Quyết định cần chốt trước khi bắt đầu code

- [ ] Multi-module Maven hay 2 project độc lập?
- [ ] Có làm API Gateway ở bước này không? Nếu có: mô hình A (gateway verify) hay B (gateway chỉ routing/rate-limit/audit tập trung)?
- [ ] Service phụ minh hoạ (`stats-service` hay tên khác) sẽ làm gì cụ thể, đủ đơn giản để không tốn công ngoài mục tiêu học security?
- [ ] Có tách module `security-common` dùng chung `SecurityConfig`/`JwtAuthenticationConverter` không?

## 4. Câu hỏi tự kiểm tra

1. Vì sao Keycloak dùng RS256 lại giúp nhiều service "chia sẻ" JWK mà không cần trao đổi secret thủ công? Nếu đổi sang HS256 thì rủi ro gì tăng lên khi có nhiều service?
2. Token relay và Client Credentials Grant khác nhau ở chỗ nào về "ai đứng sau token" (`sub` là gì)? Cho 1 tình huống chỉ Client Credentials mới dùng được, token relay thì không.
3. Nếu chọn mô hình gateway A (gateway verify, service tin tưởng), rủi ro lớn nhất về mặt kiến trúc là gì, và cách phòng tránh cơ bản là gì?
4. Vì sao service account (`service-account-notes-service-client`) nên có role riêng (`ROLE_SERVICE`) thay vì dùng chung role `ADMIN`/`USER` của người dùng thật?
5. Trong flow Client Credentials, `stats-service` có cần biết gì khác về notes-service ngoài việc verify JWT như bình thường không? Vì sao đây lại là điểm mạnh của cách tiếp cận này so với việc tự chế 1 cơ chế xác thực service-to-service riêng?
