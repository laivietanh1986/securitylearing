# Bước 14 — Rate limiting, Audit log, chống brute-force

> Quy trình: user chọn kiểu kết hợp — Claude giải thích khái niệm + đưa code mẫu trước, sau đó Claude code trực tiếp luôn (không chờ user tự gõ), rồi export file này. Code đã build thành công (`mvn clean compile` → BUILD SUCCESS), chưa test runtime với Keycloak thật.

## 1. Điều chỉnh phạm vi so với roadmap gốc — vì sao

Nội dung gốc trong `LEARNING-ROADMAP.md` giả định app có `/auth/login` nội bộ để giới hạn "số lần đăng nhập sai". Nhưng trên branch `Keycloak` này, từ bước 12, **việc đăng nhập không còn diễn ra trong app Spring Boot** — Keycloak là Authorization Server duy nhất, app chỉ là Resource Server validate JWT. Vì vậy bước 14 được chia làm 2 phần rõ ràng:

- **Rate limiting API + Audit log** — làm được và có ý nghĩa trong app này, áp dụng chung cho mọi endpoint (không riêng login).
- **Chống brute-force đăng nhập sai** — chuyển thành **cấu hình phía Keycloak** (không phải code Spring), vì đó là nơi duy nhất còn xử lý password.

## 2. Khái niệm

### Rate limiting

Giới hạn số request 1 client được gọi trong 1 khoảng thời gian, để chống lạm dụng API (vét cạn tài nguyên, dò brute-force qua endpoint khác, DoS đơn giản từ 1 IP).

**Bản đầu tiên** (đã thay thế, xem lịch sử git nếu cần) dùng **fixed window** tự viết (chia thời gian thành cửa sổ cố định 10 giây, đếm request trong cửa sổ, reset khi hết cửa sổ) để thấy rõ cơ chế bên trong trước. Nhược điểm đã phát hiện: hiện tượng **"burst ở ranh giới"** — client gửi dồn request vào cuối cửa sổ này + đầu cửa sổ kế tiếp có thể đạt gần gấp đôi giới hạn thực tế trong 1 khoảng thời gian ngắn quanh ranh giới 2 cửa sổ.

**Bản hiện tại dùng thư viện Bucket4j**, implement thuật toán **token bucket** — giải quyết đúng vấn đề trên. Xem mục 6 "Q&A mở rộng" để hiểu sâu về token bucket, các chiến lược refill (`greedy`/`intervally`/`intervallyAligned`), và cách mở rộng thành rate limiting phân tán (nhiều instance) bằng Bucket4j.

**Rate limit theo gì?** Code hiện tại limit theo **IP** (`request.getRemoteAddr()`) — đơn giản, áp dụng được cho cả request chưa xác thực (trước khi biết user là ai). Nhược điểm: nhiều user đứng sau cùng 1 NAT/proxy sẽ dùng chung 1 quota. Có thể nâng cấp sau này để limit theo user (từ JWT) cho các endpoint đã xác thực.

### Audit log

Ghi lại "ai gọi gì, lúc nào, kết quả ra sao" cho mỗi request — phục vụ điều tra sự cố bảo mật sau này (ai xoá note nào, ai bị từ chối quyền nhiều lần bất thường liên tiếp).

Thông tin ghi: IP, method, path, status code response, username (lấy từ JWT), thời gian xử lý (ms).

### Account lockout / chống brute-force đăng nhập (phía Keycloak, không phải code)

Keycloak Admin Console → chọn realm `myrealm` → **Realm Settings → Security defenses → tab "Brute force detection"**:
- Bật **Enabled**.
- `Max Login Failures`: số lần sai password tối đa trước khi khoá tạm.
- `Wait Increment`: thời gian khoá tăng dần sau mỗi lần vi phạm tiếp theo.
- `Max Wait`: thời gian khoá tối đa.

Đây là tính năng có sẵn của Keycloak, không cần viết code — đúng tinh thần "tách Authorization Server và Resource Server" đã học ở bước 12: mọi thứ liên quan tới password/đăng nhập giờ là trách nhiệm của Keycloak.

## 3. Code

### `pom.xml` — thêm dependency Bucket4j

```xml
<dependency>
    <groupId>com.bucket4j</groupId>
    <artifactId>bucket4j-core</artifactId>
    <version>8.10.1</version>
</dependency>
```

### `RateLimitingFilter.java`

```java
package com.example.securitylearing.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

  private static final int CAPACITY = 20;
  private static final Duration REFILL_PERIOD = Duration.ofSeconds(10);

  private final ConcurrentHashMap<String, Bucket> bucketsByIp = new ConcurrentHashMap<>();

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String clientIp = request.getRemoteAddr();
    Bucket bucket = bucketsByIp.computeIfAbsent(clientIp, ip -> newBucket());

    if (!bucket.tryConsume(1)) {
      response.setStatus(429);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"Qua nhieu request, vui long thu lai sau\"}");
      return;
    }

    filterChain.doFilter(request, response);
  }

  private Bucket newBucket() {
    Bandwidth limit = Bandwidth.builder()
        .capacity(CAPACITY)
        .refillGreedy(CAPACITY, REFILL_PERIOD)
        .build();
    return Bucket.builder().addLimit(limit).build();
  }
}
```

**Vì sao `refillGreedy` chứ không phải `refillIntervally`:** `refillGreedy` nhỏ giọt token liên tục theo tỷ lệ thời gian trôi qua (≈ 2 token/giây với cấu hình 20 token/10s), không có thời điểm "đổ đầy 1 lần" nào để bị lợi dụng dồn request — đây chính là cách giải quyết đúng vấn đề "burst ở ranh giới" của bản fixed window trước đó. Chi tiết so sánh 3 chiến lược refill của Bucket4j (`greedy`/`intervally`/`intervallyAligned`) xem mục 6 "Q&A mở rộng".

**Lưu ý API:** bản Bucket4j 8.10.1 đã **deprecated** cách viết cũ hay gặp trên tài liệu/mạng (`Bandwidth.classic(capacity, Refill.intervally(...))`) — dùng cách viết builder mới (`Bandwidth.builder().capacity(...).refillGreedy(...).build()`) như trên để tránh warning lúc build.

**Vì sao không cần `synchronized` như bản tự viết trước:** `Bucket.tryConsume(1)` của Bucket4j tự đảm bảo thread-safe bên trong (dùng CAS loop trên state, không dùng lock truyền thống) — khác bản fixed window tự viết trước đó phải tự thêm `synchronized` thủ công.

**Vì sao dùng `ConcurrentHashMap`:** nhiều IP khác nhau gọi đồng thời, `computeIfAbsent` cần thread-safe để không tạo 2 `Bucket` khác nhau cho cùng 1 IP khi 2 request đầu tiên từ IP đó tới cùng lúc.

### `AuditLogFilter.java`

```java
package com.example.securitylearing.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AuditLogFilter extends OncePerRequestFilter {

  private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    long start = System.currentTimeMillis();
    try {
      filterChain.doFilter(request, response);
    } finally {
      long durationMs = System.currentTimeMillis() - start;
      auditLog.info("ip={} method={} path={} status={} user={} durationMs={}",
          request.getRemoteAddr(),
          request.getMethod(),
          request.getRequestURI(),
          response.getStatus(),
          resolveUsername(),
          durationMs);
    }
  }

  private String resolveUsername() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      return "anonymous";
    }
    if (authentication.getPrincipal() instanceof Jwt jwt) {
      String preferredUsername = jwt.getClaimAsString("preferred_username");
      return preferredUsername != null ? preferredUsername : jwt.getSubject();
    }
    return authentication.getName();
  }
}
```

**Vì sao dùng `try/finally` bao quanh `filterChain.doFilter(...)`:** phải log **sau khi** toàn bộ request được xử lý xong (kể cả khi controller ném exception) để lấy được `response.getStatus()` thật (200, 403, 404, 500...). Đặt log trước `doFilter()` sẽ không biết kết quả cuối cùng; `finally` đảm bảo log chạy dù có exception hay không.

**Vì sao `resolveUsername()` đọc `SecurityContextHolder` thay vì tự parse JWT lại:** tại thời điểm `AuditLogFilter` chạy (sau `BearerTokenAuthenticationFilter`, xem mục nối dây bên dưới), Spring Security đã verify JWT và set `Authentication` vào `SecurityContextHolder` rồi — không cần parse lại token, tránh trùng lặp logic.

### Nối vào `SecurityConfig.java`

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter,
    RateLimitingFilter rateLimitingFilter, AuditLogFilter auditLogFilter) throws Exception{
  http
      .cors(cors -> cors.configurationSource(corsConfigurationSource()))
      .csrf(csrf -> csrf.disable())
      .authorizeHttpRequests(...)
      .exceptionHandling(...)
      .oauth2ResourceServer(oauth2 -> oauth2
          .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
      )
      .addFilterBefore(rateLimitingFilter, BearerTokenAuthenticationFilter.class)
      .addFilterAfter(auditLogFilter, BearerTokenAuthenticationFilter.class);
  return http.build();
}
```

**Vì sao thứ tự này quan trọng:**
- `RateLimitingFilter` đặt **trước** `BearerTokenAuthenticationFilter` (filter verify JWT của Spring) — chặn request vượt giới hạn **trước khi** tốn công verify JWT/gọi JWK endpoint của Keycloak. Rate limit theo IP nên không cần biết user đã xác thực hay chưa.
- `AuditLogFilter` đặt **sau** `BearerTokenAuthenticationFilter` — để khi nó chạy, `SecurityContextHolder` đã có `Authentication` (nếu token hợp lệ), lấy được `preferred_username` thật thay vì luôn thấy "anonymous".

`RateLimitingFilter`/`AuditLogFilter` được đánh dấu `@Component` và khai làm **tham số của `securityFilterChain(...)`** — Spring tự autowire theo kiểu, giống cách các bean khác đã làm từ các bước trước.

## 4. Test

**Test rate limiting:**
```bash
for i in $(seq 1 25); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/hello; done
```
Với token bucket: 1 IP mới (bucket khởi tạo đầy 20 token) cho phép **burst 20 request đầu tiên** trả `200` gần như ngay lập tức, từ request thứ 21 trở đi trả `429` — sau đó nếu đợi vài giây (token nhỏ giọt theo `refillGreedy`, ~2 token/giây), gọi lại sẽ được thêm vài request `200` tuỳ số token đã kịp refill, chứ không phải "chờ đúng hết 10 giây mới được thêm 20 cái" như bản fixed window cũ.

**Test audit log:** gọi vài request bất kỳ (`/hello`, `/notes` có/không token), xem console log của app có dòng dạng:
```
AUDIT - ip=0:0:0:0:0:0:0:1 method=GET path=/notes status=200 user=admin durationMs=15
AUDIT - ip=0:0:0:0:0:0:0:1 method=GET path=/notes status=401 user=anonymous durationMs=2
```

## 5. Gap / giới hạn đã biết (chưa xử lý)

- **Rate limit theo IP, không theo user** — nhiều user sau cùng NAT/proxy dùng chung quota; nếu cần chính xác hơn theo user đã xác thực, phải limit theo `preferred_username` từ JWT thay vì `getRemoteAddr()` — nhưng khi đó endpoint chưa xác thực (như `/hello`) sẽ không limit được theo cách này.
- **In-memory, không dùng được nếu scale nhiều instance** — `ConcurrentHashMap<String, Bucket>` chỉ tồn tại trong 1 process; nếu chạy nhiều instance sau load balancer, mỗi instance có quota riêng, tổng quota thực tế của 1 client = số instance × `CAPACITY`. Bucket4j có sẵn hướng giải quyết (`bucket4j-redis`, `bucket4j-hazelcast`...) — xem mục 6 Q&A mở rộng — nhưng chưa áp dụng ở bước này.
- **Không có cơ chế dọn bộ nhớ (`bucketsByIp` map)** — IP nào từng gọi 1 lần sẽ ở lại trong map mãi mãi (dù rất nhỏ). Với app học tập chạy ngắn hạn không vấn đề gì; app chạy lâu dài với traffic từ rất nhiều IP khác nhau (bot, scanner...) có thể cần thêm cơ chế eviction (ví dụ dùng cache có TTL như Caffeine) — chưa làm ở bước này.
- **Chưa trả header rate-limit chuẩn** (`X-RateLimit-Remaining`, `Retry-After`) — Bucket4j hỗ trợ qua `tryConsumeAndReturnRemaining(1)` (trả về `ConsumptionProbe` có số token còn lại + thời gian chờ refill), nhưng code hiện tại chỉ dùng `tryConsume(1)` (trả `boolean` trơn) — xem mục 6.
- **Audit log chỉ in ra console (SLF4J mặc định)**, chưa ghi vào file riêng hay hệ thống log tập trung (ELK, v.v.) — nằm ngoài phạm vi Spring Security, thuộc về cấu hình `logback.xml`/hạ tầng logging.

## 6. Q&A mở rộng — tìm hiểu sâu về Bucket4j

### Token bucket là gì

Hình dung 1 cái xô chứa tối đa `capacity` token. Mỗi request tiêu 1 token; còn token thì cho qua, hết thì từ chối. Token được refill (bơm lại) theo thời gian theo 1 trong 3 chiến lược:

| Chiến lược | Cách hoạt động | Ưu/nhược |
|---|---|---|
| `refillIntervally(N, period)` | Hết mỗi `period`, đổ **1 lần** đủ `N` token | Gần giống fixed window — vẫn có thể bị burst đúng lúc vừa refill |
| `refillIntervallyAligned(N, period, startInstant)` | Giống trên nhưng refill đúng theo mốc đồng hồ tường (ví dụ đúng phút 0 mỗi giờ) | Dùng khi cần quota reset đúng lịch, ví dụ "giới hạn theo ngày, reset lúc 0h" |
| `refillGreedy(N, period)` (đang dùng) | Token nhỏ giọt liên tục theo tỷ lệ thời gian trôi qua | Không có mốc "đổ đầy 1 lần" để lợi dụng dồn request — giải quyết đúng vấn đề burst ở ranh giới |

### Ý nghĩa thực tế của cấu hình đang dùng: `capacity(20)` + `refillGreedy(20, 10s)`

Mặc định 1 bucket mới được tạo đã **đầy `capacity` token ngay từ đầu** (trừ khi gọi thêm `.initialTokens(...)`). Nghĩa là: 1 IP mới (hoặc IP "nghỉ" đủ lâu để xô đầy lại) được phép **burst 20 request liền một lúc**, sau đó throttle về nhịp ổn định 20 token / 10 giây = trung bình **2 request/giây**, chảy đều chứ không "chờ đủ 10 giây rồi có 20 cái 1 lúc". Đây là hành vi đúng bản chất token bucket — vừa chịu được traffic dồn dập hợp lệ (client gọi nhiều API liên tiếp lúc load trang), vừa chặn được lạm dụng kéo dài.

### Vì sao `tryConsume(1)` thread-safe mà không cần `synchronized`

Bên trong, `Bucket` giữ state (số token hiện có, thời điểm refill gần nhất) bằng CAS (compare-and-swap) loop trên `AtomicLong`/`VarHandle`, không dùng lock truyền thống — khác hẳn cách bản tự viết trước phải tự thêm `synchronized` thủ công.

### Tính năng chưa dùng tới nhưng đáng biết

- **`tryConsumeAndReturnRemaining(1)`** thay vì `tryConsume(1)`: trả về 1 `ConsumptionProbe` chứa số token còn lại + số nano-giây phải chờ tới lần refill kế tiếp — dùng để trả thêm header chuẩn REST API như `X-RateLimit-Remaining`, `Retry-After` cho client biết khi nào nên thử lại.
- **Distributed rate limiting**: Bucket4j có các module `bucket4j-redis`, `bucket4j-hazelcast`, `bucket4j-ignite`... cho phép nhiều instance app dùng chung 1 kho đếm token ở Redis/Hazelcast thay vì `ConcurrentHashMap` cục bộ — logic `Bandwidth`/`tryConsume` giữ nguyên, chỉ đổi cách tạo `Bucket` (qua 1 `ProxyManager` trỏ tới backend chia sẻ). Đây là hướng giải quyết đúng gap "in-memory, không dùng được khi scale nhiều instance" ở mục 5.

## 7. Câu hỏi tự kiểm tra

1. Vì sao rate limiting nên đặt **trước** bước verify JWT, không phải sau?
2. Fixed window có thể bị "lách" thế nào ở ranh giới 2 cửa sổ? Vì sao `refillGreedy` của token bucket giải quyết đúng vấn đề đó, còn `refillIntervally` thì không (gần như quay lại vấn đề cũ)?
3. Với `capacity(20)` + `refillGreedy(20, 10s)`, nếu 1 IP gọi đúng 2 request/giây liên tục không nghỉ, có bao giờ bị 429 không? Còn nếu gọi 20 request dồn dập ngay giây đầu tiên rồi dừng, khi nào IP đó lại được burst 20 request tiếp theo?
4. Vì sao không thể chống brute-force đăng nhập bằng code trong app Spring Boot này nữa? Nếu quay lại nhánh `spring_security` (có `/auth/login` tự viết ở bước 8), account lockout sẽ cần code ở đâu?
5. Nếu 10 request đầu tiên từ 1 IP đều là request KHÔNG hợp lệ (JWT sai/thiếu), `RateLimitingFilter` có đếm chúng vào quota không? Vì sao đặt filter trước `BearerTokenAuthenticationFilter` lại có ý nghĩa phòng thủ ở đây (gợi ý: kẻ tấn công dò JWT sai hàng loạt)?
