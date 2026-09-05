# Bước 9 — Refresh token

Access token của bước 8 sống 1 giờ. Muốn an toàn hơn (giảm thiệt hại nếu token bị lộ), cần rút ngắn thời hạn access token xuống rất ngắn (5-15 phút) — nhưng như vậy user sẽ bị văng ra liên tục, phải đăng nhập lại bằng password mỗi 15 phút, trải nghiệm tệ. Refresh token giải quyết mâu thuẫn này: tách "chứng minh danh tính" (password, chỉ dùng lúc login) ra khỏi "duy trì phiên làm việc" (refresh token, dùng để xin access token mới mà không cần gõ lại password).

## 1. Kiến trúc 2 loại token

| | Access token | Refresh token |
|---|---|---|
| Thời hạn | Ngắn (5-15 phút) | Dài (7-30 ngày) |
| Dùng để | Gọi mọi API (`Authorization: Bearer`) | Chỉ gọi `/auth/refresh` |
| Verify bằng | Chữ ký (stateless, không cần DB) | Chữ ký **+ tra DB** (để biết còn hiệu lực/đã bị thu hồi chưa) |
| Có thể revoke sớm? | Không (đặc điểm cố hữu của JWT thuần) | Có (vì có state trong DB) |

## 2. Cách làm

**`JwtService` — thêm claim phân biệt loại token, 2 method sinh token:**

```java
public String generateAccessToken(UserDetails userDetails) {
    return buildToken(userDetails, "access", 1000 * 60 * 15);       // 15 phút
}

public String generateRefreshToken(UserDetails userDetails) {
    return buildToken(userDetails, "refresh", 1000L * 60 * 60 * 24 * 7); // 7 ngày
}

private String buildToken(UserDetails userDetails, String type, long ttlMillis) {
    return Jwts.builder()
        .subject(userDetails.getUsername())
        .claim("type", type)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + ttlMillis))
        .signWith(getSigningKey())
        .compact();
}
```

**Entity + Repository để lưu refresh token đã phát hành:**

```java
@Entity
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class RefreshToken {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String token;

    private String username;
    private Instant expiryDate;
    private boolean revoked;
}
```

```java
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
}
```

**`/auth/login` trả về cả 2 token, lưu refresh token vào DB:**

```java
@PostMapping("/login")
public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));
    UserDetails userDetails = userDetailsService.loadUserByUsername(req.getUsername());

    String accessToken = jwtService.generateAccessToken(userDetails);
    String refreshToken = jwtService.generateRefreshToken(userDetails);

    refreshTokenRepository.save(RefreshToken.builder()
        .token(refreshToken)
        .username(userDetails.getUsername())
        .expiryDate(Instant.now().plus(7, ChronoUnit.DAYS))
        .revoked(false)
        .build());

    return ResponseEntity.ok(Map.of("accessToken", accessToken, "refreshToken", refreshToken));
}
```

**Endpoint `/auth/refresh` — cấp access token mới, xoay vòng refresh token:**

```java
@PostMapping("/refresh")
public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
    String oldToken = body.get("refreshToken");

    RefreshToken stored = refreshTokenRepository.findByToken(oldToken)
        .orElseThrow(() -> new BadCredentialsException("Refresh token không hợp lệ"));

    if (stored.isRevoked() || stored.getExpiryDate().isBefore(Instant.now())) {
        throw new BadCredentialsException("Refresh token đã hết hạn hoặc bị thu hồi");
    }

    String username = jwtService.extractUsername(oldToken);
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

    // Rotation: thu hồi token cũ, phát hành cặp token mới
    stored.setRevoked(true);
    refreshTokenRepository.save(stored);

    String newAccessToken = jwtService.generateAccessToken(userDetails);
    String newRefreshToken = jwtService.generateRefreshToken(userDetails);
    refreshTokenRepository.save(RefreshToken.builder()
        .token(newRefreshToken).username(username)
        .expiryDate(Instant.now().plus(7, ChronoUnit.DAYS)).revoked(false).build());

    return ResponseEntity.ok(Map.of("accessToken", newAccessToken, "refreshToken", newRefreshToken));
}
```

**Endpoint `/auth/logout` — thu hồi refresh token:**

```java
@PostMapping("/logout")
public ResponseEntity<?> logout(@RequestBody Map<String, String> body) {
    refreshTokenRepository.findByToken(body.get("refreshToken"))
        .ifPresent(rt -> { rt.setRevoked(true); refreshTokenRepository.save(rt); });
    return ResponseEntity.noContent().build();
}
```

## 3. Khái niệm cần nắm

1. **Vì sao access token "không thể" revoke sớm, còn refresh token thì được:** access token được `JwtAuthenticationFilter` verify **chỉ bằng chữ ký** (bước 8), không tra DB — đây chính là lợi ích "stateless" (nhanh, không tốn query). Nhưng hệ quả là server **không có cách nào** biết token đó "đã bị thu hồi" trước khi nó tự hết hạn tự nhiên — logout chỉ xoá token phía client, còn access token cũ vẫn **hợp lệ về mặt chữ ký** cho tới khi hết hạn. Đây chính xác là lý do access token phải **ngắn** — giới hạn "cửa sổ thiệt hại" nếu bị lộ. Refresh token thì ngược lại: mỗi lần dùng đều tra DB (`findByToken`), nên có thể đánh dấu `revoked = true` để vô hiệu hoá ngay lập tức.

2. **Refresh token rotation — vì sao mỗi lần refresh phải cấp token MỚI thay vì tái sử dụng:** nếu refresh token dùng được nhiều lần không giới hạn, kẻ tấn công chỉ cần đánh cắp 1 lần là có thể tự cấp access token mãi mãi. Rotation giới hạn: mỗi refresh token chỉ dùng được **đúng 1 lần**, sau đó bị revoke và thay bằng token mới. Hệ quả phụ quan trọng: nếu thấy một refresh token **đã bị revoke** vẫn được đem ra dùng lại, đó là dấu hiệu rõ ràng của **token bị đánh cắp** (reuse detection) — lúc đó nên revoke luôn toàn bộ "họ" token của user đó, không chỉ token đang bị dùng lại.

3. **Claim `"type": "access"` / `"refresh"` — vì sao cần phân biệt:** cả 2 loại token đều được ký bằng cùng 1 secret key và có cùng cấu trúc JWT — nếu không có claim phân biệt, `JwtAuthenticationFilter` (dùng cho các API thường) có thể **vô tình chấp nhận** một refresh token bị lộ để gọi API như access token thật, hoặc `/auth/refresh` có thể bị lừa chấp nhận access token thay vì refresh token. Cần kiểm tra claim `type` ở đúng chỗ: `JwtAuthenticationFilter` chỉ chấp nhận token có `type=access`; endpoint `/auth/refresh` chỉ chấp nhận `type=refresh`.

4. **Vì sao refresh token cần lưu trong DB thay vì chỉ tin vào chữ ký (giống access token):** nếu chỉ dựa vào chữ ký, refresh token cũng "sống mãi cho tới khi hết hạn" như access token — mất khả năng revoke/rotate. Việc bắt buộc tra DB (`findByToken`) mỗi lần dùng refresh token chính là điểm khác biệt cốt lõi khiến nó **không hoàn toàn stateless** — đánh đổi có chủ đích giữa bảo mật (revocable) và hiệu năng (phải query DB), chấp nhận được vì refresh token dùng ít hơn access token rất nhiều lần.

5. **Vòng đời đầy đủ của một phiên đăng nhập:** `login` → nhận cặp (access, refresh) → dùng access cho mọi request trong 15 phút → access hết hạn, client tự động gọi `/auth/refresh` với refresh token (không cần hỏi lại password) → nhận cặp token mới → lặp lại → cho tới khi refresh token cũng hết hạn (7-30 ngày, "phiên" thực sự kết thúc, bắt buộc login lại) hoặc user chủ động logout (revoke refresh token ngay lập tức).

## 4. Cách kiểm tra

```bash
# Login, lấy cả 2 token
curl -X POST http://localhost:8080/auth/login -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}'
# → {"accessToken": "...", "refreshToken": "..."}

# Dùng refresh token để lấy cặp token mới
curl -X POST http://localhost:8080/auth/refresh -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refresh token cũ>"}'

# Dùng LẠI refresh token cũ (đã bị rotate/revoke) → phải bị từ chối
curl -X POST http://localhost:8080/auth/refresh -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refresh token cũ, đã dùng 1 lần>"}'
# → 401, "Refresh token đã hết hạn hoặc bị thu hồi"

# Logout, rồi thử refresh lại bằng token đã logout
curl -X POST http://localhost:8080/auth/logout -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refresh token mới nhất>"}'
```

## 5. Câu hỏi tự kiểm tra

Sau khi user bấm "logout", access token họ đang cầm (chưa hết hạn 15 phút) có còn gọi API thành công được không?

→ **Có**, vẫn gọi được bình thường cho tới khi access token tự hết hạn — vì `JwtAuthenticationFilter` chỉ verify chữ ký, không tra DB, nên không biết refresh token liên quan đã bị revoke. Đây là giới hạn cố hữu đã nói ở mục 1 — chính là lý do access token phải ngắn: nó quyết định "logout có hiệu lực thực sự sau bao lâu", chứ không phải "ngay lập tức" như người dùng thường tưởng.

## 6. Q&A mở rộng

### "7 ngày" là tính từ lúc login, hay là idle-timeout?

Với thiết kế **rotation** ở trên, mỗi lần gọi `/auth/refresh`, refresh token cũ bị revoke và token mới được cấp với hạn 7 ngày **tính lại từ thời điểm đó**:

```java
.expiryDate(Instant.now().plus(7, ChronoUnit.DAYS))   // đếm lại từ bây giờ, không phải từ lúc login gốc
```

Đây gọi là **sliding expiration** (khác với *absolute expiration* — hết hạn cứng kể từ lúc login, không đổi dù có dùng lại giữa chừng). Với sliding expiration: chỉ cần user **mở app ít nhất 1 lần mỗi ≤7 ngày**, họ sẽ không bao giờ phải nhập lại password — đồng hồ liên tục được "reset". Nếu user thực sự không đụng tới app quá 7 ngày liên tục, refresh token cuối cùng họ có sẽ tự hết hạn, và họ buộc phải đăng nhập lại bằng password. Nói cách khác: "7 ngày" ở đây là **giới hạn idle tối đa được phép**, không phải giới hạn cứng kể từ lần login đầu tiên.

### Nếu refresh token bị đánh cắp, có nguy cơ bị DoS liên tục không?

Cần tách 2 tình huống khác nhau:

**Tình huống 1 — attacker "đua" với user thật bằng token bị đánh cắp:** ai gọi `/auth/refresh` trước sẽ được cấp token mới (rotation), người gọi sau (dù là ai) bị từ chối vì token cũ đã revoke. Kết quả: user thật bị **buộc đăng nhập lại đúng 1 lần** — một sự kiện đơn lẻ, không phải vòng lặp DoS vô hạn, vì token gốc chỉ dùng được đúng 1 lần dù ai dùng trước. Rủi ro thực sự nghiêm trọng hơn ở đây **không phải DoS, mà là chiếm quyền (impersonation)**: nếu attacker thắng cuộc đua, họ sở hữu chuỗi token mới và có thể tiếp tục refresh vô thời hạn để duy trì quyền truy cập như chính user đó.

**Tình huống 2 — spam endpoint `/auth/refresh` bằng token rác (không cần đánh cắp gì):** đây mới là DoS thực sự — mỗi request (kể cả token giả) đều tốn 1 query DB (`findByToken`) trước khi bị từ chối. Đây là dạng resource-exhaustion DoS thông thường của bất kỳ endpoint public nào, không đặc thù riêng cho refresh token — cần rate-limit theo IP/user, sẽ làm ở bước 14 ("Rate limiting, audit log, và bảo vệ chống brute-force").

**Cách giảm thiểu rủi ro khi refresh token bị lộ:**
1. TTL ngắn hơn nếu app nhạy cảm.
2. Reuse detection → revoke cả "họ" token, không chỉ token đang bị dùng lại — cắt quyền truy cập của attacker ngay khi phát hiện.
3. Lưu refresh token trong cookie `httpOnly` + `Secure` (JS không đọc được → chống XSS đánh cắp), tránh `localStorage`.
4. Rate limit `/auth/refresh` và `/auth/login` — chặn spam bất kể có token thật hay không.

---

*Gợi ý bước tiếp theo:* Bước 10 — Phân quyền chi tiết dựa trên dữ liệu (ownership): user chỉ được sửa/xoá "Note" do chính mình tạo, dùng `@PreAuthorize` với SpEL truy cập tham số method.
