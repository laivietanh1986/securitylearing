# JWT tự viết & Red Team — Giải thích và bài học

Tài liệu này giải thích **ý nghĩa** của từng phần trong bài tập JWT (`src/main/java/com/example/securitylearing/jwt/`) và **kiến thức bảo mật** rút ra từ mỗi bước, không chỉ là "code làm gì".

---

## Phần A — Tự viết JWT: học cơ chế bên dưới lớp vỏ thư viện

### A.1 — Encode header + payload, ký HMAC-SHA256

File: [`HmacJwtSigner.java`](src/main/java/com/example/securitylearing/jwt/HmacJwtSigner.java)

**Ý nghĩa:** một JWT không phải là dữ liệu "mã hoá" (encrypted) — nó chỉ là dữ liệu **được ký** (signed). Ai cũng đọc được payload (chỉ là base64url của JSON), thứ duy nhất ngăn giả mạo là chữ ký HMAC ở cuối:

```
base64url(header) + "." + base64url(payload) + "." + base64url(HMAC-SHA256(header.payload, secret))
```

**Bài học:**
- **JWT không giấu dữ liệu.** Không bao giờ được nhét thông tin nhạy cảm (mật khẩu, số thẻ...) vào payload — chỉ cần decode base64 là đọc được, không cần secret.
- **"Ký lại từ đầu" là bản chất của verify**, không phải một phép so sánh chuỗi đơn giản. Verifier không "đọc" chữ ký để biết nó đúng hay sai — nó tính toán lại HMAC từ đầu (dùng secret của chính mình) rồi so với chữ ký đính kèm. Điều này giải thích tại sao secret **không bao giờ được nằm trong token** — nếu nó nằm trong token thì ai cũng tự ký lại được.
- `header` không lấy từ input của caller — trong `HmacJwtSigner`, `alg` luôn bị hardcode thành `"HS256"`. Đây là chi tiết nhỏ nhưng quan trọng: **bên ký không tin caller nói mình muốn thuật toán gì**, cũng như bên verify sau này sẽ không tin token nói nó được ký bằng thuật toán gì (xem Phần B.5).

### A.2 — Verify: tách 3 phần, ký lại, so sánh bằng `MessageDigest.isEqual()`

File: [`HmacJwtVerifier.java`](src/main/java/com/example/securitylearing/jwt/HmacJwtVerifier.java), [`JwtToken.java`](src/main/java/com/example/securitylearing/jwt/JwtToken.java)

**Ý nghĩa:** `JwtToken.parse()` chỉ làm nhiệm vụ đọc cấu trúc (base64url, JSON) — nó **không đưa ra bất kỳ quyết định tin cậy nào**. Việc "chấp nhận hay từ chối" hoàn toàn nằm ở `HmacJwtVerifier.verify()`, tách biệt rõ ràng hai việc:
1. Parse (cấu trúc) — có thể sai (JSON hỏng, thiếu dấu chấm) nhưng không liên quan bảo mật.
2. Trust decision (thuật toán, chữ ký, claims) — đây mới là nơi bảo mật nằm.

**Bài học:** tách "đọc được" và "tin được" ra hai bước rõ ràng là nguyên tắc thiết kế quan trọng. Rất nhiều lỗ hổng JWT trong thực tế đến từ việc nhập nhằng hai bước này — ví dụ đọc `alg` từ token rồi *dùng luôn* giá trị đó để quyết định cách verify (xem `VulnerableJwtVerifier` ở Phần B).

### A.3 — Validate `exp`, `iat`, `iss`, `aud`, có leeway cho clock skew

**Ý nghĩa:** chữ ký hợp lệ chỉ chứng minh **ai đã tạo ra token** (nếu chỉ họ biết secret) và **nó chưa bị sửa**. Nó không chứng minh token **còn hiệu lực**, **dùng đúng chỗ**, hay **không đến từ tương lai**. Đó là việc của claims:

| Claim | Câu hỏi nó trả lời | Vì sao cần |
|---|---|---|
| `exp` | Token còn hạn không? | Giới hạn "cửa sổ thiệt hại" nếu token bị đánh cắp |
| `iat` | Token được tạo khi nào? | Phát hiện token có `iat` ở tương lai (dấu hiệu đồng hồ bị thao túng hoặc forge) |
| `nbf` | Token đã "mở khoá" chưa? | Cho phép phát hành token dùng sau (delayed activation) |
| `iss` | Ai phát hành? | Chặn token hợp lệ về mặt chữ ký nhưng đến từ hệ thống/issuer khác nếu secret bị dùng chung |
| `aud` | Token dành cho service nào? | Chặn "token confusion" giữa các service dùng chung issuer — token cấp cho service A bị replay sang service B |

**`leewaySeconds`** tồn tại vì đồng hồ của issuer và verifier hiếm khi khớp tuyệt đối (NTP drift vài giây là bình thường). Không có leeway → token hợp lệ bị từ chối oan do lệch giờ vài trăm mili-giây. Leeway quá lớn → kéo dài thời gian token hết hạn vẫn được chấp nhận. Mặc định trong bài là `0` (không khoan nhượng) để test B.7 ("hết hạn 1 giây trước phải fail") đúng theo yêu cầu chặt nhất; `leewaySeconds()` là chỗ để nới lỏng có chủ đích, không phải nới lỏng ngầm.

---

## Phần B — Red team: học cách một verifier "trông có vẻ đúng" vẫn có thể sai chết người

Đây là phần quan trọng nhất vì lỗi JWT trong thực tế gần như luôn nằm ở **logic verify**, không phải ở thuật toán ký. Bài tập dựng riêng [`VulnerableJwtVerifier.java`](src/main/java/com/example/securitylearing/jwt/VulnerableJwtVerifier.java) — mô phỏng đúng kiểu lỗi từng có thật trong các thư viện JWT (vd. `jsonwebtoken` cho Node.js, CVE liên quan đến `alg` confusion) — để attack có mục tiêu thật thay vì lý thuyết suông.

### B.4 — `alg: "none"`

**Cơ chế lỗ hổng:** `"none"` là một giá trị `alg` **hợp lệ theo RFC 7518 §3.6**, dùng cho JWT "unsecured" (không ký). Một verifier ngây thơ đọc `alg` từ header rồi rẽ nhánh theo đó (`if alg == "none": chấp nhận luôn`) sẽ tự nguyện tắt bước kiểm tra chữ ký — vì chính token nói với verifier rằng "tôi không cần chữ ký", và verifier tin luôn.

**Vì sao nguy hiểm:** attacker không cần biết secret. Chỉ cần đổi header thành `{"alg":"none"}`, xoá chữ ký, sửa payload tuỳ ý (vd. `role: admin`) → token được chấp nhận.

**Fix:** [`HmacJwtVerifier`](src/main/java/com/example/securitylearing/jwt/HmacJwtVerifier.java) và [`RsaJwtVerifier`](src/main/java/com/example/securitylearing/jwt/RsaJwtVerifier.java) đều có `ALLOWED_ALGORITHMS` — một **whitelist cố định phía server**, không phụ thuộc token. `alg` trong token chỉ được *đối chiếu* với whitelist này, không bao giờ được dùng để *chọn nhánh xử lý*.

**Bài học cốt lõi:** đừng bao giờ để dữ liệu chưa được xác thực (ở đây là chính cái header của token cần xác thực) quyết định *cách* bạn xác thực nó. Đây là một dạng tổng quát của lỗi "trust the input" — giống hệt tinh thần của SQL injection (dữ liệu quyết định câu lệnh) hay deserialization gadget chain (dữ liệu quyết định luồng thực thi).

### B.5 — Algorithm confusion (RS256 → giả bằng HS256 dùng public key làm secret)

**Cơ chế lỗ hổng:** hệ thống dùng RSA — server giữ private key để **ký**, public key để **verify**. Public key theo định nghĩa là công khai (thường publish ở JWKS endpoint hoặc nhúng trong client). Một verifier "tiện lợi" kiểu:

```java
if (alg == "RS256") verifyRsaSignature(publicKey, ...);
if (alg == "HS256") verifyHmac(publicKey.getEncoded(), ...);  // BUG
```

...vô tình biến public key thành "secret" dùng cho HMAC. Nhưng public key **không secret** — ai cũng có nó. Attacker: lấy public key (hợp pháp, ai cũng lấy được), tự đặt header `alg: HS256`, tự tính HMAC-SHA256 bằng chính public key đó, ký claims tuỳ ý → verifier (vì thấy `alg=HS256`) tính lại HMAC bằng cùng public key → khớp → chấp nhận. **Attacker chưa từng cần chạm vào private key.**

Đây chính là điều [`AlgorithmConfusionAttackTest.java`](src/test/java/com/example/securitylearing/jwt/AlgorithmConfusionAttackTest.java) chứng minh bằng code thật: forge một token, feed vào `VulnerableJwtVerifier` → được chấp nhận với `role: admin`.

**Fix:** không dùng một verifier "đa năng" đọc `alg` để chọn key/thuật toán. Thay vào đó, **một verifier instance gắn chết với một thuật toán và một loại key** — `RsaJwtVerifier` chỉ biết RSA + public key cố định, chỉ chấp nhận `alg=RS256`; `HmacJwtVerifier` chỉ biết HMAC + secret cố định, chỉ chấp nhận `alg=HS256`. Token forge ở trên có `alg=HS256` → bị `RsaJwtVerifier` từ chối ngay ở bước whitelist, **trước khi** bất kỳ phép toán crypto nào chạy.

**Bài học cốt lõi:** whitelist thuật toán không chỉ để chặn `none` — nó còn chặn việc *trộn lẫn không gian key* giữa các họ thuật toán khác nhau (symmetric vs asymmetric). Nguyên tắc thiết kế đúng: **(thuật toán, loại key) phải được server quyết định cứng, không bao giờ suy ra từ input.** Đây là lý do ở Phần C, cách nimbus thực sự an toàn (`JWSVerificationKeySelector` + `JWKSource` chỉ chứa `RSAKey`) là **không có chỗ nào tồn tại một mảng byte "secret"** để một header HS256 lợi dụng — an toàn ở tầng kiểu dữ liệu, không phải một `if` kiểm tra thêm.

### B.6 — Sửa 1 bit trong payload

**Cơ chế phòng thủ:** HMAC-SHA256 có **hiệu ứng lan toả (avalanche effect)** — đổi 1 bit input làm khoảng phân nửa số bit output đổi theo, gần như ngẫu nhiên. Vì vậy verifier tính lại HMAC từ payload đã bị sửa sẽ ra một giá trị hoàn toàn khác chữ ký gốc đính kèm → `MessageDigest.isEqual()` trả `false` → từ chối.

Trong [`HmacJwtVerifierTest.rejectsBitFlippedPayload`](src/test/java/com/example/securitylearing/jwt/HmacJwtVerifierTest.java), bit bị lật nằm ngay trong giá trị `"user-42"` (đổi thành ký tự khác) chứ không lật bit đầu tiên của JSON — lật bit đầu (byte `{`) sẽ làm hỏng luôn cú pháp JSON và bị chặn ở bước *parse*, không phải bước *verify chữ ký*. Chọn vị trí lật bit cẩn thận để bài test chứng minh đúng thứ cần chứng minh: **tính toàn vẹn được đảm bảo bởi chữ ký, không phải bởi may mắn JSON bị hỏng.**

**Bài học:** đây là lý do JWT dùng MAC/chữ ký chứ không phải checksum (CRC32, MD5-không-khoá...) — checksum ai cũng tính lại được kể cả không có secret, còn HMAC/RSA signature thì không. "Toàn vẹn" (integrity) trong JWT không đến từ base64 hay JSON, nó đến hoàn toàn từ phép toán crypto ở bước cuối.

### B.7 — Token hết hạn 1 giây trước

**Ý nghĩa của con số "1 giây":** đây là bài test biên (boundary test) — không kiểm tra "hết hạn rõ ràng" (vd. hết hạn 1 ngày trước) mà kiểm tra đúng ranh giới `now >= exp`. Loại lỗi hay gặp nhất ở đây là **off-by-one** trong so sánh (`>` thay vì `>=`) hoặc nhầm đơn vị (giây vs mili-giây — một lỗi rất phổ biến khi trộn `System.currentTimeMillis()` với `exp` tính bằng giây theo chuẩn JWT, làm token "không bao giờ hết hạn" trong hàng nghìn năm).

**Bài học:** luôn viết test ở đúng ranh giới thời gian (`exp - 1s`, `exp`, `exp + 1s`) thay ví chỉ test "còn hạn" và "hết hạn từ lâu" — hai trường hợp dễ đó không bắt được lỗi off-by-one hay lỗi đơn vị.

---

## Phần C — So với thư viện thật (nimbus-jose-jwt): "an toàn theo checklist" vs "an toàn theo cấu trúc"

File: [`NimbusJwtService.java`](src/main/java/com/example/securitylearing/jwt/NimbusJwtService.java), [`NimbusJwtComparisonTest.java`](src/test/java/com/example/securitylearing/jwt/NimbusJwtComparisonTest.java)

Chạy đúng 4 attack ở Phần B lên nimbus cho thấy hai *tầng* phòng thủ khác nhau:

1. **`alg: none` bị chặn ở tầng type-system.** `SignedJWT` và `PlainJWT` (unsecured) là **hai class khác nhau** trong nimbus. `SignedJWT.parse()` trên một token có `alg=none` ném `ParseException` ngay lúc parse — không có khái niệm "SignedJWT không chữ ký" tồn tại được trong hệ thống kiểu của thư viện. Đây mạnh hơn nhiều so với "kiểm tra whitelist lúc runtime" (như `HmacJwtVerifier` tự viết) — nó **loại trừ khả năng viết sai bằng cách làm cho trạng thái sai không thể biểu diễn được**.

2. **Algorithm confusion — điều bất ngờ nhất của bài tập:** nếu gọi thẳng `new MACVerifier(publicKeyBytes)` (bắt chước y hệt lỗi trong `VulnerableJwtVerifier`), **nimbus vẫn bị dính** — `NimbusJwtComparisonTest` chứng minh điều này (`jwt.verify(new MACVerifier(publicKeyBytesKnownToAttacker))` trả `true`). Thư viện không cấm bạn tự đưa key sai loại vào API mức thấp.
   Chỗ nimbus thực sự an toàn là khi dùng đúng API được thiết kế cho việc này: `JWSVerificationKeySelector` gắn với một `JWSAlgorithm` cụ thể (vd. `RS256`) và một `JWKSource` — nguồn key đó **chỉ chứa `RSAKey`**, không hề có một mảng byte "secret" nào tồn tại trong hệ thống để một header giả mạo `alg=HS256` có thể mượn dùng. Ở đây phòng thủ nằm ở **việc không tồn tại vật liệu để tấn công**, không phải một câu lệnh kiểm tra.

**Bài học lớn nhất của Phần C:** "dùng thư viện thật" không tự động an toàn — an toàn phụ thuộc vào việc bạn dùng **đúng lớp API** mà thư viện thiết kế để enforce ràng buộc (ở đây là `JWSVerificationKeySelector` + `JWKSource` kiểu hoá theo thuật toán), chứ không phải các API tiện lợi mức thấp (`MACVerifier` trần trụi). Một thư viện tốt giảm diện tích lỗi bằng cách làm cho cách dùng an toàn là cách dùng *dễ nhất/mặc định nhất*, nhưng nó không thể ngăn bạn cầm dao chọc tay nếu bạn cố tình cầm sai đầu.

---

## Vì sao `String.equals()` sai chỗ để so sánh chữ ký

`String.equals()` (và `Arrays.equals()`) so sánh **short-circuit**: vừa gặp ký tự/byte đầu tiên khác nhau là trả `false` ngay lập tức, không so tiếp phần còn lại. Hệ quả: **thời gian chạy phụ thuộc vào số ký tự đầu khớp đúng.**

Kẻ tấn công có khả năng đo độ trễ đủ chính xác (kể cả qua mạng — với đủ số lần lặp lại để lọc nhiễu, các nghiên cứu timing attack qua HTTP đã chứng minh khả thi) có thể khai thác điều này để dò chữ ký **từng byte một**:
1. Gửi chữ ký đoán với byte đầu = `0x00`, đo thời gian phản hồi.
2. Thử `0x00` → `0xFF`, byte nào cho thời gian phản hồi lâu hơn (do so sánh đi được xa hơn 1 bước trước khi fail) → đó là byte đúng.
3. Cố định byte 1, lặp lại cho byte 2, byte 3...

Với HMAC-SHA256 (32 byte), thay vì phải thử tối đa `2^256` khả năng (bất khả thi), attacker chỉ cần khoảng `256 × 32 = 8192` phép đo có định hướng — một sự khác biệt về độ khó **theo cấp số nhân**.

`MessageDigest.isEqual()` được thiết kế để **luôn duyệt hết toàn bộ độ dài của cả hai mảng**, bất kể phát hiện sai khác ở đâu — thời gian chạy không phụ thuộc vào nội dung, chỉ phụ thuộc vào độ dài (public, không phải bí mật). Đó là lý do nó là API bắt buộc dùng khi so sánh bất kỳ giá trị bí mật/derived-from-secret nào (chữ ký, MAC, hash mật khẩu, token session...), không riêng gì JWT.

---

## Tổng kết — những nguyên tắc rút ra, áp dụng được ngoài phạm vi JWT

1. **Tách "đọc được" khỏi "tin được".** Parse dữ liệu không đồng nghĩa với việc dữ liệu đó đáng tin — quyết định tin cậy phải là một bước riêng, tường minh.
2. **Không bao giờ để input chưa xác thực quyết định *cách* bạn xác thực nó.** (alg header, Content-Type client tự khai, `X-Forwarded-*` chưa được proxy tin cậy ghi đè... đều cùng một lớp lỗi.)
3. **Whitelist cứng phía server, không suy luận từ token/request.** Áp dụng cho thuật toán JWT, cho phép Content-Type, cho danh sách redirect URL hợp lệ, v.v.
4. **So sánh giá trị bí mật luôn dùng hàm constant-time** (`MessageDigest.isEqual`, hoặc `MessageDigest.isEqual`-tương-đương của ngôn ngữ khác) — không bao giờ dùng `==`, `.equals()` mặc định.
5. **Một thư viện "thật" chỉ an toàn nếu dùng đúng API được thiết kế để enforce ràng buộc** — luôn tự hỏi "API tiện lợi này có đang bỏ qua một ràng buộc mà tôi tưởng nó tự làm không?" thay vì mặc định tin "thư viện nổi tiếng thì chắc an toàn".
6. **Viết test ở đúng ranh giới** (`exp - 1s`, không phải chỉ "rất hết hạn" hay "còn rất mới") để bắt được lỗi off-by-one và lỗi đơn vị thời gian.
