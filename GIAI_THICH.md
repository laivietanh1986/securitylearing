# Mục đích của bài lab này

Bài này dạy 4 chủ đề cốt lõi về **lưu trữ mật khẩu an toàn** — thứ hầu như mọi hệ thống
backend đều phải làm đúng, nhưng rất dễ làm sai. Từng phần giải quyết một câu hỏi thực tế
cụ thể.

## 1. Benchmark BCrypt cost 4→15 — "Cost factor" là gì và chọn sao cho đúng

BCrypt cố tình **chậm**, và độ chậm đó tăng theo cấp số nhân (`cost` tăng 1 → thời gian
gấp đôi). Đây không phải bug, mà là cơ chế phòng thủ: nếu hacker lấy trộm được database
password hash, họ phải hash lại hàng tỷ lần để dò mật khẩu (brute-force/dictionary
attack) — cost càng cao thì họ càng tốn thời gian/tiền GPU.

Vấn đề là: cost cao cũng làm **server của bạn** chậm khi user login thật. Bạn học cách:

- Tự đo thời gian thật (không đoán mò) bằng `System.nanoTime`
- Nhận ra quy luật gấp đôi (cost 12 = 331ms, cost 13 = 578ms...)
- Chọn một con số cụ thể (ở đây là 12) **dựa trên số liệu**, cân bằng giữa UX (user không
  muốn chờ >1s để login) và bảo mật (đủ chậm để attacker tốn kém).

## 2. Argon2id với 3 bộ tham số — Tại sao "memory-hard" mạnh hơn BCrypt

BCrypt chỉ tốn CPU, mà GPU có hàng nghìn core CPU yếu nên có thể chạy song song cực
nhanh → GPU crack BCrypt nhanh hơn CPU rất nhiều lần.

Argon2id giải quyết điểm yếu đó bằng cách bắt mỗi lần hash phải chiếm một **vùng RAM
lớn** (19-47 MB ở đây). GPU có hàng nghìn core nhưng RAM/băng thông bộ nhớ thì có hạn →
không thể chạy song song hàng nghìn phép hash cùng lúc như với BCrypt. Bạn học được:

- `memory`, `iterations`, `parallelism` ảnh hưởng thời gian hash thế nào
- Vì sao các hệ thống mới (OWASP khuyến nghị) chọn Argon2id thay vì BCrypt

## 3. Bảng cost → ms → attempts/giây của attacker có GPU — Biến số kỹ thuật thành lý lẽ bảo mật

Đây là bước quan trọng nhất về tư duy: một con số "331ms" tự nó vô nghĩa với sếp/khách
hàng. Bạn cần dịch nó thành: *"ở cost 12, kẻ tấn công có 1 GPU chỉ dò được ~1000 mật
khẩu/giây"* — đó là ngôn ngữ để **bảo vệ quyết định kỹ thuật** trước người không rành kỹ
thuật, và cũng để tự bạn đánh giá "mức phòng thủ này có đủ không".

## 4. `DelegatingPasswordEncoder` + migrate MD5 → BCrypt khi login — Bài toán thực tế của hệ thống cũ

Không hệ thống production nào được viết lại từ đầu. Rất nhiều hệ thống cũ lưu password
bằng MD5/SHA1 (không an toàn theo chuẩn hiện tại). Bạn **không thể** bắt hết user đổi
mật khẩu ngay lập tức (rất phiền, user bỏ chạy). Giải pháp chuẩn: âm thầm nâng cấp hash
**ngay khi user đó login thành công lần tiếp theo** — vì lúc đó bạn có sẵn plaintext
password trong tay (chỉ khoảnh khắc đó thôi) để hash lại bằng thuật toán mới.

Bạn học được:

- Prefix `{MD5}`, `{bcrypt}` để một encoder biết hash nào dùng thuật toán nào
- Cơ chế `upgradeEncoding()` có sẵn trong Spring Security, không cần tự viết logic phát
  hiện "hash cũ"

## 5. Timing attack lab — Rò rỉ thông tin qua **thời gian phản hồi**, không qua nội dung response

Đây là lỗ hổng rất tinh vi mà nhiều dev không biết: nếu code viết kiểu

```java
if (user == null) return 401;      // trả về NGAY, không hash gì cả
if (!matches(pw, user.hash)) return 401;  // phải hash rồi mới trả về
```

thì request với email **không tồn tại** sẽ nhanh hơn hẳn request với email **tồn tại
nhưng sai password** — vì nhánh đầu không tốn thời gian hash BCrypt (~300ms), nhánh sau
thì có. Attacker đo thời gian phản hồi hàng loạt là **dò được email nào có tài khoản
trong hệ thống** mà không cần đăng nhập được — gọi là **user enumeration qua timing
side-channel**.

Cách sửa (dummy hash) đã làm trong bài: dù email không tồn tại, code vẫn chạy
`matches()` với một hash giả có cùng cost — để hai nhánh luôn tốn thời gian gần bằng
nhau. Bạn học được:

- Khái niệm **side-channel attack** (rò rỉ qua kênh phụ: thời gian, chứ không phải qua
  dữ liệu trả về)
- Cách đo bằng percentile (p50/p99) thay vì trung bình đơn thuần — vì hệ thống thật có
  nhiễu (GC, cache...), p99 cho biết trường hợp xấu nhất
- Cách viết test tự động để **giữ** thuộc tính bảo mật này không bị phá vỡ khi code sau
  này thay đổi (regression test cho bảo mật, không chỉ cho chức năng)

---

**Tóm gọn triết lý chung của cả bài**: bảo mật không phải "dùng thuật toán mạnh là
xong" — mà là hiểu **đánh đổi** (cost vs UX), **đo đạc thật** thay vì đoán, và nhận diện
các lỗ hổng tinh vi (timing, migration) mà logic "đúng chức năng" vẫn có thể mắc phải.
