# Bước 11 — OAuth2 Login với GitHub

> Phạm vi bước này: chỉ làm **GitHub** (OAuth2 thuần). Google (OIDC) tạm hoãn — xem mục 5 "Gap chưa xử lý" để biết lý do.

## 1. Khái niệm

### Authorization Code flow (rút gọn)

```
User → App:        "Login with GitHub"
App → GitHub:       redirect tới authorization endpoint (client_id, redirect_uri, scope, state)
GitHub → User:      màn hình đăng nhập + xin quyền
GitHub → App:       redirect về redirect_uri kèm "code"
App → GitHub:       đổi code lấy access_token (server-to-server, kèm client_secret)
App → GitHub:       dùng access_token gọi UserInfo endpoint lấy thông tin user
App:                tạo/tìm user nội bộ tương ứng, issue JWT
```

Spring Security lo phần lớn việc này (redirect, đổi code, gọi userinfo) — chỉ cần cấu hình client-id/secret và viết logic map user.

### Vì sao GitHub không phải OIDC

Google dùng **OIDC** (lớp chuẩn hoá trên OAuth2, trả ID token) → Spring biểu diễn user là `OidcUser`, cấu hình qua `.oidcUserService(...)`.
GitHub chỉ là **OAuth2 thuần** (không OIDC) → Spring biểu diễn user là `OAuth2User` thường, cấu hình qua `.userService(...)`.

Đây là lý do nếu sau này thêm Google vào cùng cấu hình mà chỉ set `.userService(...)`, Google login sẽ luôn thất bại (Spring dùng `OidcUserService` mặc định thay vì custom service) — xem mục 5.

### STATELESS vs OAuth2 login flow

App gốc dùng `SessionCreationPolicy.STATELESS` (JWT thuần). Nhưng `oauth2Login()` mặc định của Spring Security **cần session** để lưu tạm `state`/`nonce` chống CSRF trong lúc redirect qua GitHub rồi quay lại.

→ Đổi `STATELESS` → `SessionCreationPolicy.IF_REQUIRED`: session chỉ tạo tạm trong lúc OAuth2 redirect; sau khi issue JWT xong, các request API tiếp theo vẫn dùng Bearer token bình thường, không phụ thuộc session.

## 2. Đăng ký OAuth App trên GitHub (ngoài code)

GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.
Authorization callback URL: `http://localhost:8080/login/oauth2/code/github`.
Lấy `client-id` và `client-secret`.

## 3. Dependency & cấu hình

`pom.xml`:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

`application.yaml`:
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
#          google:                          # tạm hoãn, xem mục 5
#            client-id: ${GOOGLE_CLIENT_ID}
#            client-secret: ${GOOGLE_CLIENT_SECRET}
#            scope: openid,profile,email
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope: read:user,user:email
  application:
    name: securitylearing
jwt:
  secret: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

Dùng biến môi trường cho client-id/secret, không hardcode/commit secret thật.

`github` là provider có sẵn trong Spring (`CommonOAuth2Provider`) nên không cần khai báo thêm block `provider:` — Spring tự biết endpoint, và tự set `user-name-attribute = id`.

## 4. Entity & repository

### `User.java` — thêm field cho user OAuth

```java
@Column(nullable = true)   // đổi từ nullable = false — user OAuth không có password nội bộ
private String password;

@Column(nullable = true)
private String provider;    // "github", null nếu là user local

@Column(nullable = true)
private String providerId;  // id GitHub cấp cho user đó, ổn định không đổi
```

**Vì sao dùng `providerId` chứ không chỉ email:** email có thể null (GitHub cho phép để private) hoặc user đổi email; `providerId` luôn ổn định.

### `UserRepository.java` — thêm query theo khoá định danh OAuth

```java
Optional<User> findByProviderAndProviderId(String provider, String providerId);
```

### `CustomUserDetailService.java` — xử lý password null cho user OAuth

```java
return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
    .password(user.getPassword() != null ? user.getPassword() : "{noop}oauth2-external-user")
    .roles(user.getRoles())
    .build();
```

**Lưu ý:** `Spring Security User.UserBuilder.password(...)` gọi `Assert.hasText(...)` bên trong — nếu để `null`/rỗng, `build()` ném `IllegalArgumentException`. Cần fallback về 1 chuỗi placeholder không rỗng.

Prefix `{noop}` chỉ có ý nghĩa đặc biệt khi dùng `DelegatingPasswordEncoder` — app này dùng thẳng `BCryptPasswordEncoder` nên `{noop}` chỉ là 1 chuỗi bình thường không phải hash hợp lệ. Không sao: `BCryptPasswordEncoder.matches()` khi thấy chuỗi không đúng định dạng bcrypt sẽ trả về `false` (không throw), nên user OAuth-only cố login bằng `/auth/login` với password bất kỳ sẽ chỉ nhận 401 "sai password" — không crash.

## 5. `CustomOAuth2UserService` — map `OAuth2User` → `User` nội bộ

```java
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

  private final UserRepository userRepository;

  @Override
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    OAuth2User oAuth2User = super.loadUser(userRequest);

    String provider = userRequest.getClientRegistration().getRegistrationId(); // "github"
    String providerId = oAuth2User.getName(); // GitHub trả "id"
    String email = oAuth2User.getAttribute("email");

    userRepository.findByProviderAndProviderId(provider, providerId)
        .orElseGet(() -> {
          User newUser = User.builder()
              .username(email != null ? email : provider + "_" + providerId)
              .provider(provider)
              .providerId(providerId)
              .roles("USER")
              .build();
          return userRepository.save(newUser);
        });

    return oAuth2User;
  }
}
```

**Gotcha thực tế:** GitHub có thể **không trả `email`** trong response nếu user để email private trong setting GitHub → cần fallback username `provider + "_" + providerId`.

## 6. `OAuth2LoginSuccessHandler` — issue JWT sau khi login OAuth thành công

```java
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

  private final JwtService jwtService;
  private final UserDetailsService userDetailsService;
  private final UserRepository userRepository;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

    OAuth2User oAuth2User = oauthToken.getPrincipal();
    String provider = oauthToken.getAuthorizedClientRegistrationId(); // "github"
    String providerId = oAuth2User.getName();                         // GitHub numeric id

    User user = userRepository.findByProviderAndProviderId(provider, providerId)
        .orElseThrow(() -> new IllegalStateException("User not provisioned: " + provider + "/" + providerId));

    UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
    String accessToken = jwtService.generateAccessToken(userDetails);
    String refreshToken = jwtService.generateRefreshToken(userDetails);

    response.sendRedirect("/oauth2/success?token=" + accessToken + "&refresh=" + refreshToken);
  }
}
```

**Lưu ý bảo mật:** trả token qua query param chỉ để demo/học — token trên URL có thể bị log lại (server log, browser history, header `Referer`). App thật nên redirect kèm 1 `code` ngắn hạn dùng 1 lần rồi frontend đổi lấy token qua API riêng, hoặc set token vào cookie `HttpOnly`.

## 7. `SecurityConfig` — nối dây

```java
@Bean
public SecurityFilterChain securityFilterChain(
    HttpSecurity http,
    JwtAuthenticationFilter jwtAuthFilter,
    CustomOAuth2UserService customOAuth2UserService,
    OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler) throws Exception {
  http
      .csrf(c -> c.disable())
      .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)) // đổi từ STATELESS
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/hello").permitAll()
          .requestMatchers("/auth/**").permitAll()
          .requestMatchers("/oauth2/**", "/login/**").permitAll()   // thêm cho luồng OAuth
          .requestMatchers("/notes/**").authenticated()
          .anyRequest().authenticated())
      .oauth2Login(oauth2 -> oauth2
          .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
          .successHandler(oAuth2LoginSuccessHandler))
      .exceptionHandling(...)
      .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
  return http.build();
}
```

`customOAuth2UserService`/`oAuth2LoginSuccessHandler` được khai làm **tham số của `@Bean` method** — Spring tự autowire theo kiểu, giống cách `jwtAuthFilter` đã làm từ bước 8.

## 8. Bug thực tế đã gặp & sửa

### Bug A — thiếu tham số trong `securityFilterChain`, biên dịch lỗi "cannot find symbol"

Lần đầu thêm `.oauth2Login(...)` dùng `customOAuth2UserService` và `oAuth2LoginSuccessHandler` trực tiếp trong thân method, nhưng chưa khai báo ở đâu (không phải field, không phải tham số) → compile error. **Sửa:** thêm 2 bean này làm tham số của `securityFilterChain(...)`.

### Bug B — nhầm overload `JwtService`, truyền `String` thay vì `UserDetails`

Code mẫu ban đầu viết `jwtService.generateAccessToken(user.getUsername())` — nhưng `JwtService.generateAccessToken`/`generateRefreshToken` (đã có từ bước 9) nhận `UserDetails`, không nhận `String`. **Sửa:** load `UserDetails` qua `userDetailsService.loadUserByUsername(...)` trước khi generate token.

### Bug C — lệch username giữa nơi tạo user và nơi login (đã sửa)

`OAuth2LoginSuccessHandler` ban đầu tra user bằng `oAuth2User.getAttribute("email")` trực tiếp, trong khi `CustomOAuth2UserService` khi tạo user có fallback sang `provider + "_" + providerId` nếu `email` null. Hai nơi tính username theo 2 cách khác nhau → GitHub user không public email sẽ tạo được row nhưng login lại `UsernameNotFoundException` vì tra nhầm.

**Sửa:** `OAuth2LoginSuccessHandler` không tự tính username nữa — tra thẳng qua khoá ổn định `findByProviderAndProviderId(provider, providerId)` (cùng khoá mà `CustomOAuth2UserService` dùng để tạo/tìm user), rồi lấy `username` thật từ record DB. Không còn 2 nơi tính trùng logic → không thể lệch.

## 9. Gap chưa xử lý (đã ghi nhận, chưa sửa)

- **Google (OIDC) chưa hoạt động nếu bật lại:** `.userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))` chỉ áp dụng cho provider OAuth2 thuần (GitHub). Vì Google dùng OIDC (`scope` có `openid`), Spring sẽ dùng `OidcUserService` mặc định, **không gọi** `customOAuth2UserService` → nếu bật lại Google mà chưa thêm `.oidcUserService(...)` với 1 `CustomOidcUserService extends OidcUserService`, login Google sẽ luôn thất bại (`UsernameNotFoundException` trong `OAuth2LoginSuccessHandler` vì chưa có row nào được tạo). Đây là lý do Google đang bị comment trong `application.yaml`.
- **Không xử lý account linking khi trùng email:** nếu 1 user đã đăng ký local qua `/auth/register` bằng email X (có password), sau đó đăng nhập GitHub bằng tài khoản GitHub cũng gắn email X → `CustomOAuth2UserService` không tìm thấy theo `(provider, providerId)` (vì user cũ có `provider = null`) → cố tạo user mới với `username = X` → vi phạm `@Column(unique = true)` trên `username` → ném `DataIntegrityViolationException` ngay trong filter chain lúc authenticate → **không được `GlobalExceptionHandler` bắt** (advice chỉ áp dụng cho exception ném từ `@RestController`) → user nhận lỗi 500 khó hiểu.
  - Hướng sửa khi quay lại: trước khi tạo mới, kiểm tra thêm `findByUsername(username)`; nếu đã tồn tại thì hoặc ném `OAuth2AuthenticationException` (Spring Security có cơ chế bắt riêng, trả `/login?error` thay vì 500 trần trụi), hoặc thật sự "link" — gắn `provider`/`providerId` vào user local đã có thay vì tạo mới.

## 10. Câu hỏi tự kiểm tra

1. Vì sao `oauth2Login()` cần session dù app dùng JWT stateless cho API? Session đó tồn tại trong bao lâu?
2. Vì sao không thể chỉ dùng `email` làm khoá định danh user OAuth mà phải thêm `provider` + `providerId`?
3. Nếu `CustomOAuth2UserService.loadUser()` ném exception (ví dụ lỗi DB), request sẽ đi tới đâu? Có qua `GlobalExceptionHandler` không? Vì sao?
4. `{noop}oauth2-external-user` có thật sự "an toàn" không khi app dùng `BCryptPasswordEncoder` thẳng thay vì `DelegatingPasswordEncoder`? Điều gì xảy ra nếu ai đó tình cờ đăng ký password trùng đúng chuỗi này qua `/auth/register`? (Gợi ý: so sánh với cách `BCryptPasswordEncoder.matches()` xử lý chuỗi không đúng định dạng bcrypt.)

## 11. Test bằng trình duyệt

Vì có redirect qua GitHub thật, không dùng curl được cho bước redirect:

1. Mở trình duyệt vào `http://localhost:8080/oauth2/authorization/github`.
2. Đăng nhập GitHub, cấp quyền.
3. Kiểm tra có redirect về `/oauth2/success?token=...&refresh=...` với JWT hợp lệ không.
4. Copy `token`, dùng `Authorization: Bearer <token>` gọi `/notes`:

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:8080/notes
```

5. Kiểm tra trong H2 console (`/h2-console` nếu đã bật) bảng `users` có row mới với `provider = 'github'`, `providerId` đúng id GitHub, `password = null`.
