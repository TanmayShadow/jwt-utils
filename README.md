# JWT Utilities Library

A reusable library for JWT token creation, validation, and claim extraction in Spring Boot applications.  
It provides a custom annotation `@ValidateJwtToken` to validate JWT tokens at the REST controller endpoint level.

---

## 📌 Highlights (v1.1.0+)

- ✅ Spring Boot auto-configuration — no setup required
- ✅ Inject `JwtUtil` via `@Autowired`
- ✅ Reads `secretKey` and `headerName` from `application.properties`
- ✅ Custom annotation `@ValidateJwtToken` with fallback config support
- ✅ Descriptive exceptions for better debugging

---

## 📦 Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
  <groupId>io.github.tanmayshadow</groupId>
  <artifactId>jwt-utils</artifactId>
  <version>1.1.0</version>
</dependency>
```

---

## ⚙️ Configuration (application.properties)

```properties
tanmayshadow.jwtutils.secret-key=your-256bit-secret-key
tanmayshadow.jwtutils.header-name=X-Authorization
```

---

## 🚀 Usage (v1.1.0+)

### 1. Inject JwtUtil via Spring

```java
@RestController
public class JwtExample {

   @Autowired
   private JwtUtil jwtUtil;

   @GetMapping("/generate")
   public String generateToken() {
      Map<String, Object> claims = Map.of("username", "john");
      return jwtUtil.generateJwtToken(claims, 3600000); // 1 hour
   }

   @GetMapping("/verify")
   public boolean validate(@RequestHeader("X-Authorization") String token) {
      return jwtUtil.validateToken(token);
   }

   @GetMapping("/claim")
   public Object extractClaim(@RequestHeader("X-Authorization") String token) {
      return jwtUtil.getClaim(token, "username");
   }
}
```

---

### 2. Use Annotation for Auto Validation

```java
@RestController
public class MyController {

   @ValidateJwtToken // Reads key and header from application.properties
   @GetMapping("/secure")
   public String secureEndpoint() {
      return "Access granted!";
   }

   @ExceptionHandler(JwtValidationException.class)
   public ResponseEntity<String> handleJwtValidationException(JwtValidationException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
   }
}
```

---

## ⚠️ Migration Notice (v1.0.0 → v1.1.0)

> Static methods like `JwtUtil.generateJwtToken(...)` have been deprecated.  
> You should now inject `JwtUtil` as a Spring bean (`@Autowired`) and configure your secret key via `application.properties`.

> If you're using the annotation `@ValidateJwtToken`, you can now omit `secretKey` and `headerName` — it falls back to properties automatically.

---

## 🧱 Dependencies

Ensure the following are in your project:

### Spring AOP
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-aop</artifactId>
</dependency>
```

### Servlet API
```xml
<dependency>
  <groupId>jakarta.servlet</groupId>
  <artifactId>jakarta.servlet-api</artifactId>
  <version>6.0.0</version>
  <scope>provided</scope>
</dependency>
```

### JJWT
```xml
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt</artifactId>
  <version>0.12.6</version>
</dependency>
```

---

## 📄 Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history and release notes.

---

## 🙌 Contributing

Contributions are welcome! Please open an issue or pull request.

---

## 💬 Support

For questions or issues, please open an issue on the [GitHub repository](https://github.com/tanmayshadow/jwt-utils).