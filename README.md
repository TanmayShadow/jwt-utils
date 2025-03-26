# JWT Utilities Library

A reusable library for JWT token creation, validation, and claim extraction in Spring Boot applications. It also provides a custom annotation @ValidateJwtToken to validate JWT tokens at the REST controller endpoint level.

---

## Features

1. **JWT Utilities**:
    - Create JWT tokens with a secret key.
    - Validate JWT tokens with a secret key.
    - Extract claims from a JWT token.

2. **Annotation**:
    - `@ValidateJwtToken`: A function-level annotation to validate JWT tokens before executing the actual logic of a REST controller endpoint.

3. **Custom Exceptions**:
    - `JwtValidationException`: Base exception for JWT validation errors.
    - `MissingTokenException`: Thrown when the JWT token is missing or empty.
    - `InvalidTokenException`: Thrown when the JWT token is invalid.

---

## Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
  <groupId>io.github.tanmayshadow</groupId>
  <artifactId>jwt-utils</artifactId>
  <version>1.0.0</version>
</dependency>
```
---

## Usage
### 1. JWT Utilities 

#### 1.1 Create JWT Token
Use the JwtUtil.generateJwtToken method to create a JWT token.

```java
import util.io.github.JwtUtil;

public class JwtExample {
   public static void main(String[] args) {
      String secretKey = "my-secret-key";
      Map<String, Object> claims = new HashMap<>();
      claims.put("username","name");
      claims.put("role","admin");
      long expirationTime = 3600000; // 1 hour in milliseconds

      String token = JwtUtil.generateJwtToken(claims,secretKey,expiration);
      System.out.println("Generated Token: " + token);
   }
}
```

#### 1.2 Validate JWT Token
Use the JwtUtil.validateToken method to validate a JWT token.

```java
import util.io.github.JwtUtil;

public class JwtExample {
   public static void main(String[] args) {
      String secretKey = "my-secret-key";
      String token = "your-jwt-token";

      boolean isValid = JwtUtil.validateToken(token, secretKey);
      System.out.println("Is Token Valid? " + isValid);
   }
}
```

#### 1.3 Extract Claims from Token
Use the JwtUtil.getClaim and getAllClaims methods to extract claims from a JWT token.

```java
import io.jsonwebtoken.Claims;
import util.io.github.JwtUtil;

public class JwtExample {
   public static void main(String[] args) {
      String secretKey = "my-secret-key";
      String token = "your-jwt-token";
      String claimName = "your-claim-name";

      Claims claims = JwtUtil.getAllClaims(token, secretKey);
      System.out.println("Subject: " + claims.getSubject());
      System.out.println("Expiration: " + claims.getExpiration());

      Object claim = JwtUtil.getClaim(token, secretKey, claimName);
      System.out.println("Claim Value: " + claim);
   }
}
```

### 2. Annotation
#### 2.1 Function-Level Annotation (@ValidateJwtToken)
Use the @ValidateJwtToken annotation to validate JWT tokens before executing the logic of a REST controller endpoint.

```java
import annotation.io.github.ValidateJwtToken;
import exception.io.github.JwtValidationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {

   @ValidateJwtToken(secretKey = "my-secret-key", headerName = "Authorization")
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

### 3. Custom Exceptions
#### 3.1 JwtValidationException
Base exception for all JWT validation errors.

#### 3.2 MissingTokenException
Thrown when the JWT token is missing or empty.

#### 3.3 InvalidTokenException
Thrown when the JWT token is invalid.

---
## Example Workflow
### 1. Create a Token:

* Use JwtUtil.generateJwtToken to generate a JWT token.

### 2. Validate a Token:

* Use JwtUtil.validateToken to validate the token.

### 3. Use the Annotation:

* Apply the @ValidateJwtToken annotation to your REST controller endpoints.

### 4. Handle Exceptions:

* Use @ExceptionHandler to handle JwtValidationException, MissingTokenException, and InvalidTokenException.

---

## Dependencies
This library requires the following dependencies in your project:

### * Spring Boot AOP (for aspect-oriented programming):
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-aop</artifactId>
</dependency>
```
### * Servlet API (if using HttpServletRequest):
```xml
<dependency>
    <groupId>jakarta.servlet</groupId>
    <artifactId>jakarta.servlet-api</artifactId>
    <version>6.0.0</version>
    <scope>provided</scope>
</dependency>
```
### * JJWT (for JWT validation):
```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.12.6</version>
</dependency>
```
---
## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

---

## Support
For any questions or issues, please open an issue on the GitHub repository.
