# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] - 2025-07-02
### Added
- Spring Boot auto-configuration support using `JwtAutoConfiguration`.
- Default constructor to `JwtUtil` for reading config from `application.properties`.
- Auto-registration of `JwtUtil` as a Spring-managed bean (no manual `@Bean` or `@ComponentScan` required).
- Exception messages now refer to RFC 7518 when secret key length is invalid.
- Fallback to properties if annotation values (`secretKey`, `headerName`) are missing.
- Javadoc added for all public methods in `JwtUtil`.

### Changed
- `JwtUtil` methods are now instance-based instead of static.
- Improved token validation error handling and logging.

### Deprecated
- Static methods for token generation, validation, and claim extraction.

---

## [1.0.0] - 2025-03-26
### Initial
- Generate, validate, and extract JWT claims via static methods.
- Use of `@ValidateJwtToken` annotation with `secretKey` and `headerName` provided manually.
- Basic exception classes for missing and invalid tokens.