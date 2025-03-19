package io.github.tanmayshadow.exception;

public class InvalidTokenException extends JwtValidationException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
