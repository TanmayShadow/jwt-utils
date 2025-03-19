package io.github.tanmayshadow.exception;

public class MissingTokenException extends JwtValidationException {
    public MissingTokenException(String message) {
        super(message);
    }
}