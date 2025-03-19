package io.github.tanmayshadow.annotation;

import io.github.tanmayshadow.exception.InvalidTokenException;
import io.github.tanmayshadow.exception.MissingTokenException;
import io.github.tanmayshadow.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class JwtValidationAspect {

    private final HttpServletRequest request;

    public JwtValidationAspect(HttpServletRequest request) {
        this.request = request;
    }

    @Before("@annotation(org.example.annotation.ValidateJwtToken)")
    public void validateJwt(JoinPoint joinPoint) throws Throwable{
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        ValidateJwtToken annotation = signature.getMethod().getAnnotation(ValidateJwtToken.class);

        String token = request.getHeader(annotation.headerName());
        if (token == null || token.isEmpty()) {
            throw new MissingTokenException("Missing or invalid authorization header");
        }
        // Validate the token
        if (!JwtUtil.validateToken(token, annotation.secretKey())) {
            throw new InvalidTokenException("Invalid Token");
        }
    }
}
