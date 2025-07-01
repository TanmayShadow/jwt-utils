package io.github.tanmayshadow.annotation;

import io.github.tanmayshadow.config.JwtUtilsProperties;
import io.github.tanmayshadow.exception.InvalidTokenException;
import io.github.tanmayshadow.exception.JwtConfigurationException;
import io.github.tanmayshadow.exception.MissingTokenException;
import io.github.tanmayshadow.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

@Aspect
public class JwtValidationAspect {

    private final HttpServletRequest request;
    private final JwtUtilsProperties props;
    private final JwtUtil jwtUtil;

    public JwtValidationAspect(HttpServletRequest request, JwtUtilsProperties props) {
        this.request = request;
        this.props = props;
        this.jwtUtil = new JwtUtil(props);
    }

    @Before("@annotation(io.github.tanmayshadow.annotation.ValidateJwtToken)")
    public void validateJwt(JoinPoint joinPoint) throws Throwable{
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        ValidateJwtToken annotation = signature.getMethod().getAnnotation(ValidateJwtToken.class);

        // Check whether headerName and secretKey is passed from annotation
        // If not then fetch from application.properties
        // tanmayshadow.jwtutils.secret-key=secretKey
        // tanmayshadow.jwtutils.header-name=headerName

        String headerName = annotation.headerName().isEmpty()?props.getHeaderName():annotation.headerName();
        String secretKey = annotation.secretKey().isEmpty()?props.getSecretKey():annotation.secretKey();

        if (headerName == null || headerName.isEmpty()) {
            throw new JwtConfigurationException(
                    "The 'header-name' used for extracting the JWT token is not configured. " +
                            "Expected property 'tanmayshadow.jwtutils.header-name' in application.properties or a valid value in @ValidateJwtToken. " +
                            "This value is required to extract the JWT from incoming HTTP requests."
            );
        }

        if (secretKey == null || secretKey.isEmpty()) {
            throw new JwtConfigurationException(
                    "The JWT secret key is not configured. " +
                            "Expected property 'tanmayshadow.jwtutils.secret-key' in application.properties or a valid value in @ValidateJwtToken. " +
                            "The secret key is required to validate the HMAC signature of the JWT. " +
                            "Refer to RFC 7518, Section 3.2 for HMAC requirements: https://tools.ietf.org/html/rfc7518#section-3.2"
            );
        }

        String token = request.getHeader(headerName);
        if (token == null || token.isEmpty()) {
            throw new MissingTokenException(
                    "Missing or empty JWT token in the request header. " +
                            "The header '" + headerName + "' was expected but not found or was empty. " +
                            "Ensure the JWT token is included in the HTTP request header with the correct name."
            );
        }
        // Validate the token
        if (!jwtUtil.validateToken(token, secretKey)) {
            throw new InvalidTokenException(
                    "The JWT token provided is invalid or has failed signature verification. " +
                            "Ensure the token is correctly signed using the configured HMAC secret and has not expired or been tampered with."
            );
        }
    }
}
