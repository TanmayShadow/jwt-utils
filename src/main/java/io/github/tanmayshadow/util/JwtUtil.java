package io.github.tanmayshadow.util;

import io.github.tanmayshadow.config.JwtUtilsProperties;
import io.github.tanmayshadow.exception.JwtConfigurationException;
import io.github.tanmayshadow.exception.MissingTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.Properties;
import java.io.IOException;

/**
 * Utility class for handling JSON Web Tokens (JWT) operations such as generation,
 * validation, and claims extraction.
 * <p>
 * This class supports both Spring-managed usage (via {@code @Component}) and
 * manual instantiation via constructors.
 *
 * <h2>Usage Options:</h2>
 * <ul>
 *     <li><b>Spring Boot:</b> Declare {@code JwtUtil} as a bean using {@code @Autowired}.</li>
 *     <li><b>Manual:</b> Use {@code new JwtUtil(secretKey, headerName)} or the default constructor.</li>
 * </ul>
 *
 * <h2>Configuration:</h2>
 * <ul>
 *     <li>{@code tanmayshadow.jwtutils.secret-key} – 256-bit key for signing and validating JWTs</li>
 *     <li>{@code tanmayshadow.jwtutils.header-name} – Name of the HTTP header containing the JWT</li>
 * </ul>
 *
 * <p>
 * The default constructor reads values from {@code application.properties}.
 * </p>
 *
 * <h2>Example 1: Passing SecretKey and HeaderName in constructor</h2>
 * <pre>{@code
 * JwtUtil jwt = new JwtUtil("mySecretKey", "X-Authorization");
 * boolean isValid = jwt.validateToken(token);
 * Object email = jwt.getClaim(token, "email");
 * }</pre>
 *
 *  * <h2>Example 2: Fetching SecretKey and HeaderName from application.properties</h2>
 *  * <pre>{@code
 *  * JwtUtil jwt = new JwtUtil();
 *  * boolean isValid = jwt.validateToken(token);
 *  * Object email = jwt.getClaim(token, "email");
 *  * }</pre>
 *
 * @author Tanmay
 * @since 1.0.0
 */
public class JwtUtil {
    private final JwtUtilsProperties props;
    private static Logger log = LoggerFactory.getLogger(JwtUtil.class);

    /**
     * Default constructor for non-Spring use — reads from application.properties automatically.
     */
    public JwtUtil() {
        JwtUtilsProperties autoProps = new JwtUtilsProperties();
        try {
            Properties properties = PropertiesLoaderUtils.loadProperties(new ClassPathResource("application.properties"));
            autoProps.setSecretKey(properties.getProperty("tanmayshadow.jwtutils.secret-key"));
            autoProps.setHeaderName(properties.getProperty("tanmayshadow.jwtutils.header-name"));

            if (autoProps.getSecretKey() == null || autoProps.getSecretKey().isBlank()) {
                throw new JwtConfigurationException("Missing 'tanmayshadow.jwtutils.secret-key' in application.properties");
            }
            if (autoProps.getHeaderName() == null || autoProps.getHeaderName().isBlank()) {
                throw new JwtConfigurationException("Missing 'tanmayshadow.jwtutils.header-name' in application.properties");
            }

        } catch (IOException e) {
            throw new JwtConfigurationException("Failed to load application.properties: " + e.getMessage());
        }
        this.props = autoProps;
    }

    /**
     * Constructor used by Spring Boot with auto-wired JwtUtilsProperties.
     */
    public JwtUtil(JwtUtilsProperties props) {
        this.props = props;
    }

    /**
     * Constructor for manual usage by providing secretKey and headerName.
     */
    public JwtUtil(String secretKey, String headerName) {
        JwtUtilsProperties manualProps = new JwtUtilsProperties();
        manualProps.setSecretKey(secretKey);
        manualProps.setHeaderName(headerName);
        this.props = manualProps;
    }

    /**
     * Generates a JWT token using the provided secret key and claims.
     *
     * @param claims     a map of key-value pairs to include in the JWT payload
     * @param secretKey  the secret key used to sign the token (must be at least 256 bits for HMAC-SHA)
     * @param expiration the expiration time in milliseconds from the current time
     * @return a signed JWT token string
     *
     * @throws IllegalArgumentException if the secret key is invalid or too short
     */
    public String generateJwtToken(Map<String,Object> claims, String secretKey, int expiration){
        SecretKey KEY = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration)) // 10 hours
                .signWith(KEY)
                .compact();
    }

    /**
     * Generates a JWT token using the secret key defined in application properties.
     *
     * @param claims     a map of key-value pairs to include in the JWT payload
     * @param expiration the expiration time in milliseconds from the current time
     * @return a signed JWT token string
     *
     * @throws JwtConfigurationException if the secret key is not properly configured
     * @throws IllegalArgumentException if the secret key is invalid or too short
     */
    public String generateJwtToken(Map<String,Object> claims, int expiration){
        SecretKey KEY = this.getSecretKey();
        return Jwts.builder()
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(KEY)
                .compact();
    }

    /**
     * Validates a JWT token using a provided secret key.
     *
     * @param token      the JWT token to validate
     * @param secretKey  the HMAC secret key used to verify the token signature
     * @return {@code true} if the token is valid; {@code false} otherwise
     *
     * @throws IllegalArgumentException if the secret key is invalid or malformed
     */
    public boolean validateToken(String token, String secretKey) {
        try {
            SecretKey KEY = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
            Jwts.parser()
                    .verifyWith(KEY)
                    .build()
                    .parse(token);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT Token");
        }catch (SignatureException s){
            log.error("Signature Exception : "+s.getMessage());
        }
        return false;
    }

    /**
     * Validates a JWT token using the secret key defined in application properties.
     *
     * @param token the JWT token to validate
     * @return {@code true} if the token is valid; {@code false} otherwise
     *
     * @throws JwtConfigurationException if the secret key is not configured properly
     * @throws IllegalArgumentException if the secret key is invalid
     */
    public boolean validateToken(String token) {
        try {
            SecretKey KEY = this.getSecretKey();
            Jwts.parser()
                    .verifyWith(KEY)
                    .build()
                    .parse(token);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT Token");
        }catch (SignatureException s){
            log.error("Signature Exception : "+s.getMessage());
        }
        return false;
    }

    /**
     * Validates a JWT token extracted from an HTTP request header using the configured secret key.
     * <p>
     * This method also checks that both the header name and secret key are configured properly.
     *
     * @param request the incoming HTTP request containing the JWT token
     * @return {@code true} if the token is valid; {@code false} otherwise
     *
     * @throws JwtConfigurationException if either the header name or secret key is not configured
     * @throws MissingTokenException if the token is missing or blank in the request header
     * @throws IllegalArgumentException if the secret key is invalid
     */
    public boolean validateToken(HttpServletRequest request) {
        try {
            this.validateHeaderPresence();
            String token = request.getHeader(props.getHeaderName());
            this.validateTokenPresence(token);
            SecretKey KEY = this.getSecretKey();
            Jwts.parser()
                    .verifyWith(KEY)
                    .build()
                    .parse(token);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT Token");
        }catch (SignatureException s){
            log.error("Signature Exception : "+s.getMessage());
        }
        return false;
    }

    /**
     * Extracts a specific claim from the JWT token using a custom secret key.
     *
     * @param token      the JWT token from which the claim is to be extracted
     * @param secretKey  the HMAC secret key used to verify the token's signature
     * @param claimName  the name of the claim to extract
     * @return the value of the claim if present and valid; {@code null} otherwise
     *
     * @throws IllegalArgumentException if the secret key is invalid or malformed
     * @throws io.jsonwebtoken.JwtException if the token is invalid or parsing fails
     */
    public Object getClaim(String token,String secretKey,String claimName){
        try {
            SecretKey KEY = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
            Claims claims = Jwts.parser()
                    .verifyWith(KEY) // Set the secret key
                    .build()
                    .parseSignedClaims(token) // Parse the token
                    .getPayload();           // Retrieve the claims

            // Extract other claims
            return claims.get(claimName);
        } catch (Exception e) {
            log.error("Error in getting JWT Claims: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Extracts a specific claim from the JWT token using the secret key configured in application properties.
     *
     * @param token      the JWT token from which the claim is to be extracted
     * @param claimName  the name of the claim to extract
     * @return the value of the claim if present and valid; {@code null} otherwise
     *
     * @throws JwtConfigurationException if the secret key is not configured properly
     * @throws io.jsonwebtoken.JwtException if the token is invalid or parsing fails
     */
    public Object getClaim(String token,String claimName){
        try {
            SecretKey KEY = this.getSecretKey();
            Claims claims = Jwts.parser()
                    .verifyWith(KEY) // Set the secret key
                    .build()
                    .parseSignedClaims(token) // Parse the token
                    .getPayload();           // Retrieve the claims

            // Extract other claims
            return claims.get(claimName);
        } catch (Exception e) {
            log.error("Error in getting JWT Claims: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Extracts a specific claim from the JWT token present in the HTTP request header.
     * <p>
     * This method uses the header name and secret key configured via application properties.
     *
     * @param request    the HTTP request containing the JWT token in the configured header
     * @param claimName  the name of the claim to extract
     * @return the value of the claim if present and valid; {@code null} otherwise
     *
     * @throws JwtConfigurationException if either the header name or secret key is not configured
     * @throws MissingTokenException if the token is missing or blank in the request
     * @throws io.jsonwebtoken.JwtException if the token is invalid or parsing fails
     */
    public Object getClaim(HttpServletRequest request,String claimName){
        try {
            this.validateHeaderPresence();
            String token = request.getHeader(props.getHeaderName());
            this.validateTokenPresence(token);
            SecretKey KEY = this.getSecretKey();
            Claims claims = Jwts.parser()
                    .verifyWith(KEY) // Set the secret key
                    .build()
                    .parseSignedClaims(token) // Parse the token
                    .getPayload();           // Retrieve the claims

            // Extract other claims
            return claims.get(claimName);
        } catch (Exception e) {
            log.error("Error in getting JWT Claims: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Extracts all claims from the given JWT token using a custom secret key.
     *
     * @param token      the JWT token to parse
     * @param secretKey  the HMAC secret key used to verify the token's signature
     * @return a {@link Claims} object containing all the token's claims if valid; {@code null} otherwise
     *
     * @throws IllegalArgumentException if the secret key is invalid or improperly formatted
     * @throws io.jsonwebtoken.JwtException if the token is malformed or cannot be verified
     */
    public Claims getAllClaims(String token,String secretKey){
        try {
            SecretKey KEY = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
            return Jwts.parser()
                    .verifyWith(KEY) // Set the secret key
                    .build()
                    .parseSignedClaims(token) // Parse the token
                    .getPayload();           // Retrieve the claims

        } catch (Exception e) {
            log.error("Error in Extracting all Claims: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Extracts all claims from the given JWT token using the secret key configured in application properties.
     *
     * @param token the JWT token to parse
     * @return a {@link Claims} object containing all the token's claims if valid; {@code null} otherwise
     *
     * @throws JwtConfigurationException if the secret key is not configured
     * @throws MissingTokenException if the token is blank or null
     * @throws io.jsonwebtoken.JwtException if the token is malformed or cannot be verified
     */
    public Claims getAllClaims(String token){
        try {
            this.validateTokenPresence(token);
            SecretKey KEY = this.getSecretKey();
            return Jwts.parser()
                    .verifyWith(KEY) // Set the secret key
                    .build()
                    .parseSignedClaims(token) // Parse the token
                    .getPayload();           // Retrieve the claims

        } catch (Exception e) {
            log.error("Error in Extracting all Claims: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Extracts all claims from the JWT token present in the HTTP request header.
     * <p>
     * The token is expected in the header name configured via application properties.
     *
     * @param request the incoming HTTP request containing the JWT token in its header
     * @return a {@link Claims} object containing all the token's claims if valid; {@code null} otherwise
     *
     * @throws JwtConfigurationException if either the header name or secret key is not configured
     * @throws MissingTokenException if the token is missing or blank in the request
     * @throws io.jsonwebtoken.JwtException if the token is malformed or cannot be verified
     */
    public Claims getAllClaims(HttpServletRequest request){
        try {
            this.validateHeaderPresence();
            String token = request.getHeader(props.getHeaderName());
            this.validateTokenPresence(token);
            SecretKey KEY = this.getSecretKey();
            return Jwts.parser()
                    .verifyWith(KEY) // Set the secret key
                    .build()
                    .parseSignedClaims(token) // Parse the token
                    .getPayload();           // Retrieve the claims

        } catch (Exception e) {
            log.error("Error in Extracting all Claims: {}", e.getMessage());
        }
        return null;
    }

    /**
     *
     * Throws {@link MissingTokenException} if the token is null, empty, or blank.
     *
     * @param token the JWT token extracted from the request header
     * @throws MissingTokenException if the token is missing or empty
     */
    private void validateTokenPresence(String token) {
        if (token == null || token.isBlank()) {
            throw new MissingTokenException(
                    "Missing or empty JWT token in the request header. " +
                            "The header '" + props.getHeaderName() + "' was expected but not found or was empty. " +
                            "Ensure the JWT token is included in the HTTP request header with the correct name."
            );
        }
    }

    /**
     * Validates that the JWT header name is properly configured.
     * Throws JwtConfigurationException if not set in either application.properties or annotation.
     */
    private void validateHeaderPresence(){
        if (props.getHeaderName() == null || props.getHeaderName().isBlank()) {
            throw new JwtConfigurationException(
                    "The 'header-name' used for extracting the JWT token is not configured. " +
                            "Expected property 'tanmayshadow.jwtutils.header-name' in application.properties." +
                            "This value is required to extract the JWT from incoming HTTP requests."
            );
        }
    }


    /**
     * Validates that the JWT secret key is properly configured.
     * Throws JwtConfigurationException if not set in either application.properties or annotation.
     */
    private void validateSecretKeyPresence(){
        if (props.getSecretKey() == null || props.getSecretKey().isEmpty()) {
            throw new JwtConfigurationException(
                    "The JWT secret key is not configured. " +
                            "Expected property 'tanmayshadow.jwtutils.secret-key' in application.properties or a valid value in @ValidateJwtToken. " +
                            "The secret key is required to validate the HMAC signature of the JWT. " +
                            "Refer to RFC 7518, Section 3.2 for HMAC requirements: https://tools.ietf.org/html/rfc7518#section-3.2"
            );
        }
    }

    /**
     * Validates that the JWT secret key is properly configured.
     * Returns SecretKey from props.getSecretKey()
     * Throws JwtConfigurationException if not set in either application.properties or annotation.
     */
    private SecretKey getSecretKey() {
        this.validateSecretKeyPresence();
        return Keys.hmacShaKeyFor(props.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

}
