package io.github.tanmayshadow.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {
//    private static String SECRET_KEY = "tT88q8jpDWTpS7gnvwdV9fislqbAuNXI";
//    private final static SecretKey KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    private static Logger log = LoggerFactory.getLogger(JwtUtil.class);

    public static String generateJwtToken(Map<String,Object> claims, String secretKey, int expiration){
        SecretKey KEY = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration)) // 10 hours
                .signWith(KEY)
                .compact();
    }
    public static boolean validateToken(String token, String secretKey) {
        try {
            SecretKey KEY = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
            Jwts.parser()
                    .verifyWith(KEY)
                    .build()
                    .parse(token);
            return true;
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT Token");
        }catch (SignatureException s){
            System.out.println("Signature Exception : "+s.getMessage());
        }
        return false;
    }

    public static Object getClaim(String token,String secretKey,String claimName){
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
    public static Claims getAllClaims(String token,String secretKey){
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
}
