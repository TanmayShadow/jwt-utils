package io.github.tanmayshadow.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD,ElementType.TYPE,ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidateJwtToken {
    String secretKey() default "tT88q8jpDWTpS7gnvwdV9fislqbAuNXI";
    String headerName() default "X-Authorization";
}
