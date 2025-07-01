package io.github.tanmayshadow.config;

import io.github.tanmayshadow.annotation.JwtValidationAspect;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtAutoConfiguration {

    @Bean
    public JwtValidationAspect jwtValidationAspect(HttpServletRequest request) {
        return new JwtValidationAspect(request);
    }
}
