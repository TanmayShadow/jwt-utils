package io.github.tanmayshadow.config;

import io.github.tanmayshadow.annotation.JwtValidationAspect;
import io.github.tanmayshadow.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(JwtUtilsProperties.class)
public class JwtAutoConfiguration {

    @Bean
    public JwtValidationAspect jwtValidationAspect(
            HttpServletRequest request,
            JwtUtilsProperties properties
    ) {
        return new JwtValidationAspect(request, properties);
    }

    @Bean
    public JwtUtil jwtUtil(JwtUtilsProperties props) {
        return new JwtUtil(props);
    }
}
