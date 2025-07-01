package io.github.tanmayshadow.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "tanmayshadow.jwtutils")
public class JwtUtilsProperties {

    private String secretKey="";
    private String headerName="";

    // Getters and setters
    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getHeaderName() {
        return headerName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }
}
